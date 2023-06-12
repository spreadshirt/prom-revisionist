package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"gopkg.in/yaml.v3"
)

var config struct {
	Addr        string
	UpstreamURL string
	Config      string
}

func main() {
	flag.StringVar(&config.Addr, "addr", "0.0.0.0:19090", "Address to listen on")
	flag.StringVar(&config.UpstreamURL, "upstream", "http://localhost:9090", "Upstream Prometheus url")
	flag.StringVar(&config.Config, "config", "config.yaml", "Config file specifying the rewrites")
	flag.Parse()

	revisionists, err := parseConfig(config.Config)
	if err != nil {
		log.Fatal(err)
	}

	if flag.NArg() == 1 {
		expr, err := parser.ParseExpr(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("before:", expr.Pretty(0))

		rewritten, _, err := rewrite(revisionists, os.Args[1])
		if err != nil {
			log.Fatal(err)
		}

		expr, err = parser.ParseExpr(rewritten)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("after: ", expr.Pretty(0))
		return
	}

	upstreamURL, err := url.Parse(config.UpstreamURL)
	if err != nil {
		log.Fatal(err)
	}

	// TODO: support match[]?

	http.HandleFunc("/api/", func(w http.ResponseWriter, req *http.Request) {
		log.Printf("api call: %q %s %s", req.URL.String(), req.Header.Get("Content-Type"), req.Header.Get("Content-Length"))

		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, req.Body)
		if err != nil {
			log.Printf("could not read request body: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		body := buf.Bytes()

		req.Body = io.NopCloser(buf)
		err = req.ParseForm()
		if err != nil {
			log.Printf("could not read form: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		var rev *Revisionist
		wasRewrite := false
		if len(req.PostForm) > 0 {
			query := req.PostForm.Get("query")
			if query != "" {
				before := query

				query, rev, err = rewrite(revisionists, query)
				if err != nil {
					log.Printf("could not rewrite: %s", err)
				}

				if rev != nil {
					log.Printf("rewriting!\n%s\n=>\n%s", before, query)

					req.PostForm.Set("query", query)
					wasRewrite = true
				}
			}

			body = []byte(req.PostForm.Encode())
		}

		u := req.URL
		u.Scheme = upstreamURL.Scheme
		u.Host = upstreamURL.Host
		if u.Query().Get("query") != "" {
			query := u.Query().Get("query")
			before := query

			query, rev, err = rewrite(revisionists, query)
			if err != nil {
				log.Printf("could not rewrite: %s", err)
			}

			if rev != nil {
				log.Printf("rewriting!\n%s\n=>\n%s", before, query)

				params := u.Query()
				params.Set("query", query)
				u.RawQuery = params.Encode()
				wasRewrite = true
			}
		}
		proxyReq, err := http.NewRequest(req.Method, u.String(), bytes.NewBuffer(body))
		if err != nil {
			log.Printf("failed to created request: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		proxyReq.Header = req.Header

		username, password, ok := req.BasicAuth()
		if ok {
			proxyReq.SetBasicAuth(username, password)
		}

		resp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			log.Printf("failed to created request: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		contentEncoding := resp.Header.Get("Content-Encoding")
		for name, vals := range resp.Header {
			if name == "Content-Length" && contentEncoding != "" {
				// recompression changes the length, skip
				continue
			}

			for _, val := range vals {
				w.Header().Add(name, val)
			}
		}
		w.WriteHeader(resp.StatusCode)

		var out io.Writer = w
		if resp.StatusCode != 200 {
			log.Printf("error %d", resp.StatusCode)
			out = io.MultiWriter(w, os.Stdout)
		}

		var in io.Reader = resp.Body
		if wasRewrite {
			if contentEncoding != "" {
				switch contentEncoding {
				case "gzip":
					in, err = gzip.NewReader(in)
					if err != nil {
						log.Printf("could not create gzip reader: %s", err)
						return
					}

					zw := gzip.NewWriter(out)
					defer zw.Close()

					out = zw
				case "deflate":
					in, err = zlib.NewReader(in)
					if err != nil {
						log.Printf("could not create deflate reader: %s", err)
						return
					}

					zw := zlib.NewWriter(out)
					defer zw.Close()

					out = zw
				default:
					log.Printf("unhandled compression %q", contentEncoding)
					return
				}
			}

			dec := json.NewDecoder(in)
			tw := NewTokenWriter(out, dec)
			token, err := dec.Token()
			for err == nil {
				switch tok := token.(type) {
				case string:
					replace, ok := rev.config.RenameLabelsReverse[tok]
					if ok {
						token = replace
					}
				}
				err = tw.Write(token)
				if err != nil {
					break
				}

				token, err = dec.Token()
			}
			if err != nil && err != io.EOF {
				log.Printf("could not decode response: %s", err)
				return
			}

			return
		}

		_, err = io.Copy(out, in)
		if err != nil {
			log.Printf("could not write body: %s", err)
			return
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		u := req.URL
		u.Scheme = upstreamURL.Scheme
		u.Host = upstreamURL.Host
		proxyReq, err := http.NewRequest(req.Method, u.String(), req.Body)
		if err != nil {
			log.Printf("failed to created request: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		proxyReq.Header = req.Header

		username, password, ok := req.BasicAuth()
		if ok {
			proxyReq.SetBasicAuth(username, password)
		}

		resp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			log.Printf("failed to created request: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		for name, vals := range resp.Header {
			for _, val := range vals {
				w.Header().Add(name, val)
			}
		}
		w.WriteHeader(resp.StatusCode)

		_, err = io.Copy(w, resp.Body)
		if err != nil {
			log.Printf("could not write body: %s", err)
			return
		}
	})

	log.Printf("Listening on http://%s", config.Addr)
	log.Fatal(http.ListenAndServe(config.Addr, nil))
}

func rewrite(revisionists []*Revisionist, query string) (string, *Revisionist, error) {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return query, nil, fmt.Errorf("invalid query: %w", err)
	}

	for _, rev := range revisionists {
		if !rev.ShouldProcess(expr) {
			log.Printf("%s does not match %q", rev.config.For, query)
			continue
		}

		log.Printf("%s matches %q", rev.config.For, query)

		err = parser.Walk(rev, expr, nil)
		if err != nil {
			return query, nil, fmt.Errorf("walk: %w", err)
		}

		expr, err = rev.WrapExpr(expr)
		if err != nil {
			return query, nil, fmt.Errorf("wrap: %w", err)
		}

		return expr.Pretty(0), rev, nil
	}

	return query, nil, nil
}

type Config struct {
	Rewrites []RewriteConfig `yaml:"rewrites"`
}

type RewriteConfig struct {
	Name   string         `yaml:"name"`
	For    *regexp.Regexp `yaml:"-"`
	ForRaw string         `yaml:"for"`
	Wrap   struct {
		Match    *regexp.Regexp `yaml:"-"`
		With     parser.Expr    `yaml:"-"`
		MatchRaw string         `yaml:"match"`
		WithRaw  string         `yaml:"with"`
	} `yaml:"wrap"`
	RenameMetrics       map[string]string `yaml:"rename-metrics"`
	RenameLabels        map[string]string `yaml:"rename-labels"`
	RenameLabelsReverse map[string]string `yaml:"-"`
	RewriteMatchers     []struct {
		From    *labels.Matcher `yaml:"-"`
		To      *labels.Matcher `yaml:"-"`
		FromRaw string          `yaml:"from"`
		ToRaw   string          `yaml:"to"`
	} `yaml:"rewrite-matchers"`
	DeleteLabels   []string          `yaml:"delete-labels"`
	AddMatchers    []*labels.Matcher `yaml:"-"`
	AddMatchersRaw []string          `yaml:"add-matchers"`
}

func RewriteConfigFromString(cfg string) (*RewriteConfig, error) {
	var config RewriteConfig
	dec := yaml.NewDecoder(bytes.NewBufferString(cfg))
	dec.KnownFields(true)
	err := dec.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("could not parse yaml: %w", err)
	}

	err = config.Parse()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config, err
}

func (r *RewriteConfig) Parse() error {
	var err error

	r.For, err = regexp.Compile(r.ForRaw)
	if err != nil {
		return fmt.Errorf("for regexp: %w", err)
	}

	if r.Wrap.MatchRaw != "" {
		r.Wrap.Match, err = regexp.Compile(r.Wrap.MatchRaw)
		if err != nil {
			return fmt.Errorf("wrap.match regexp: %w", err)
		}

		r.Wrap.With, err = parser.ParseExpr(r.Wrap.WithRaw)
		if err != nil {
			return fmt.Errorf("wrap.with promtheus expr: %w", err)
		}
	}

	// reverse label renames to easily convert them back in the response
	r.RenameLabelsReverse = make(map[string]string, len(r.RenameLabels))
	for key, val := range r.RenameLabels {
		r.RenameLabelsReverse[val] = key
	}

	for j, matcher := range r.RewriteMatchers {
		matchers, err := parser.ParseMetricSelector(matcher.FromRaw)
		if err != nil {
			return fmt.Errorf("rewrite-matchers[%d].from label matcher %q: %w", j, matcher.FromRaw, err)
		}

		if len(matchers) != 1 {
			return fmt.Errorf("rewrite-matchers[%d].from label matcher %q: must contain only one label matcher", j, matcher.FromRaw)
		}

		r.RewriteMatchers[j].From = matchers[0]

		matchers, err = parser.ParseMetricSelector(matcher.ToRaw)
		if err != nil {
			return fmt.Errorf("rewrite-matchers[%d].to label matcher %q: %w", j, matcher.ToRaw, err)
		}

		if len(matchers) != 1 {
			return fmt.Errorf("rewrite-matchers[%d].to label matcher %q: must contain only one label matcher", j, matcher.ToRaw)
		}

		r.RewriteMatchers[j].To = matchers[0]
	}

	r.AddMatchers = make([]*labels.Matcher, 0, len(r.AddMatchersRaw))
	for j, matcher := range r.AddMatchersRaw {
		matchers, err := parser.ParseMetricSelector(matcher)
		if err != nil {
			return fmt.Errorf("add-matchers[%d] label matcher %q: %w", j, matcher, err)
		}

		if len(matchers) != 1 {
			return fmt.Errorf("rewrite-matchers[%d] label matcher %q: must contain only one label matcher", j, matcher)
		}

		r.AddMatchers = append(r.AddMatchers, matchers[0])
	}

	return nil
}

func parseConfig(path string) ([]*Revisionist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var config Config
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	err = dec.Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	revisionists := make([]*Revisionist, 0, len(config.Rewrites))
	for i, rewrite := range config.Rewrites {
		err := rewrite.Parse()
		if err != nil {
			return nil, fmt.Errorf("invalid rewrites[%d].%w", i, err)
		}

		revisionists = append(revisionists, &Revisionist{config: &rewrite})
	}

	return revisionists, nil
}

type Revisionist struct {
	config *RewriteConfig
}

func (r *Revisionist) ShouldProcess(expr parser.Expr) bool {
	return r.config.For.MatchString(expr.Pretty(0))
}

func (r *Revisionist) WrapExpr(expr parser.Expr) (parser.Expr, error) {
	if r.config.Wrap.Match == nil || !r.config.Wrap.Match.MatchString(expr.Pretty(0)) {
		return expr, nil
	}

	wrapped, err := parser.ParseExpr(r.config.Wrap.WithRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid wrap prometheus expr: %w", err)
	}

	err = parser.Walk(&wrapper{inner: expr}, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("could not wrap prometheus expr: %w", err)
	}

	return wrapped, nil
}

type wrapper struct {
	inner parser.Expr
}

func (w *wrapper) Visit(node parser.Node, path []parser.Node) (parser.Visitor, error) {
	if node == nil && path == nil {
		return nil, nil
	}

	switch val := node.(type) {
	case *parser.BinaryExpr:
		if val.LHS.String() == "unwrapped_query" {
			val.LHS = w.inner
		} else {
			val.RHS = w.inner
		}

		return nil, nil
	default:
		return nil, fmt.Errorf("unhandled node %#T", node)
	}
}

func (r *Revisionist) Visit(node parser.Node, path []parser.Node) (parser.Visitor, error) {
	if node == nil && path == nil {
		return nil, nil
	}

	switch val := node.(type) {
	case *parser.AggregateExpr:
		for i, label := range val.Grouping {
			replacement, ok := r.config.RenameLabels[label]
			if ok {
				val.Grouping[i] = replacement
			}
		}
	case *parser.VectorSelector:
		replacement, ok := r.config.RenameMetrics[val.Name]
		if ok {
			val.Name = replacement
		}

		matchers := make([]*labels.Matcher, 0, len(val.LabelMatchers))
		for _, label := range val.LabelMatchers {
			if label.Name == "__name__" {
				replacement, ok := r.config.RenameMetrics[label.Value]
				if ok {
					label.Value = replacement
				}
			}

			replacement, ok := r.config.RenameLabels[label.Name]
			if ok {
				label.Name = replacement
			}

			for _, rewrite := range r.config.RewriteMatchers {
				if rewrite.To.Type == label.Type && rewrite.From.Name == label.Name && rewrite.From.Value == label.Value {
					label.Type = rewrite.To.Type
					label.Name = rewrite.To.Name
					label.Value = rewrite.To.Value
				}
			}

			shouldDelete := false
			for _, deleteLabel := range r.config.DeleteLabels {
				if label.Name == deleteLabel {
					shouldDelete = true
					break
				}
			}

			if shouldDelete {
				continue
			}

			matchers = append(matchers, label)
		}

		for _, matcher := range r.config.AddMatchers {
			matchers = append(matchers, matcher)
		}

		val.LabelMatchers = matchers
	}
	return r, nil
}
