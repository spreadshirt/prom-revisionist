package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

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
	flag.StringVar(&config.Addr, "addr", "localhost:19090", "Address to listen on")
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

		err = parser.Walk(revisionists[0], expr, nil)
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

		wasRewrite := false
		if len(req.PostForm) > 0 {
			query := req.PostForm.Get("query")
			if query != "" {
				expr, err := parser.ParseExpr(query)
				if err != nil {
					log.Printf("invalid query %q: %s", query, err)
				} else {
					before := expr.String()
					// TODO: support multiple revisionists!
					err = parser.Walk(revisionists[0], expr, nil)
					if err != nil {
						log.Printf("could not rewrite: %s", err)
					} else {
						expr, err = revisionists[0].WrapExpr(expr)
						if err != nil {
							log.Printf("could not wrap: %s", err)
						}
						log.Printf("rewriting!\n%s\n=>\n%s", before, expr.String())
						req.PostForm.Set("query", expr.String())

						wasRewrite = true
					}
				}
			}

			body = []byte(req.PostForm.Encode())
		}

		u := req.URL
		u.Scheme = upstreamURL.Scheme
		u.Host = upstreamURL.Host
		// TODO: modify query in url.Query/url.RawQuery
		proxyReq, err := http.NewRequest(req.Method, u.String(), bytes.NewBuffer(body))
		if err != nil {
			log.Printf("failed to created request: %s", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		proxyReq.Header = req.Header
		if wasRewrite {
			// TODO: allow keeping gzip and other encodings (handle them transparently)
			proxyReq.Header.Del("Accept-Encoding")
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

		var out io.Writer = w
		if resp.StatusCode != 200 {
			log.Printf("error %d", resp.StatusCode)
			out = io.MultiWriter(w, os.Stdout)
		}

		var in io.Reader = resp.Body
		if wasRewrite {
			log.Println("rewriting body")

			buf := new(bytes.Buffer)
			_, err = io.Copy(buf, resp.Body)
			if err != nil {
				log.Printf("could not write body: %s", err)
				return
			}

			if strings.Contains(buf.String(), `"service"`) {
				log.Println("rewriting service in response")
			}
			// TODO: rewrite by using streaming in some way
			res := strings.Replace(buf.String(), `"service"`, `"service_name"`, -1)
			res = strings.Replace(res, `"uri"`, `"operation"`, -1)

			buf.Reset()
			_, err = buf.WriteString(res)
			if err != nil {
				log.Printf("could not rewrite: %s", err)
				return
			}

			in = buf
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
	RenameMetrics   map[string]string `yaml:"rename-metrics"`
	RenameLabels    map[string]string `yaml:"rename-labels"`
	RewriteMatchers []struct {
		From    *labels.Matcher `yaml:"-"`
		To      *labels.Matcher `yaml:"-"`
		FromRaw string          `yaml:"from"`
		ToRaw   string          `yaml:"to"`
	} `yaml:"rewrite-matchers"`
	DeleteLabels   []string          `yaml:"delete-labels"`
	AddMatchers    []*labels.Matcher `yaml:"-"`
	AddMatchersRaw []string          `yaml:"add-matchers"`
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
		config.Rewrites[i].For, err = regexp.Compile(rewrite.ForRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid rewrites[%d].for regexp: %w", i, err)
		}

		config.Rewrites[i].Wrap.Match, err = regexp.Compile(rewrite.Wrap.MatchRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid rewrites[%d].wrap.match regexp: %w", i, err)
		}

		config.Rewrites[i].Wrap.With, err = parser.ParseExpr(rewrite.Wrap.WithRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid rewrites[%d].wrap.with promtheus expr: %w", i, err)
		}

		for j, matcher := range rewrite.RewriteMatchers {
			matchers, err := parser.ParseMetricSelector(matcher.FromRaw)
			if err != nil {
				return nil, fmt.Errorf("invalid rewrites[%d].rewrite-matchers[%d].from label matcher %q: %w", i, j, matcher.FromRaw, err)
			}

			if len(matchers) != 1 {
				return nil, fmt.Errorf("invalid rewrites[%d].rewrite-matchers[%d].from label matcher %q: must contain only one label matcher", i, j, matcher.FromRaw)
			}

			config.Rewrites[i].RewriteMatchers[j].From = matchers[0]

			matchers, err = parser.ParseMetricSelector(matcher.ToRaw)
			if err != nil {
				return nil, fmt.Errorf("invalid rewrites[%d].rewrite-matchers[%d].to label matcher %q: %w", i, j, matcher.ToRaw, err)
			}

			if len(matchers) != 1 {
				return nil, fmt.Errorf("invalid rewrites[%d].rewrite-matchers[%d].to label matcher %q: must contain only one label matcher", i, j, matcher.ToRaw)
			}

			config.Rewrites[i].RewriteMatchers[j].To = matchers[0]
		}

		config.Rewrites[i].AddMatchers = make([]*labels.Matcher, 0, len(rewrite.AddMatchersRaw))
		for j, matcher := range rewrite.AddMatchersRaw {
			matchers, err := parser.ParseMetricSelector(matcher)
			if err != nil {
				return nil, fmt.Errorf("invalid rewrites[%d].add-matchers[%d] label matcher %q: %w", i, j, matcher, err)
			}

			if len(matchers) != 1 {
				return nil, fmt.Errorf("invalid rewrites[%d].rewrite-matchers[%d] label matcher %q: must contain only one label matcher", i, j, matcher)
			}

			config.Rewrites[i].AddMatchers = append(config.Rewrites[i].AddMatchers, matchers[0])
		}

		revisionists = append(revisionists, &Revisionist{config: config.Rewrites[i]})
	}

	return revisionists, nil
}

type Revisionist struct {
	config RewriteConfig
}

func (r *Revisionist) ShouldProcess(expr parser.Expr) bool {
	return r.config.For.MatchString(expr.Pretty(0))
}

func (r *Revisionist) WrapExpr(expr parser.Expr) (parser.Expr, error) {
	log.Printf("WRAP? %v %q", r.config.Wrap.Match, r.config.Wrap.MatchRaw)
	log.Println(r.config.Wrap.Match.MatchString(expr.Pretty(0)), expr.Pretty(0))

	if r.config.Wrap.Match == nil || !r.config.Wrap.Match.MatchString(expr.Pretty(0)) {
		return expr, nil
	}

	log.Println("wrapping!")

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
