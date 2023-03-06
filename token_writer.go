package main

import (
	"encoding/json"
	"fmt"
	"io"
)

type tokenWriter struct {
	w   io.Writer
	dec *json.Decoder

	writers []TokenWriter
}

func NewTokenWriter(w io.Writer, dec *json.Decoder) *tokenWriter {
	return &tokenWriter{
		w:       w,
		dec:     dec,
		writers: []TokenWriter{simpleWriter{}},
	}
}

func (tw *tokenWriter) Write(token json.Token) error {
	if len(tw.writers) == 0 {
		return fmt.Errorf("no writer for token %#v", token)
	}

	curTw := tw.writers[len(tw.writers)-1]
	if curTw.Done(token) {
		tw.writers = tw.writers[:len(tw.writers)-1]
		curTw = tw.writers[len(tw.writers)-1]
	}

	nextTw, err := curTw.Write(tw.w, token, tw.dec.More())
	if err != nil {
		return fmt.Errorf("could not write: %w", err)
	}
	if nextTw != nil {
		tw.writers = append(tw.writers, nextTw)
	}

	return nil
}

type TokenWriter interface {
	Done(json.Token) bool
	Write(io.Writer, json.Token, bool) (TokenWriter, error)
}

type simpleWriter struct{}

func (sw simpleWriter) Done(json.Token) bool { return false }
func (sw simpleWriter) Write(w io.Writer, token json.Token, _ bool) (TokenWriter, error) {
	var err error
	var writer TokenWriter

	switch tok := token.(type) {
	case bool:
		_, err = fmt.Fprintf(w, "%v", tok)
	case string:
		_, err = fmt.Fprintf(w, "%q", tok)
	case json.Number:
		_, err = w.Write([]byte(tok))
	case float64:
		_, err = fmt.Fprintf(w, "%f", tok)
	case nil:
		_, err = w.Write([]byte("null"))
	case json.Delim:
		if tok == '{' {
			writer = &objectWriter{}
		} else if tok == '[' {
			writer = &arrayWriter{}
		}
		_, err = w.Write([]byte(tok.String()))
	default:
		err = fmt.Errorf("unhandled value %#v of type %T", token, token)
	}

	return writer, err
}

type objectWriter struct {
	simpleWriter

	n int
}

func (ow *objectWriter) Done(token json.Token) bool {
	return token == json.Delim('}')
}

func (ow *objectWriter) Write(w io.Writer, token json.Token, more bool) (TokenWriter, error) {
	tw, err := ow.simpleWriter.Write(w, token, more)
	if err != nil {
		return nil, err
	}
	if tw != nil {
		return tw, err
	}

	if ow.n%2 == 0 && more {
		_, err = w.Write([]byte(":"))
	} else if more {
		_, err = w.Write([]byte(","))
	}
	ow.n += 1

	return tw, err
}

type arrayWriter struct {
	simpleWriter

	n int
}

func (aw *arrayWriter) Done(token json.Token) bool {
	return token == json.Delim(']')
}

func (aw *arrayWriter) Write(w io.Writer, token json.Token, more bool) (TokenWriter, error) {
	tw, err := aw.simpleWriter.Write(w, token, more)
	if err != nil {
		return nil, err
	}
	if tw != nil {
		return tw, nil
	}

	if more {
		_, err = w.Write([]byte(","))
	}
	aw.n += 1

	return tw, err
}
