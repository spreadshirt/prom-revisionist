package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/require"
)

type testStruct struct {
	Nested struct {
		A safeString
		B float64
		C bool
		D *bool

		DoubleNested struct {
			Stuff safeString
			// Recursive *testStruct
		}
	}

	Array       []safeString
	StructArray []struct {
		X safeString
		Y float64
		Z float64

		Contents struct {
			Name safeString
		}
	}
}

type safeString string

func (s safeString) Generate(rand *rand.Rand, size int) reflect.Value {
	buf := make([]byte, size)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return reflect.ValueOf(safeString(fmt.Sprintf("%x", buf)))
}

func TestTokenWriter(t *testing.T) {
	plain := func(ts testStruct) testStruct {
		return ts
	}
	writeAndParse := func(ts testStruct) testStruct {
		data, err := json.Marshal(ts)
		require.NoError(t, err, "marshal")

		buf := new(bytes.Buffer)
		dec := json.NewDecoder(bytes.NewBuffer(data))
		tw := NewTokenWriter(buf, dec)
		token, err := dec.Token()
		for err == nil {
			err = tw.Write(token)
			if err != nil {
				err = fmt.Errorf("token write: %w", err)
				continue
			}
			token, err = dec.Token()
		}
		if err != nil && err != io.EOF {
			require.NoError(t, err, "token write")
		}

		var res testStruct
		err = json.Unmarshal(buf.Bytes(), &res)
		if synErr, ok := err.(*json.SyntaxError); err != nil && ok {
			err = fmt.Errorf("syntax error: %w << %s >>", err, buf.Bytes()[synErr.Offset-10:synErr.Offset+10])
		}
		require.NoError(t, err, "unmarshal")

		require.Equal(t, ts, res)

		return res
	}

	err := quick.CheckEqual(plain, writeAndParse, nil)
	require.NoError(t, err)
}
