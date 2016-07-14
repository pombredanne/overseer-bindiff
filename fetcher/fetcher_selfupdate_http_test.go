// Copyright (c) 2016 Tamás Gulácsi
//
// The MIT License (MIT)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package fetcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
)

func TestTemplates(t *testing.T) {
	tpl := Templates{}
	if err := tpl.Init("", "", ""); err != nil {
		t.Fatal(err)
	}
	info := URLInfo{
		Platform: Platform{GOOS: "goos", GOARCH: "goarch"},
		OldSha:   "oldsha", NewSha: "newsha", BinaryName: "Binary",
		IsEncrypted: true,
	}
	if s, err := tpl.Execute(tpl.Info, info); err != nil {
		t.Fatal(err)
	} else if await := "goos_goarch.json"; s != await {
		t.Errorf("info got %q, awaited %q.", s, await)
	}

	if s, err := tpl.Execute(tpl.Diff, info); err != nil {
		t.Fatal(err)
	} else if await := "goos_goarch/oldsha/newsha.gpg"; s != await {
		t.Errorf("diff got %q, awaited %q.", s, await)
	}

	if s, err := tpl.Execute(tpl.Bin, info); err != nil {
		t.Fatal(err)
	} else if await := "goos_goarch/newsha.gz.gpg"; s != await {
		t.Errorf("bin got %q, awaited %q.", s, await)
	}
}

func TestFetchInfo(t *testing.T) {
	Logf = func(prefix string, keyvals ...interface{}) {
		t.Logf(prefix, keyvals...)
	}
	if !HasKeys(testKeyring) {
		t.Fatal("keyring is empty!")
	}
	server := httptest.NewServer(testHandler(t))
	defer server.Close()
	su := &HTTPSelfUpdate{
		URL:      server.URL,
		InfoPath: "info.json",
		DiffPath: "diff",
		BinPath:  "bin.gz",
		Keyring:  testKeyring,
	}
	su.Init()

	if err := su.fetchInfo(); err != nil {
		t.Errorf("%+v", err)
	}
}

func testHandler(t *testing.T) http.Handler {
	const bin = `This is NOT a binary!`
	sha := sha256.New()
	io.WriteString(sha, bin)
	infoJSON := `{"Sha256":"` + base64.StdEncoding.EncodeToString(sha.Sum(nil)) + `"}`
	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&buf, SignerKey(testKeyring), strings.NewReader(infoJSON), nil); err != nil {
		panic(err)
	}
	infoJSONAsc := buf.String()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/info.json":
			io.WriteString(w, infoJSON)
		case "/info.json.asc":
			io.WriteString(w, infoJSONAsc)
		default:
			http.Error(w, r.URL.Path+" NOT FOUND", http.StatusNotFound)
		}
	})
}
