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

// Packge fetcher fetches the overseer-bindiff prepared binary diffs or the
// full binary from the configured URL.
//
// Not just the idea, but a lot of code is copied from
// https://github.com/sanbornm/go-selfupdate
// and modified (we don't have version here).
package fetcher

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"text/template"
	"time"

	"gopkg.in/errgo.v1"

	"github.com/kardianos/osext"
	"github.com/kr/binarydist"
)

const (
	DefaultInfoPath = "{{.GOOS}}_{{.GOARCH}}.json"
	DefaultDiffPath = "{{.GOOS}}_{{.GOARCH}}/{{.OldSha}}/{{.NewSha}}"
	DefaultBinPath  = "{{.GOOS}}_{{.GOARCH}}/{{.NewSha}}.gz"
)

var (
	LogPrefix = "[overseer-bindiff] "
	Logf      = Discardf
)

func Discardf(pattern string, args ...interface{}) {}

func logf(pattern string, args ...interface{}) {
	if Logf == nil {
		return
	}
	Logf(LogPrefix+pattern, args...)
}

// HTTPSelfUpdate is the configuration and runtime data for doing an update.
//
// First retrieves the current sha256 of the latest binary from <URL>/<InfoPath>
// such as http://example.com/mybin/linux-amd64.json
//
// Then tries the diffs from <URL>/<DiffPath>
// for example http://example.com/mybin/linux-amd64/aaa/bbb
//
// Then retrieves the full binary from <URL>/<BinPath>
// for example http://example.com/mybin/linux-amd64/bbb.gz
//
// InfoPath, DiffPath and BinPath are treated as text/template templates.
// Usable fields: GOOS, GOARCH, OldSha, NewSha, BinaryName.
type HTTPSelfUpdate struct {
	URL      string // Base URL for API requests
	InfoPath string // template for info path, defaults to DefaultInfoPath
	DiffPath string // template for diff path, defaults to DefaultDiffPath
	BinPath  string // template for full binary path, defaults to DefaultBinPath
	Info     Info
	Interval time.Duration

	//interal state
	delay     bool
	lasts     map[string]string
	Templates Templates
}
type Info struct {
	Sha256 []byte // sha256 of the latest version
}

type Templates struct {
	Info, Diff, Bin *template.Template
}

func (t *Templates) Init(info, diff, bin string) error {
	if info == "" {
		info = DefaultInfoPath
	}
	var err error
	if t.Info, err = template.New("info").Parse(info); err != nil {
		return errgo.Notef(err, "parse info template %q", info)
	}
	if diff == "" {
		diff = DefaultDiffPath
	}
	if t.Diff, err = template.New("diff").Parse(diff); err != nil {
		return errgo.Notef(err, "parse diff template %q", diff)
	}
	if bin == "" {
		bin = DefaultBinPath
	}
	if t.Bin, err = template.New("bin").Parse(bin); err != nil {
		return errgo.Notef(err, "parse bin template %q", bin)
	}
	return nil
}

type Platform struct {
	GOOS, GOARCH string
}

var thePlatform = Platform{
	GOOS:   runtime.GOOS,
	GOARCH: runtime.GOARCH,
}
var self string

type URLInfo struct {
	Platform
	OldSha, NewSha, BinaryName string
}

// Init initializes the templates and returns any error met.
func (h *HTTPSelfUpdate) Init() error {
	if h.Interval == 0 {
		h.Interval = 5 * time.Minute
	}

	var err error
	self, err = osext.Executable()
	if err != nil {
		return errgo.Notef(err, "find self executable")
	}

	return h.Templates.Init(h.InfoPath, h.DiffPath, h.BinPath)
}

func (_ Templates) Execute(tpl *template.Template, info URLInfo) (string, error) {
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, info); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (h *HTTPSelfUpdate) Fetch() (io.Reader, error) {
	//delay fetches after first
	if h.delay {
		time.Sleep(h.Interval)
	}
	h.delay = true

	var old io.ReadSeeker
	fh, err := os.Open(self)
	if err == nil {
		defer fh.Close()
		old = fh
	} else {
		logf("cannot open %q: %v", self, err)
	}

	// fetch info
	if err = h.fetchInfo(); err != nil {
		return nil, err
	}

	hsh := NewSha()
	if _, err := io.Copy(hsh, fh); err != nil {
		return nil, errgo.Notef(err, "read binary %q", fh.Name())
	}
	oldSha := hsh.Sum(nil)
	if bytes.Equal(oldSha, h.Info.Sha256) {
		return nil, nil
	}
	if _, err := fh.Seek(0, 0); err != nil {
		return nil, errgo.Notef(err, "seek back to the beginning of %q", fh.Name())
	}

	var bin []byte
	if old != nil {
		if bin, err = h.fetchAndVerifyPatch(old, oldSha); err != nil {
			bin = nil
			if err == ErrHashMismatch {
				logf("update: hash mismatch from patched binary")
			}
		}
	}
	if bin == nil {
		if bin, err = h.fetchAndVerifyFullBin(); err != nil {
			if err == ErrHashMismatch {
				logf("update: hash mismatch from full binary")
			} else {
				logf("update: fetching full binary: %v", err)
			}
			return nil, err
		}
	}

	//success!
	return bytes.NewReader(bin), nil
}

func fetch(URL string) (io.ReadCloser, error) {
	logf("fetch %q", URL)
	resp, err := http.Get(URL)
	if err != nil {
		return nil, errgo.Notef(err, "GET %q", URL)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errgo.Newf("GET failed for %q: %d", URL, resp.StatusCode)
	}
	return resp.Body, nil
}

func (h HTTPSelfUpdate) getPath(which string, oldSha, newSha []byte) (string, error) {
	var tpl *template.Template
	switch which {
	case "info":
		tpl = h.Templates.Info
	case "diff":
		tpl = h.Templates.Diff
	case "bin":
		tpl = h.Templates.Bin
	default:
		return "", errgo.Newf("unknown template %q", which)
	}
	var oldShaS, newShaS string
	if len(oldSha) > 0 {
		oldShaS = EncodeSha(oldSha)
	}
	if len(newSha) > 0 {
		newShaS = EncodeSha(newSha)
	}
	ui := URLInfo{
		Platform:   thePlatform,
		OldSha:     oldShaS,
		NewSha:     newShaS,
		BinaryName: filepath.Base(self),
	}
	path, err := h.Templates.Execute(tpl, ui)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", errgo.Newf("empty path from %v", ui)
	}
	return path, nil
}

func (h *HTTPSelfUpdate) fetchInfo() error {
	path, err := h.getPath("info", nil, nil)
	if err != nil {
		return errgo.Notef(err, "get info path")
	}
	r, err := fetch(h.URL + "/" + path)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	err = json.NewDecoder(io.TeeReader(r, &buf)).Decode(&h.Info)
	r.Close()
	if err != nil {
		return errgo.Notef(err, "decode %q", buf.String())
	}
	if len(h.Info.Sha256) != sha256.Size {
		return errgo.New("bad cmd hash in info")
	}
	logf("Upstream hash is %q.", EncodeSha(h.Info.Sha256))
	return nil
}

var ErrHashMismatch = errors.New("hash mismatch")

func (h *HTTPSelfUpdate) fetchAndVerifyPatch(old io.ReadSeeker, oldSha []byte) ([]byte, error) {
	if old == nil {
		return nil, errors.New("empty old")
	}
	bin, err := h.fetchAndApplyPatch(old, oldSha)
	if err != nil {
		return nil, err
	}
	if !verifySha(bin, h.Info.Sha256) {
		return nil, ErrHashMismatch
	}
	return bin, nil
}

func (h *HTTPSelfUpdate) fetchAndApplyPatch(old io.ReadSeeker, oldSha []byte) ([]byte, error) {
	if len(oldSha) != sha256.Size {
		oldSha = GetSha(old)
		if _, err := old.Seek(0, 0); err != nil {
			return nil, err
		}
	}
	path, err := h.getPath("diff", oldSha, h.Info.Sha256)
	if err != nil {
		return nil, err
	}
	r, err := fetch(h.URL + "/" + path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var buf bytes.Buffer
	err = binarydist.Patch(old, &buf, r)
	return buf.Bytes(), err
}

func (h *HTTPSelfUpdate) fetchAndVerifyFullBin() ([]byte, error) {
	bin, err := h.fetchBin()
	if err != nil {
		return nil, err
	}
	verified := verifySha(bin, h.Info.Sha256)
	if !verified {
		return nil, ErrHashMismatch
	}
	return bin, nil
}

func (h *HTTPSelfUpdate) fetchBin() ([]byte, error) {
	path, err := h.getPath("bin", nil, h.Info.Sha256)
	if err != nil {
		return nil, err
	}
	r, err := fetch(h.URL + "/" + path)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	buf := new(bytes.Buffer)
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(buf, gz); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func NewSha() hash.Hash {
	return sha256.New()
}

func verifySha(b []byte, sha []byte) bool {
	h := NewSha()
	h.Write(b)
	return bytes.Equal(h.Sum(nil), sha)
}

func EncodeSha(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}
func DecodeSha(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

func GetSha(r io.Reader) []byte {
	h := NewSha()
	io.Copy(h, r)
	return h.Sum(nil)
}
