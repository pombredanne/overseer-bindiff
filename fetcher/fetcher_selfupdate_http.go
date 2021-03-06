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

// Package fetcher fetches the overseer-bindiff prepared binary diffs or the
// full binary from the configured URL.
//
// Not just the idea, but a lot of code is copied from
// https://github.com/sanbornm/go-selfupdate
// and modified (we don't have version here).
package fetcher

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/openpgp"

	"github.com/kardianos/osext"
	"github.com/kr/binarydist"
	"github.com/pkg/errors"
)

const (
	DefaultInfoPath = "{{.GOOS}}_{{.GOARCH}}.json"
	DefaultDiffPath = "{{.GOOS}}_{{.GOARCH}}/{{.OldSha}}/{{.NewSha}}{{if .IsEncrypted}}.gpg{{end}}"
	DefaultBinPath  = "{{.GOOS}}_{{.GOARCH}}/{{.NewSha}}.gz{{if .IsEncrypted}}.gpg{{end}}"

	DefaultFetchInfoTimeout  = 10 * time.Second
	DefaultFetchPatchTimeout = 1 * time.Minute
	DefaultFetchBinTimeout   = 10 * time.Minute
)

var (
	LogPrefix = "[overseer-bindiff] "
	Logf      = Discardf
)
var (
	ErrNoPassphrase = errors.New("no passphrase for key")
	KeyPrompt       = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return nil, ErrNoPassphrase
	}
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
// Usable fields: GOOS, GOARCH, OldSha, NewSha, BinaryName, IsEncrypted.
//
// URLs starting with "file://" are treated as file path, and opened directly with os.Open - mainly for testing.
type HTTPSelfUpdate struct {
	URL      string // Base URL for API requests
	InfoPath string // template for info path, defaults to DefaultInfoPath
	DiffPath string // template for diff path, defaults to DefaultDiffPath
	BinPath  string // template for full binary path, defaults to DefaultBinPath
	Info     Info
	Interval time.Duration

	FetchInfoTimeout  time.Duration
	FetchPatchTimeout time.Duration
	FetchBinTimeout   time.Duration

	Keyring openpgp.KeyRing // for decrypting encrypted binary

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
		return errors.Wrapf(err, "parse info template %q", info)
	}
	if diff == "" {
		diff = DefaultDiffPath
	}
	if t.Diff, err = template.New("diff").Parse(diff); err != nil {
		return errors.Wrapf(err, "parse diff template %q", diff)
	}
	if bin == "" {
		bin = DefaultBinPath
	}
	if t.Bin, err = template.New("bin").Parse(bin); err != nil {
		return errors.Wrapf(err, "parse bin template %q", bin)
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
	IsEncrypted                bool
}

// Init initializes the templates and returns any error met.
func (h *HTTPSelfUpdate) Init() error {
	if h.Interval == 0 {
		h.Interval = 5 * time.Minute
	}

	var err error
	self, err = osext.Executable()
	if err != nil {
		return errors.Wrapf(err, "find self executable")
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
		logf("sleep %s", h.Interval)
		time.Sleep(h.Interval)
	}
	h.delay = true

	var old io.ReadSeeker
	fh, err := os.Open(self)
	if err == nil {
		defer fh.Close()
		old = fh
	} else {
		logf("cannot open %q: %+v", self, err)
	}

	// fetch info
	if err = h.fetchInfo(); err != nil {
		return nil, err
	}

	hsh := NewSha()
	if _, err := io.Copy(hsh, fh); err != nil {
		return nil, errors.Wrapf(err, "read binary %q", fh.Name())
	}
	oldSha := hsh.Sum(nil)
	if bytes.Equal(oldSha, h.Info.Sha256) {
		return nil, nil
	}
	if _, err := fh.Seek(0, 0); err != nil {
		return nil, errors.Wrapf(err, "seek back to the beginning of %q", fh.Name())
	}

	var bin []byte
	if old != nil {
		if bin, err = h.fetchAndVerifyPatch(old, oldSha); err != nil {
			bin = nil
			if err == ErrHashMismatch {
				logf("update: hash mismatch from patched binary")
			} else {
				logf("update: fetching patch: %+v", err)
			}
		}
	}
	if bin == nil {
		if bin, err = h.fetchAndVerifyFullBin(); err != nil {
			if err == ErrHashMismatch {
				logf("update: hash mismatch from full binary")
			} else {
				logf("update: fetching full binary: %+v", err)
			}
			return nil, err
		}
	}

	//success!
	logf("success, binary length=%d", len(bin))
	return bytes.NewReader(bin), nil
}

func fetch(ctx context.Context, URL string, keyring openpgp.KeyRing) (io.ReadCloser, error) {
	logf("fetch %q", URL)
	if strings.HasPrefix(URL, "file://") { // great for testing
		return os.Open(URL[7:])
	}
	req, err := http.NewRequest("GET", URL, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "NewRequest(%q)", URL)
	}
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logf("fetch %q: %+v", URL, err)
		return nil, errors.Wrapf(err, "GET %q", URL)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		logf("fetch %q: %v", URL, resp.StatusCode)
		return nil, errors.New(fmt.Sprintf("GET failed for %q: %d", URL, resp.StatusCode))
	}
	logf("fetched %q: %v", URL, resp.StatusCode)
	if !HasKeys(keyring) {
		return resp.Body, nil
	}
	md, err := openpgp.ReadMessage(resp.Body, keyring, KeyPrompt, nil)
	if err != nil {
		resp.Body.Close()
		logf("read %q with keyring %v: %+v", URL, keyring, err)
		return nil, errors.Wrapf(err, "read pgp message with %v", keyring)
	}
	var part [1024]byte
	n, err := io.ReadAtLeast(md.UnverifiedBody, part[:], cap(part)/2)
	return struct {
		io.Reader
		io.Closer
	}{
		io.MultiReader(bytes.NewReader(part[:n]), md.UnverifiedBody),
		resp.Body,
	}, errors.Wrapf(err, "read UnverifiedBody with %v", keyring)
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
		return "", errors.New("unknown template " + which)
	}
	var oldShaS, newShaS string
	if len(oldSha) > 0 {
		oldShaS = EncodeSha(oldSha)
	}
	if len(newSha) > 0 {
		newShaS = EncodeSha(newSha)
	}
	ui := URLInfo{
		Platform:    thePlatform,
		OldSha:      oldShaS,
		NewSha:      newShaS,
		BinaryName:  filepath.Base(self),
		IsEncrypted: HasKeys(h.Keyring),
	}
	path, err := h.Templates.Execute(tpl, ui)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", errors.New(fmt.Sprintf("empty path from %v", ui))
	}
	return path, nil
}

func (h *HTTPSelfUpdate) fetchInfo() error {
	path, err := h.getPath("info", nil, nil)
	if err != nil {
		return errors.Wrapf(err, "get info path")
	}
	ctx, cancel := getTimeoutCtx(context.Background(), h.FetchInfoTimeout, DefaultFetchInfoTimeout)
	defer cancel()
	r, err := fetch(ctx, h.URL+"/"+path, nil)
	if err != nil {
		return err
	}
	b, err := ioutil.ReadAll(r)
	r.Close()
	if err != nil {
		return err
	}

	if HasKeys(h.Keyring) {
		r, err := fetch(ctx, h.URL+"/"+path+".asc", nil)
		if err != nil {
			return err
		}
		_, err = openpgp.CheckArmoredDetachedSignature(h.Keyring, bytes.NewReader(b), r)
		r.Close()
		if err != nil {
			for _, e := range h.Keyring.(openpgp.EntityList) {
				logf("%q", e.Identities)
			}
			return errors.Wrapf(err, "check %q with %q", b, h.Keyring)
		}
	}
	err = json.NewDecoder(bytes.NewReader(b)).Decode(&h.Info)
	if err != nil {
		return errors.Wrapf(err, "decode %q", b)
	}
	if len(h.Info.Sha256) != sha256.Size {
		return errors.New("bad cmd hash in info")
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
	ctx, cancel := getTimeoutCtx(context.Background(), h.FetchPatchTimeout, DefaultFetchPatchTimeout)
	defer cancel()
	r, err := fetch(ctx, h.URL+"/"+path, h.Keyring)
	if err != nil {
		return nil, errors.WithMessage(err, "fetchAndVerifyPatch")
	}
	defer r.Close()
	var buf bytes.Buffer
	err = binarydist.Patch(old, &buf, r)
	return buf.Bytes(), errors.Wrap(err, "apply patch")
}

func (h *HTTPSelfUpdate) fetchAndVerifyFullBin() ([]byte, error) {
	bin, err := h.fetchBin()
	if err != nil {
		return nil, errors.WithMessage(err, "fetchAndVerifyFullBin")
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
	ctx, cancel := getTimeoutCtx(context.Background(), h.FetchBinTimeout, DefaultFetchBinTimeout)
	defer cancel()
	r, err := fetch(ctx, h.URL+"/"+path, h.Keyring)
	if err != nil {
		return nil, errors.WithMessage(err, "fetchBin")
	}
	defer r.Close()
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, errors.Wrap(err, "gzip")
	}
	b, err := ioutil.ReadAll(gz)
	return b, errors.Wrap(err, "read gzip")
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
func getTimeoutCtx(ctx context.Context, d time.Duration, def time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if d < 0 {
		return ctx, func() {}
	}
	if d == 0 {
		d = def
	}
	return context.WithTimeout(ctx, d)
}
