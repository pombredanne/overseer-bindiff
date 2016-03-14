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
// Not just the idea, but lot of code is copied from
// https://github.com/sanbornm/go-selfupdate
package fetcher

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/kardianos/osext"
	"github.com/kr/binarydist"
)

const plat = runtime.GOOS + "-" + runtime.GOARCH

// HTTPSelfUpdate is the configuration and runtime data for doing an update.
//
// First retrieves the current sha256 of the latest binary from <URL>/<platform>.json
// such as http://example.com/mybin/linux-amd64.json
//
// Then tries the diffs from <URL>/<plat>/<oldsha>/<newsha>
// for example http://example.com/mybin/linux-amd64/aaa/bbb
//
// Then retrieves the full binary from <URL>/<platform>/<current_sha>.gz
// for example http://example.com/mybin/linux-amd64/bbb.gz
type HTTPSelfUpdate struct {
	URL  string // Base URL for API requests
	Info struct {
		Sha256 []byte // sha256 of the latest version
	}
	Interval time.Duration

	//interal state
	delay bool
	lasts map[string]string
}

func (h *HTTPSelfUpdate) Init() error {
	if h.Interval == 0 {
		h.Interval = 5 * time.Minute
	}
	return nil
}

func (h *HTTPSelfUpdate) Fetch() (io.Reader, error) {
	//delay fetches after first
	if h.delay {
		time.Sleep(h.Interval)
	}
	h.delay = true

	var old io.ReadSeeker
	path, err := osext.Executable()
	if err != nil {
		log.Printf("cannot find executable: %v", err)
	} else {
		fh, err := os.Open(path)
		if err == nil {
			defer fh.Close()
			old = fh
		} else {
			log.Printf("cannot open %q: %v", path, err)
		}
	}

	// fetch info
	if err = h.fetchInfo(); err != nil {
		return nil, err
	}

	var bin []byte
	if old != nil {
		if bin, err = h.fetchAndVerifyPatch(old); err != nil {
			bin = nil
			if err == ErrHashMismatch {
				log.Println("update: hash mismatch from patched binary")
			}
		}
	}
	if bin == nil {
		if bin, err = h.fetchAndVerifyFullBin(); err != nil {
			if err == ErrHashMismatch {
				log.Println("update: hash mismatch from full binary")
			} else {
				log.Println("update: fetching full binary,", err)
			}
			return nil, err
		}
	}

	//success!
	return bytes.NewReader(bin), nil
}

func fetch(URL string) (io.ReadCloser, error) {
	resp, err := http.Get(URL)
	if err != nil {
		return nil, fmt.Errorf("GET %q: %v", URL, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET failed for %q: %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func (h *HTTPSelfUpdate) fetchInfo() error {
	r, err := fetch(h.URL + "/" + plat + ".json")
	if err != nil {
		return err
	}
	err = json.NewDecoder(r).Decode(&h.Info)
	r.Close()
	if err != nil {
		return err
	}
	if len(h.Info.Sha256) != sha256.Size {
		return errors.New("bad cmd hash in info")
	}
	return nil
}

var ErrHashMismatch = errors.New("hash mismatch")

func (h *HTTPSelfUpdate) fetchAndVerifyPatch(old io.ReadSeeker) ([]byte, error) {
	if old == nil {
		return nil, errors.New("empty old")
	}
	bin, err := h.fetchAndApplyPatch(old)
	if err != nil {
		return nil, err
	}
	if !verifySha(bin, h.Info.Sha256) {
		return nil, ErrHashMismatch
	}
	return bin, nil
}

func (h *HTTPSelfUpdate) fetchAndApplyPatch(old io.ReadSeeker) ([]byte, error) {
	cur := getSha(old)
	if _, err := old.Seek(0, 0); err != nil {
		return nil, err
	}
	r, err := fetch(fmt.Sprintf("%s/%s/%x/%x", h.URL, plat, cur, h.Info.Sha256))
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
	r, err := fetch(fmt.Sprintf("%s/%s/%x.gz", h.URL, plat, h.Info.Sha256))
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

func verifySha(b []byte, sha []byte) bool {
	h := sha256.New()
	h.Write(b)
	return bytes.Equal(h.Sum(nil), sha)
}

func getSha(r io.Reader) []byte {
	h := sha256.New()
	io.Copy(h, r)
	return h.Sum(nil)
}
