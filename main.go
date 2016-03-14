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

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kr/binarydist"
	"github.com/tgulacsi/overseer-bindiff/fetcher"
)

func main() {
	genDir := "public"
	flag.StringVar(&genDir, "o", genDir, "Output directory for writing updates")

	goos := os.Getenv("GOOS")
	goarch := os.Getenv("GOARCH")
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	flag.StringVar(&goos, "os", goos,
		"Target OS. Defaults to running os or the environment variable GOOS.")
	flag.StringVar(&goarch, "arch", goarch,
		"Target ARCH. Defaults to running arch or the environment variable GOARCH.")
	var u fetcher.HTTPSelfUpdate
	flag.StringVar(&u.InfoPath, "bin", fetcher.DefaultInfoPath, "info path template")
	flag.StringVar(&u.DiffPath, "bin", fetcher.DefaultDiffPath, "diff path template")
	flag.StringVar(&u.BinPath, "bin", fetcher.DefaultBinPath, "binary path template")

	flag.Parse()
	var appPath string
	if flag.NArg() < 1 {
		var err error
		if appPath, err = os.Getwd(); err != nil {
			log.Fatal(err)
		}
	} else {
		appPath = flag.Arg(0)
	}

	if err := u.Init(); err != nil {
		log.Fatal(err)
	}
	os.MkdirAll(genDir, 0755)

	// If dir is given create update for each file
	fi, err := os.Stat(appPath)
	if err != nil {
		log.Fatal(err)
	}

	if !fi.IsDir() {
		if err = createUpdate(genDir, u, appPath, goos, goarch); err != nil {
			log.Fatal(err)
		}
	}

	files, err := ioutil.ReadDir(appPath)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		parts := strings.SplitN(file.Name(), "-", 2)
		if err := createUpdate(
			genDir,
			u,
			filepath.Join(appPath, file.Name()),
			parts[0], parts[1],
		); err != nil {
			log.Fatal(err)
		}
	}
}

func createUpdate(genDir string, u fetcher.HTTPSelfUpdate, path string, goos, goarch string) error {
	c := fetcher.Info{Sha256: generateSha(path)}

	fh, err := os.Create(filepath.Join(genDir, h.GetPath("info")), 0755)
	if err != nil {
		return err
	}
	defer fh.Close()
	if err := json.NewEncoder(fh).Encode(c); err != nil {
		return err
	}
	return fh.Close()

	os.MkdirAll(filepath.Join(genDir, version), 0755)

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	f, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	w.Write(f)
	w.Close() // You must close this first to flush the bytes to the buffer.
	err = ioutil.WriteFile(filepath.Join(genDir, version, platform+".gz"), buf.Bytes(), 0755)

	files, err := ioutil.ReadDir(genDir)
	if err != nil {
		fmt.Println(err)
	}

	for _, file := range files {
		if file.IsDir() == false {
			continue
		}
		if file.Name() == version {
			continue
		}

		os.Mkdir(filepath.Join(genDir, file.Name(), version), 0755)

		fName := filepath.Join(genDir, file.Name(), platform+".gz")
		old, err := os.Open(fName)
		if err != nil {
			// Don't have an old release for this os/arch, continue on
			continue
		}

		fName = filepath.Join(genDir, version, platform+".gz")
		newF, err := os.Open(fName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Can't open %s: error: %s\n", fName, err)
			os.Exit(1)
		}

		ar := newGzReader(old)
		defer ar.Close()
		br := newGzReader(newF)
		defer br.Close()
		patch := new(bytes.Buffer)
		if err := binarydist.Diff(ar, br, patch); err != nil {
			panic(err)
		}
		ioutil.WriteFile(filepath.Join(genDir, file.Name(), version, platform), patch.Bytes(), 0755)
	}
}

func printUsage() {
	fmt.Println(`
Positional arguments:
	Single platform: go-selfupdate myapp
	Cross platform: go-selfupdate /tmp/mybinares/`)
}

func generateSha(path string) []byte {
	fh, err := os.Open(path)
	if err != nil {
		log.Println(err)
		return nil
	}
	s := fetcher.GetSha(fh)
	fh.Close()
	return s
}

type gzReader struct {
	z, r io.ReadCloser
}

func (g *gzReader) Read(p []byte) (int, error) {
	return g.z.Read(p)
}

func (g *gzReader) Close() error {
	g.z.Close()
	return g.r.Close()
}

func newGzReader(r io.ReadCloser) io.ReadCloser {
	var err error
	g := new(gzReader)
	g.r = r
	g.z, err = gzip.NewReader(r)
	if err != nil {
		panic(err)
	}
	return g
}
