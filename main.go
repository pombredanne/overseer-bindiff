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

	"gopkg.in/errgo.v1"

	"github.com/kr/binarydist"
	"github.com/tgulacsi/overseer-bindiff/fetcher"
)

func main() {
	fetcher.Logf = log.Printf

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
	var infoPath, diffPath, binPath string
	flag.StringVar(&infoPath, "info", fetcher.DefaultInfoPath, "info path template")
	flag.StringVar(&diffPath, "diff", fetcher.DefaultDiffPath, "diff path template")
	flag.StringVar(&binPath, "bin", fetcher.DefaultBinPath, "binary path template")

	flag.Usage = printUsage
	flag.Parse()
	var appPath string
	if flag.NArg() < 1 {
		printUsage()
		os.Exit(1)
	} else {
		appPath = flag.Arg(0)
	}

	var tpl fetcher.Templates
	if err := tpl.Init(infoPath, diffPath, binPath); err != nil {
		log.Fatal(err)
	}
	os.MkdirAll(genDir, 0755)

	// If dir is given create update for each file
	fi, err := os.Stat(appPath)
	if err != nil {
		log.Fatal(err)
	}

	if !fi.IsDir() {
		src, err := os.Open(appPath)
		if err != nil {
			log.Fatal(errgo.Notef(err, "open %q", appPath))
		}
		err = createUpdate(genDir, tpl, src,
			fetcher.Platform{GOOS: goos, GOARCH: goarch},
		)
		src.Close()
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	files, err := ioutil.ReadDir(appPath)
	if err != nil {
		log.Fatal(errgo.Notef(err, "read dir %q", appPath))
	}
	for _, file := range files {
		fn := filepath.Join(appPath, file.Name())
		src, err := os.Open(fn)
		if err != nil {
			log.Println(errgo.Notef(err, "open %q", fn))
			continue
		}
		parts := strings.SplitN(file.Name(), "-", 2)
		err = createUpdate(
			genDir,
			tpl,
			src,
			fetcher.Platform{GOOS: parts[0], GOARCH: parts[1]},
		)
		src.Close()
		if err != nil {
			log.Fatal(err)
		}
	}
}

func createUpdate(genDir string, tpl fetcher.Templates, src io.ReadSeeker, plat fetcher.Platform) error {
	// generate the sha256 of the binary
	h := fetcher.NewSha()
	if _, err := io.Copy(h, src); err != nil {
		return errgo.Notef(err, "hash %q", src)
	}
	if _, err := src.Seek(0, 0); err != nil {
		return errgo.Notef(err, "seek back to the beginning of %q", src)
	}
	newSha := h.Sum(nil)
	info := fetcher.URLInfo{
		Platform: plat,
		NewSha:   fetcher.EncodeSha(newSha),
	}

	// gzip the binary to its destination
	binPath, err := tpl.Execute(tpl.Bin, info)
	if err != nil {
		return errgo.Notef(err, "execute bin template")
	}
	binPath = filepath.Join(genDir, binPath)
	log.Printf("Writing binary to %q.", binPath)
	os.MkdirAll(filepath.Dir(binPath), 0755)
	fh, err := os.Create(binPath)
	if err != nil {
		return errgo.Notef(err, "create %q", binPath)
	}
	defer fh.Close()
	w := gzip.NewWriter(fh)
	if _, err := io.Copy(w, src); err != nil {
		return errgo.Notef(err, "gzip %q into %q", src, fh.Name())
	}
	if err := w.Close(); err != nil {
		return errgo.Notef(err, "flush gzip into %q", fh.Name())
	}
	if err := fh.Close(); err != nil {
		return errgo.Notef(err, "close %q", fh.Name())
	}

	// write info.json
	infoPath, err := tpl.Execute(tpl.Info, info)
	if err != nil {
		return errgo.Notef(err, "execute info template")
	}
	infoPath = filepath.Join(genDir, infoPath)
	log.Printf("Writing info to %q.", infoPath)
	os.MkdirAll(filepath.Dir(infoPath), 0755)
	fh, err = os.Create(infoPath)
	if err != nil {
		return errgo.Notef(err, "create %q", infoPath)
	}
	defer fh.Close()
	if err := json.NewEncoder(fh).Encode(fetcher.Info{Sha256: newSha}); err != nil {
		return errgo.Notef(err, "encode %v into %q", newSha, fh.Name())
	}
	if err := fh.Close(); err != nil {
		return errgo.Notef(err, "close %q", fh.Name())
	}

	info.OldSha = oldShaPlaceholder
	diffPath, err := tpl.Execute(tpl.Diff, info)
	if err != nil {
		return errgo.Notef(err, "execute diff template")
	}
	return generateDiffs(filepath.Join(genDir, diffPath), binPath)
}

const oldShaPlaceholder = "{{OLDSHA}}"

// generateDiffs calculates and writes the differences between the current
// binary and the old binaries, into diffPath.
//
// binPath must be the current binary's filename (with full path),
// and the old binaries are searched in that directory;
//
// diffPath should be the full path for the difference between the current
// binary and the binary named as oldShaPlaceholder.
func generateDiffs(diffPath, binPath string) error {
	binDir, currentName := filepath.Split(binPath)
	files, err := ioutil.ReadDir(binDir)
	if err != nil {
		return errgo.Notef(err, "read %q", binDir)
	}
	getSha := func(fn string) string {
		fn = filepath.Base(fn)
		if ext := filepath.Ext(fn); ext != "" {
			return fn[:len(fn)-len(ext)]
		}
		return fn
	}

	currentRaw, err := os.Open(binPath)
	if err != nil {
		return errgo.Notef(err, "open %q", binPath)
	}
	defer currentRaw.Close()

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if file.Name() == currentName {
			continue
		}
		oldSha := getSha(file.Name())

		fn := filepath.Join(binDir, file.Name())
		log.Printf("Calculating diff between %q and %q.", fn, binPath)
		oldRaw, err := os.Open(fn)
		if err != nil {
			log.Println(errgo.Notef(err, "open %q", fn))
			continue
		}
		defer oldRaw.Close()

		if _, err = currentRaw.Seek(0, 0); err != nil {
			return errgo.Notef(err, "seek back to the beginning of %q", currentRaw.Name())
		}
		current, err := gzip.NewReader(currentRaw)
		if err != nil {
			return errgo.Notef(err, "gzip decode %q", currentRaw.Name())
		}

		old, err := gzip.NewReader(oldRaw)
		if err != nil {
			log.Println(err)
			continue
		}
		diffName := strings.Replace(diffPath, oldShaPlaceholder, oldSha, -1)
		emptyDir(filepath.Dir(diffName))
		log.Printf("Writing diff to %q.", diffName)
		os.MkdirAll(filepath.Dir(diffName), 0755)
		diff, err := os.Create(diffName)
		if err != nil {
			return errgo.Notef(err, "create %q", diffName)
		}
		if err := binarydist.Diff(old, current, diff); err != nil {
			return errgo.Notef(err, "calculate binary diffs and write into %q", diff.Name())
		}
		if err := diff.Close(); err != nil {
			return errgo.Notef(err, "close %q", diff.Name())
		}
		oldRaw.Close()
	}
	return nil
}

func printUsage() {
	fmt.Println(`
Positional arguments:
	Single platform: go-selfupdate myapp
	Cross platform: go-selfupdate /tmp/mybinares/`)
}

func emptyDir(path string) error {
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return errgo.Notef(err, "read dir %q", path)
	}
	for _, fi := range files {
		if fi.IsDir() {
			continue
		}
		fn := filepath.Join(path, fi.Name())
		log.Printf("Deleting %q.", fn)
		os.Remove(fn)
	}
	return nil
}
