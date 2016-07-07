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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/kr/binarydist"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/tgulacsi/overseer-bindiff/fetcher"
)

const DefaultRSABits = 1024

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
	cmdMain := &cobra.Command{
		Use: "main",
	}

	var infoPath, diffPath, binPath string
	cmdGenerate := &cobra.Command{
		Use: "generate",
		Run: func(_ *cobra.Command, args []string) {
			appPath := os.Args[0]
			if !filepath.IsAbs(appPath) {
				if filepath.Base(appPath) == appPath { // search PATH
					var err error
					if appPath, err = exec.LookPath(appPath); err != nil {
						log.Fatal(err)
					}
				} else {
					wd, err := os.Getwd()
					if err != nil {
						log.Fatal(err)
					}
					appPath = filepath.Clean(filepath.Join(wd, appPath))
				}
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
					log.Fatal(errors.Wrapf(err, "open %q", appPath))
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
				log.Fatal(errors.Wrapf(err, "read dir %q", appPath))
			}
			for _, file := range files {
				fn := filepath.Join(appPath, file.Name())
				src, err := os.Open(fn)
				if err != nil {
					log.Println(errors.Wrapf(err, "open %q", fn))
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
		},
	}
	F := cmdGenerate.Flags()
	F.StringVar(&goos, "os", goos,
		"Target OS. Defaults to running os or the environment variable GOOS.")
	F.StringVar(&goarch, "arch", goarch,
		"Target ARCH. Defaults to running arch or the environment variable GOARCH.")
	F.StringVar(&infoPath, "info", fetcher.DefaultInfoPath, "info path template")
	F.StringVar(&diffPath, "diff", fetcher.DefaultDiffPath, "diff path template")
	F.StringVar(&binPath, "bin", fetcher.DefaultBinPath, "binary path template")
	cmdMain.AddCommand(cmdGenerate)

	{
		var out string
		cmdGenKeys := &cobra.Command{
			Use: "genkeys",
			Run: func(_ *cobra.Command, args []string) {
				if len(args) < 2 {
					fmt.Fprintf(os.Stderr, "Publisher and consumer email addresses is a must!\n")
					os.Exit(1)
				}
				w := io.WriteCloser(os.Stdout)
				if !(out == "" || out == "-") {
					var err error
					if w, err = os.Create(out); err != nil {
						log.Fatal(err)
					}
				}
				defer func() {
					if err := w.Close(); err != nil {
						log.Fatal(err)
					}
				}()
				if err := genAndSer(w, args[0], "Publisher", "overseer-bindiff", ""); err != nil {
					log.Fatal(err)
				}
				if err := genAndSer(w, args[1], "Consumer", "overseer-bindiff", ""); err != nil {
					log.Fatal(err)
				}
			},
		}
		cmdGenKeys.Flags().StringVarP(&out, "output", "o", "-", "output file name")
		cmdMain.AddCommand(cmdGenKeys)
	}

	cmdPrintKeys := &cobra.Command{
		Use:     "printkeys",
		Aliases: []string{"printkey", "key"},
		Run: func(_ *cobra.Command, args []string) {
			r := io.ReadCloser(os.Stdin)
			if len(args) > 0 && args[0] != "" && args[0] != "-" {
				var err error
				r, err = os.Open(args[0])
				if err != nil {
					log.Fatal(err)
				}
			}
			defer r.Close()
			el, err := openpgp.ReadArmoredKeyRing(r)
			if err != nil {
				log.Fatal(err)
			}
			decIds := make([]uint64, 0, 1)
			for _, k := range el.DecryptionKeys() {
				if err := serialize(os.Stdout, k.Entity, openpgp.PrivateKeyType); err != nil {
					log.Fatal(err)
				}
				decIds = append(decIds, k.Entity.PrivateKey.KeyId)
			}
			for _, e := range el {
				var seen bool
				for _, id := range decIds {
					if e.PrivateKey.KeyId == id {
						seen = true
						break
					}
					if seen {
						break
					}
				}

				if err := serialize(os.Stdout, e, openpgp.PublicKeyType); err != nil {
					log.Fatal(err)
				}
			}
			os.Stdout.Close()
		},
	}
	cmdMain.AddCommand(cmdPrintKeys)

	if _, _, err := cmdMain.Find(os.Args[1:]); err != nil {
		os.Args = append(append(os.Args[:1], "generate"), os.Args[1:]...)
	}
	cmdMain.Execute()
}

func genAndSer(w io.Writer, nce, defName, defComment, defEmail string) error {
	name, comment, email := splitNCE(nce, "Publisher", "overseer-bindiff", "")
	conf := &packet.Config{RSABits: DefaultRSABits}
	e, err := openpgp.NewEntity(name, comment, email, conf)
	if err != nil {
		return errors.Wrapf(err, "NewEntity(%q, %q, %q)", name, comment, email)
	}
	for _, blockType := range []string{openpgp.PrivateKeyType, openpgp.PublicKeyType} {
		if err := serialize(w, e, blockType); err != nil {
			return err
		}
	}
	return nil
}

func serialize(w io.Writer, e *openpgp.Entity, blockType string) error {
	wc, err := armor.Encode(w, blockType, nil)
	if err != nil {
		return errors.Wrap(err, blockType)
	}
	if blockType == openpgp.PrivateKeyType {
		err = e.SerializePrivate(wc, nil)
	} else {
		err = e.Serialize(wc)
	}
	if closeErr := wc.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return errors.Wrap(err, "SerializePrivate")
	}
	_, err = w.Write([]byte{'\n'})
	return err
}

func splitNCE(nce, defName, defComment, defEmail string) (name, comment, email string) {
	nce = strings.TrimSpace(nce)
	name, comment, email = defName, defComment, defEmail
	if i := strings.LastIndex(nce, "@"); i >= 0 {
		if j := strings.LastIndexAny(nce[:i], "< "); j < 0 {
			return name, comment, nce
		} else {
			email, nce = nce[j+1:], strings.TrimSpace(nce[:j])
		}
	}
	if strings.HasSuffix(nce, ")") {
		if i := strings.LastIndex(nce, "("); i >= 0 {
			comment, nce = nce[i+1:len(nce)-1], strings.TrimSpace(nce[i:])
		}
	}
	name = nce
	if name == "" {
		name = defName
	}
	return name, comment, email
}

func createUpdate(genDir string, tpl fetcher.Templates, src io.ReadSeeker, plat fetcher.Platform) error {
	// generate the sha256 of the binary
	h := fetcher.NewSha()
	if _, err := io.Copy(h, src); err != nil {
		return errors.Wrapf(err, "hash %q", src)
	}
	if _, err := src.Seek(0, 0); err != nil {
		return errors.Wrapf(err, "seek back to the beginning of %q", src)
	}
	newSha := h.Sum(nil)
	info := fetcher.URLInfo{
		Platform: plat,
		NewSha:   fetcher.EncodeSha(newSha),
	}

	// gzip the binary to its destination
	binPath, err := tpl.Execute(tpl.Bin, info)
	if err != nil {
		return errors.Wrapf(err, "execute bin template")
	}
	binPath = filepath.Join(genDir, binPath)
	log.Printf("Writing binary to %q.", binPath)
	os.MkdirAll(filepath.Dir(binPath), 0755)
	fh, err := os.Create(binPath)
	if err != nil {
		return errors.Wrapf(err, "create %q", binPath)
	}
	defer fh.Close()
	w := gzip.NewWriter(fh)
	if _, err := io.Copy(w, src); err != nil {
		return errors.Wrapf(err, "gzip %q into %q", src, fh.Name())
	}
	if err := w.Close(); err != nil {
		return errors.Wrapf(err, "flush gzip into %q", fh.Name())
	}
	if err := fh.Close(); err != nil {
		return errors.Wrapf(err, "close %q", fh.Name())
	}

	// write info.json
	infoPath, err := tpl.Execute(tpl.Info, info)
	if err != nil {
		return errors.Wrapf(err, "execute info template")
	}
	infoPath = filepath.Join(genDir, infoPath)
	log.Printf("Writing info to %q.", infoPath)
	os.MkdirAll(filepath.Dir(infoPath), 0755)
	fh, err = os.Create(infoPath)
	if err != nil {
		return errors.Wrapf(err, "create %q", infoPath)
	}
	defer fh.Close()
	if err := json.NewEncoder(fh).Encode(fetcher.Info{Sha256: newSha}); err != nil {
		return errors.Wrapf(err, "encode %v into %q", newSha, fh.Name())
	}
	if err := fh.Close(); err != nil {
		return errors.Wrapf(err, "close %q", fh.Name())
	}

	info.OldSha = oldShaPlaceholder
	diffPath, err := tpl.Execute(tpl.Diff, info)
	if err != nil {
		return errors.Wrapf(err, "execute diff template")
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
		return errors.Wrapf(err, "read %q", binDir)
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
		return errors.Wrapf(err, "open %q", binPath)
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
			log.Println(errors.Wrapf(err, "open %q", fn))
			continue
		}
		defer oldRaw.Close()

		if _, err = currentRaw.Seek(0, 0); err != nil {
			return errors.Wrapf(err, "seek back to the beginning of %q", currentRaw.Name())
		}
		current, err := gzip.NewReader(currentRaw)
		if err != nil {
			return errors.Wrapf(err, "gzip decode %q", currentRaw.Name())
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
			return errors.Wrapf(err, "create %q", diffName)
		}
		if err := binarydist.Diff(old, current, diff); err != nil {
			return errors.Wrapf(err, "calculate binary diffs and write into %q", diff.Name())
		}
		if err := diff.Close(); err != nil {
			return errors.Wrapf(err, "close %q", diff.Name())
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
		return errors.Wrapf(err, "read dir %q", path)
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
