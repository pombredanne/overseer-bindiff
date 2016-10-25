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
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp"
)

func TestEncryptDecrypt(t *testing.T) {
	var buf bytes.Buffer
	setBits := WithRSABits(512)
	if err := genAndSer(&buf, "test.producer@example.com", "Producer", "overseer-bindiff", "", setBits); err != nil {
		t.Fatal(err)
	}
	if err := genAndSer(&buf, "test.consumer@example.com", "Consumer", "overseer-bindiff", "", setBits); err != nil {
		t.Fatal(err)
	}

	keyring := readKeyring(bytes.NewReader(buf.Bytes()))

	var cipherBuf bytes.Buffer
	wc, err := encrypt(&cipherBuf, "test", time.Now(), keyring)
	if err != nil {
		t.Fatal(err)
	}
	const plaintext = "This is a nice test message."
	if _, err := io.WriteString(wc, plaintext); err != nil {
		t.Error(err)
	}
	if err := wc.Close(); err != nil {
		t.Fatal(err)
	}

	md, err := decrypt(bytes.NewReader(cipherBuf.Bytes()), keyring)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("md: %+v", md)
	var decrBuf bytes.Buffer
	if n, err := io.Copy(&decrBuf, md); err != nil {
		t.Fatal(err)
	} else if n != int64(len(plaintext)) || plaintext != decrBuf.String() {
		t.Errorf("got %q, wanted %q.", decrBuf.String(), plaintext)
	}
}

func readKeyring(r io.Reader) openpgp.EntityList {
	var keyring openpgp.EntityList
	for {
		el, err := openpgp.ReadArmoredKeyRing(r)
		if err != nil {
			if len(keyring) == 0 {
				panic(err)
			}
			break
		}
		keyring = append(keyring, el...)
	}
	return keyring
}
