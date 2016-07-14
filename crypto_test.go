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
	"strings"
	"testing"
	"time"

	"github.com/tgulacsi/overseer-bindiff/fetcher"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func TestEncryptDecrypt(t *testing.T) {
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(testKeyringBlob))
	if err != nil {
		t.Fatal(err)
	}
	var cipherBuf bytes.Buffer
	wc, err := openpgp.Encrypt(
		&cipherBuf, publicKeys(keyring), signerKey(keyring),
		&openpgp.FileHints{IsBinary: true, FileName: "test", ModTime: time.Now()},
		&packet.Config{DefaultCompressionAlgo: 0, RSABits: DefaultRSABits},
	)
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

	md, err := openpgp.ReadMessage(
		bytes.NewReader(cipherBuf.Bytes()),
		keyring, fetcher.KeyPrompt, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("md: %+v", md)
	var decrBuf bytes.Buffer
	if n, err := io.Copy(&decrBuf, md.UnverifiedBody); err != nil {
		t.Fatal(err)
	} else if n != int64(len(plaintext)) || plaintext != decrBuf.String() {
		t.Errorf("got %q, wanted %q.", decrBuf.String(), plaintext)
	}
}

const testKeyringBlob = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=xBxo
-----END PGP PRIVATE KEY BLOCK-----
-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBFd+pgsBEAC1iDbzScTObpKKJLIJSvzEz6GHHxoRSjtC7SwYpLYtvZNPyRzb
SLrQZrfPK/LPbA3khPLmN9Mapb7CfDvbMwe7pkynzTFyOla9If58VhrlGt4Z+QXV
5ru0pqcLwdyo5R7Vkmx94k44/b73iz9nJF+fTmvpmB7Q68Or9cZR6Vfr9lQZ5Xw9
aDWT5tejorbYeBtOwQV1LQ1hiJz7mCTLnjG/unLzaes4IaV1Uz2GewPoD1uhjYZ4
U4g4rqVv5D5+3jmqp9ZSi6JiJ034Gb8tj0+J8r69u4iGaOR4W3B+UIUBL49eXzuN
Ybk2UNh5FXpfqpaz8pfEuzWbT2BuuDU8hbe+ADOebBgg4dFIC8zi/ZQdwnxQekx8
zYXiF/9EHWytGXeNdh4vLuGqQXeaWVvU2vfTLigrqjgk1yKxm+uL3wgVKrTK0+8i
H0viFEysmI/s1+ySoKhENe8B5FvSSfr25LwYxOV79W6PINOmvv0co9mWK4V/OL9D
2jXLC8L8FUX/qKm1FHIEDa6aS3i14Kiau/n9VWvjE0Q7Y9L6SCeh4CthQOmmY3sY
A+9XRDwDFOthSW3RIu99G0ESdSfZrVhcaa9BXVgNU3axzBuNjGN+X7zIyO1/RHzy
xZDc28kqPlpjF06fgZ9K6x+FS5cBteYxfLc7qMKc+cRTmlZL6bybg4FMowARAQAB
zTNQdWJsaXNoZXIgKG92ZXJzZWVyLWJpbmRpZmYpIDxwdWJsaXNoZXJAdW5vc29m
dC5odT7CwWIEEwEIABYFAld+pgsJEHfEwrget3hyAhsDAhkBAACX8RAAJzPjzDwm
RoMwkfHnoPoofXCy/wXfIjqRFMAR7CtXUU3Qgbo+nB/1wtok5Y8EuGi9SM6j4dHW
6Yvc/doPwH0GGgunocDwTGtf1AcRsiENkZIc5ZBhVU/sC9korTwhgt+StEeTh3vo
Ev7241W6DlbKJelGEixq6pQAs+h2XOAwMZuPkq9Tz/ViBzwVWb9V5RqVkn17/5PO
lb7gg37RIbEVsZpOjmsWG1zphSjQ3b4jTr1UhqUgoWVrUdZlNeN7dYPFs9sPRF9B
+XO+3cX98AAyS6igcjAgS0inlR5qNkI9t256EJqebvNrGt6Fk9w0tUf0Jn5UjYHA
K8o1PZFqDb9ZXINEAIpMEBqmJZHeo0fkwwHgnHjp42PH1J2SXMkLxqhVLEZyglGn
MKbH5p/tY5sx67N8BwSemVeNQ5a3mzOApwqDwDZw4SViQSInvZVZQyANroyIsyKg
C+S7IiCaUmFz0UNkYaubZPq/sHAqL0WxLYD7Ij90mIYbEf3he5xEGKk2G3y+7F/2
Bihn/XoiOx0Sgyhu5PMFOen67IpKAPbEkvZGcoNbiXOlrvLCtaN+VPD0xEEzo9Uc
VDKBxXnn1a9VuKUxKhIrrroIzpodISMXwEWd1E++24payrnV/wdvNC0JPQTUGVL8
ezylnyVL14Au1BD6o9anv3FEgbV3qOb5HxLOwU0EV36mCwEQAKmHO8w6XvcnaiVx
0aCVkb5AB7FafcDWBUOqguczip8pabUJTvjpaqvmPlM6LvjoSEkoHqs3x7Bss+OJ
tomlQfB86Sx5ufpU8O9lSLoQSMeO+fqrQ7Q3t5hQ4FdU5piJUthqs43oUgxBbkDn
sLPnaLBN9dm5zBHv723FGpgao5/tQc4OrJjN7dleXm7yp6kSfyqeqLLx+L/1W/eb
/sO+BsgCzwCQkA/7kOxeNsTdbHfebpeF+L0qmIuMvhVunkk32Az7g2MpddIIIGMb
Ci0QHJU6KJr5m+cs3pFs0EQyDc3+8X23fM7K023XmhJv5aAFM4uSIjoIR6+hsB+J
JDjEb6A+rxa6VIkob1Yb28jgznF7Rxcfk1/insGiFdiw09JkIPfPOduTyVELSFSq
Sm6lWXiR1vH8DQjE2gKu52Bhbjiw7noBgBgeMo0YAg3dFqri1xsUAGLMQAkaonKN
lKpBRBcy1cbINDOmT3jx0dPN+AiIY23lPLfOS47M0qRJnKNhOOnbZzGxwPQt9ek0
aU0VTIdCS48M/NRMxvdSsB+sezKp9CN64BA9iD5Nf+buoUoAajz37pv7cboHyktW
3D5i4M7apkNGFjef90rAVLuC+6s4m9mZowGXBJfhpC3Q04hMPXSSJzDoNL/B6a//
EwQqXKZdo57xgH07J+Zojqfc10upABEBAAHCwV8EGAEIABMFAld+pgsJEHfEwrge
t3hyAhsMAABt9hAAksXiVuOqCr1yTTUhu1j2XvbTRBmGZy/pzy/VRBfcB3WV/vnv
S1WW1+EI5IK3Nfztpswvu9tKzOvVNax9p+T9XKFUh2YnxkPg9m6OHicAYUiWtquI
UoWOF/pzwusRgald/oNnIBWE7WdefJ1K2a/h+G1lxW9vLHU779DK+Cw2iWbWL9eV
tNXDR1kM0Hc23iY9xj/LRFjRiO6W3Khm+5n5YAfxQUF0GHsNhHsYS7BgOGlRmDNX
RMINRxpFyVb5ypIMgXY3poQNC7jWruflvsePsqdIPiauKGfO6Nml/7444rdQE2yw
v5J5iRm851eyIX33p/NEKY06JKNt7FCdgLzDYrcQ7Kurde/NFIJW8ZD+QmtmZqBI
g5yHFY1BSbNE6afQ/mRWVCyfjq26PlbPCioOU1cuY1BeDf2HQErpynGn/SCd5bxg
Bcpy9w8Aj/lRS67JQ6IgnsQf0SKv440M7KF17naU0++ybLQg/dlIEETe3bS2+pgS
6i7NN1S2QQYjr+iNx2H9elMwdURMRrj7efc9cdrasteGysfQKcjJanWFPmBH/Hk0
oo99RhH92XDm1bRiXRZZEzahOfnTOQCrCIEAusxSXRJanY/wYE7AR70a9123NUB0
m9ygiOClLy1KjOfROVyJdZ88re0dD/CLQBxB73w34D9JzI/rDWh01oSVll0=
=0069
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=Ri89
-----END PGP PRIVATE KEY BLOCK-----
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=G2Ty
-----END PGP PUBLIC KEY BLOCK-----
`