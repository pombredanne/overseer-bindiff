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

import "golang.org/x/crypto/openpgp"

// HasKeys iff not nil and has decryption keys.
func HasKeys(keyring openpgp.KeyRing) bool {
	return !(keyring == nil || len(keyring.DecryptionKeys()) == 0)
}

// SignerKey returns the key usable for signing from the keyring.
func SignerKey(el openpgp.EntityList) *openpgp.Entity {
	decIds := make([]uint64, 0, len(el))
	for _, k := range el.DecryptionKeys() {
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

		return e
	}
	return nil
}

// PublicKeys returns the public keys from the keyring.
func PublicKeys(keyring openpgp.EntityList) openpgp.EntityList {
	pub := make([]*openpgp.Entity, 0, len(keyring))
	for _, e := range keyring {
		if e.PrimaryKey != nil {
			pub = append(pub, e)
		}
	}
	return pub
}
