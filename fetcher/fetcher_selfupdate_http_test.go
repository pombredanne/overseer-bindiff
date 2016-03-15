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

import "testing"

func TestTemplates(t *testing.T) {
	tpl := Templates{}
	if err := tpl.Init("", "", ""); err != nil {
		t.Fatal(err)
	}
	info := URLInfo{
		Platform: Platform{GOOS: "goos", GOARCH: "goarch"},
		OldSha:   "oldsha", NewSha: "newsha", BinaryName: "Binary",
	}
	if s, err := tpl.Execute(tpl.Info, info); err != nil {
		t.Fatal(err)
	} else if await := "goos_goarch.json"; s != await {
		t.Errorf("info got %q, awaited %q.", s, await)
	}

	if s, err := tpl.Execute(tpl.Diff, info); err != nil {
		t.Fatal(err)
	} else if await := "goos_goarch/oldsha/newsha"; s != await {
		t.Errorf("diff got %q, awaited %q.", s, await)
	}

	if s, err := tpl.Execute(tpl.Bin, info); err != nil {
		t.Fatal(err)
	} else if await := "goos_goarch/newsha.gz"; s != await {
		t.Errorf("bin got %q, awaited %q.", s, await)
	}
}
