// Copyright 2023 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package share

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
)

func Share(ctx context.Context, doc sbom.Document, scores scorer.Scores, sbomFileName string) (string, error) {
	nr := reporter.NewReport(ctx,
		[]sbom.Document{doc},
		[]scorer.Scores{scores},
		[]string{sbomFileName},
		reporter.WithFormat(strings.ToLower("json")))

	js, err := nr.ShareReport()

	if err != nil {
		return "", err
	}

	return sentToBenchmark(js)
}

type shareResonse struct {
	Url string `json:"url"`
}

func sentToBenchmark(js string) (string, error) {
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Scheme: "https", Host: "sbom-benchmark.fly.dev", Path: "/user/score"},
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: ioutil.NopCloser(strings.NewReader(js)),
	}

	// // Save a copy of this request for debugging.
	///	requestDump, err := httputil.DumpRequest(req, true)
	//	if err != nil {
	//		fmt.Println(err)
	///	}
	//		fmt.Println(string(requestDump))

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("bad response from Benchmark: %s", resp.Status)
	}

	data, _ := ioutil.ReadAll(resp.Body)
	sr := shareResonse{}

	err = json.Unmarshal(data, &sr)
	if err != nil {
		return "", err
	}

	return sr.Url, nil
}
