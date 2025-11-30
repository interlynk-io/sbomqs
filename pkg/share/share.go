// Copyright 2025 Interlynk.io
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
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/reporter"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer"
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
	URL string `json:"url"`
}

func sentToBenchmark(js string) (string, error) {
	log := logger.FromContext(context.Background())
	req := &http.Request{
		Method: "POST",
		URL:    &url.URL{Scheme: "https", Host: "sbombenchmark.dev", Path: "/user/score"},
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(js)),
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warnf("failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("bad response from Benchmark: %s", resp.Status)
	}

	data, _ := io.ReadAll(resp.Body)
	sr := shareResonse{}

	err = json.Unmarshal(data, &sr)
	if err != nil {
		return "", err
	}

	return sr.URL, nil
}
