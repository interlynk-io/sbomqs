// Copyright 2026 Interlynk.io
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

package interlynkapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"go.uber.org/zap"
)

const (
	endpoint         = "/api/v1/doctor/check"
	unauthBatchSize  = 50
	authBatchSize    = 5_000
	maxRetries       = 3
	defaultRetryWait = 60 * time.Second
)

// Client is the HTTP client for the Interlynk Component Quality API.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient constructs a new instance of Client.
// apiKey may be empty for unauthenticated tier.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) batchSize() int {
	if c.apiKey != "" {
		return authBatchSize
	}
	return unauthBatchSize
}

// post sends one batch to the API and returns the parsed response.
// On HTTP 429 it reads the Retry-After header and retries up to maxRetries times.
func (c *Client) post(ctx context.Context, comps []ComponentPayload) (*DoctorResponse, error) {
	log := logger.FromContext(ctx)

	body, err := json.Marshal(DoctorRequest{Components: comps})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + endpoint

	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if c.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("API request failed: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			wait := parseRetryAfter(resp.Header.Get("Retry-After"))
			log.Warn("Component quality API rate limited",
				zap.Duration("retry_after", wait),
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", maxRetries),
			)
			resp.Body.Close()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read response body: %w", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}

		var dr DoctorResponse
		if err := json.Unmarshal(respBody, &dr); err != nil {
			return nil, fmt.Errorf("unmarshal response: %w", err)
		}
		return &dr, nil
	}

	return nil, fmt.Errorf("rate limited after %d retries", maxRetries)
}

// FetchComponentQuality maps the document's components to API payloads, sends
// them in batches, and merges the results into a ComponentQualityResult.
// On error it returns nil and the caller should treat Component Quality as N/A.
func (c *Client) FetchComponentQuality(ctx context.Context, comps []sbom.GetComponent) (*ComponentQualityResult, error) {
	log := logger.FromContext(ctx)

	if len(comps) == 0 {
		return &ComponentQualityResult{
			FindingsByCompIndex: map[int][]Finding{},
		}, nil
	}

	payloads := make([]ComponentPayload, len(comps))
	for i, comp := range comps {
		payloads[i] = mapComponent(comp)
	}

	size := c.batchSize()
	result := &ComponentQualityResult{
		FindingsByCompIndex: make(map[int][]Finding),
		TotalComponents:     len(comps),
	}

	for start := 0; start < len(payloads); start += size {
		end := start + size
		if end > len(payloads) {
			end = len(payloads)
		}
		batch := payloads[start:end]

		log.Debug("Sending component quality batch",
			zap.Int("batch_start", start),
			zap.Int("batch_end", end),
			zap.Int("batch_size", len(batch)),
		)

		dr, err := c.post(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("batch [%d:%d]: %w", start, end, err)
		}

		// Adjust Finding.Index by batch offset so indices are globally consistent.
		for _, f := range dr.Findings {
			globalIdx := start + f.Index
			result.FindingsByCompIndex[globalIdx] = append(result.FindingsByCompIndex[globalIdx], f)
		}
		if dr.Tier != "" {
			result.Tier = dr.Tier
		}
	}

	log.Info("Component quality API call complete",
		zap.Int("components", len(comps)),
		zap.String("tier", result.Tier),
		zap.Int("findings", countFindings(result)),
	)

	return result, nil
}

// parseRetryAfter parses the Retry-After header value (seconds integer or HTTP date).
// Falls back to defaultRetryWait on parse failure.
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return defaultRetryWait
	}
	if secs, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(header); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return defaultRetryWait
}

func countFindings(r *ComponentQualityResult) int {
	total := 0
	for _, findings := range r.FindingsByCompIndex {
		total += len(findings)
	}
	return total
}
