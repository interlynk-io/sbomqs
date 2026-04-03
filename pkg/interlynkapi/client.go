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

// batchResult pairs a DoctorResponse with the batch's starting offset in the
// original payload slice. The offset is needed later to convert a finding's
// batch-local Index back into a globally consistent component index.
type batchResult struct {
	offset   int
	response *DoctorResponse
}

// FetchComponentQuality is the top-level entry point for component quality scoring.
// It orchestrates three sequential steps:
//  1. Build API payloads from SBOM components.
//  2. Send those payloads to the Interlynk API in batches.
//  3. Merge all batch responses into a single result.
func (c *Client) FetchComponentQuality(ctx context.Context, comps []sbom.GetComponent) (*ComponentQualityResult, error) {
	log := logger.FromContext(ctx)

	if len(comps) == 0 {
		return &ComponentQualityResult{FindingsByCompIndex: map[int][]Finding{}}, nil
	}

	payloads := buildPayloads(comps)

	batchsResult, err := c.sendInBatches(ctx, payloads)
	if err != nil {
		return nil, err
	}

	result := mergeFindings(batchsResult, len(comps))

	log.Info("Component quality API call complete",
		zap.Int("components", len(comps)),
		zap.String("tier", result.Tier),
		zap.Int("findings", countFindings(result)),
	)

	return result, nil
}

// sendInBatches slices payloads into chunks of batchSize and calls post for
// each chunk. It returns one batchResult per chunk, each carrying the chunk's
// starting offset so that findings can later be re-indexed globally.
func (c *Client) sendInBatches(ctx context.Context, payloads []ComponentPayload) ([]batchResult, error) {
	log := logger.FromContext(ctx)
	size := c.batchSize()
	var batchesResult []batchResult

	for start := 0; start < len(payloads); start += size {
		end := start + size
		if end > len(payloads) {
			end = len(payloads)
		}
		chunk := payloads[start:end]

		log.Debug("Sending component quality batch",
			zap.Int("batch_start", start),
			zap.Int("batch_end", end),
			zap.Int("batch_size", len(chunk)),
		)

		dr, err := c.post(ctx, chunk)
		if err != nil {
			return nil, fmt.Errorf("batch [%d:%d]: %w", start, end, err)
		}

		batchesResult = append(batchesResult, batchResult{offset: start, response: dr})
	}

	return batchesResult, nil
}

// mergeFindings stitches all batch responses into a single ComponentQualityResult.
// Each finding's batch-local Index is shifted by the batch's offset to produce
// a globally consistent component index that matches the original component slice.
func mergeFindings(batches []batchResult, totalComponents int) *ComponentQualityResult {
	result := &ComponentQualityResult{
		FindingsByCompIndex: make(map[int][]Finding),
		TotalComponents:     totalComponents,
	}

	for _, b := range batches {
		for _, f := range b.response.Findings {
			globalIdx := b.offset + f.Index
			result.FindingsByCompIndex[globalIdx] = append(result.FindingsByCompIndex[globalIdx], f)
		}
		if b.response.Tier != "" {
			result.Tier = b.response.Tier
		}
	}

	return result
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
