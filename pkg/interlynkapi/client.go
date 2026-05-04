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

	log.Debug("Marshaling API request body",
		zap.Int("component_count", len(comps)),
	)
	body, err := json.Marshal(DoctorRequest{Components: comps})
	if err != nil {
		log.Debug("Failed to marshal request body",
			zap.Error(err),
		)
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := c.baseURL + endpoint
	log.Debug("Prepared HTTP POST request",
		zap.String("method", "POST"),
		zap.String("endpoint", endpoint),
		zap.String("full_url", url),
		zap.Int("request_body_size", len(body)),
		zap.Int("components_in_batch", len(comps)),
	)

	for attempt := 0; attempt < maxRetries; attempt++ {
		log.Debug("Sending HTTP request",
			zap.Int("attempt", attempt+1),
			zap.Int("max_retries", maxRetries),
		)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			log.Debug("Failed to create HTTP request",
				zap.Error(err),
			)
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if c.apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+c.apiKey)
			log.Debug("Using authenticated API access",
				zap.String("auth_type", "Bearer"),
			)
		} else {
			log.Debug("Using unauthenticated API access")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			log.Debug("HTTP request failed",
				zap.Error(err),
			)
			return nil, fmt.Errorf("API request failed: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			wait := parseRetryAfter(ctx, resp.Header.Get("Retry-After"))
			log.Warn("Component quality API rate limited (HTTP 429), will retry",
				zap.Duration("wait_duration", wait),
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", maxRetries),
			)
			resp.Body.Close()

			select {
			case <-ctx.Done():
				log.Debug("Context cancelled during rate limit wait")
				return nil, ctx.Err()
			case <-time.After(wait):
				log.Debug("Retrying after rate limit wait")
			}
			continue
		}

		log.Debug("Reading response body",
			zap.Int("status_code", resp.StatusCode),
		)
		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			log.Debug("Failed to read response body",
				zap.Error(readErr),
			)
			return nil, fmt.Errorf("read response body: %w", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			log.Debug("API returned non-OK status",
				zap.Int("status_code", resp.StatusCode),
				zap.String("response_body", strings.TrimSpace(string(respBody))),
			)
			return nil, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}

		log.Debug("Successfully received API response",
			zap.Int("status_code", resp.StatusCode),
			zap.Int("response_size_bytes", len(respBody)),
		)

		log.Debug("Unmarshaling API response")
		var dr DoctorResponse
		if err := json.Unmarshal(respBody, &dr); err != nil {
			log.Debug("Failed to unmarshal response",
				zap.Error(err),
			)
			return nil, fmt.Errorf("unmarshal response: %w", err)
		}

		log.Debug("Successfully parsed API response",
			zap.Int("findings_count", len(dr.Findings)),
			zap.Int("total_in_summary", dr.Summary.Total),
			zap.Int("components_checked", dr.Summary.ComponentsChecked),
			zap.String("tier", dr.Tier),
			zap.Int("checks_run_count", len(dr.ChecksRun)),
		)
		return &dr, nil
	}

	log.Debug("Exhausted all retries due to rate limiting")
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

	log.Info("Starting component quality assessment via Interlynk API",
		zap.String("url", c.baseURL),
		zap.Int("total_components", len(comps)),
		zap.Int("batch_size", c.batchSize()),
		zap.Bool("authenticated", c.apiKey != ""),
	)

	if len(comps) == 0 {
		log.Debug("No components to assess, returning empty result")
		return &ComponentQualityResult{FindingsByCompIndex: map[int][]Finding{}}, nil
	}

	log.Debug("Building component payloads from SBOM components",
		zap.Int("component_count", len(comps)),
	)
	payloads := buildPayloads(ctx, comps)

	log.Debug("Sending payloads to API in batches",
		zap.Int("payload_count", len(payloads)),
	)

	batchsResult, err := c.sendInBatches(ctx, payloads)
	if err != nil {
		log.Debug("Failed to send batches to API",
			zap.Error(err),
		)
		return nil, err
	}

	log.Debug("Merging batch responses into final result",
		zap.Int("batch_count", len(batchsResult)),
		zap.Int("total_components", len(comps)),
	)
	result := mergeFindings(ctx, batchsResult, len(comps))

	log.Info("Component quality assessment complete",
		zap.Int("components", result.TotalComponents),
		zap.String("tier", result.Tier),
		zap.Int("total_findings", countFindings(ctx, result)),
		zap.Int("components_with_findings", len(result.FindingsByCompIndex)),
	)

	return result, nil
}

// sendInBatches slices payloads into chunks of batchSize and calls post for
// each chunk. It returns one batchResult per chunk, each carrying the chunk's
// starting offset so that findings can later be re-indexed globally.
func (c *Client) sendInBatches(ctx context.Context, payloads []ComponentPayload) ([]batchResult, error) {
	log := logger.FromContext(ctx)

	totalBatches := (len(payloads) + c.batchSize() - 1) / c.batchSize()
	log.Debug("Starting batched API requests",
		zap.Int("total_components", len(payloads)),
		zap.Int("batch_size", c.batchSize()),
		zap.Int("expected_batches", totalBatches),
	)

	size := c.batchSize()
	var batchesResult []batchResult

	for start := 0; start < len(payloads); start += size {
		end := start + size
		if end > len(payloads) {
			end = len(payloads)
		}
		chunk := payloads[start:end]

		log.Debug("Processing batch",
			zap.Int("batch_num", len(batchesResult)+1),
			zap.Int("batch_start_idx", start),
			zap.Int("batch_end_idx", end-1),
			zap.Int("batch_size", len(chunk)),
		)

		dr, err := c.post(ctx, chunk)
		if err != nil {
			log.Debug("Batch request failed",
				zap.Int("batch_num", len(batchesResult)+1),
				zap.Int("batch_start_idx", start),
				zap.Error(err),
			)
			return nil, fmt.Errorf("batch [%d:%d]: %w", start, end, err)
		}

		log.Debug("Received batch response",
			zap.Int("batch_num", len(batchesResult)+1),
			zap.Int("findings_in_batch", len(dr.Findings)),
			zap.Int("components_checked", dr.Summary.ComponentsChecked),
			zap.String("tier", dr.Tier),
		)

		batchesResult = append(batchesResult, batchResult{offset: start, response: dr})
	}

	log.Debug("Completed all batch requests",
		zap.Int("total_batches", len(batchesResult)),
		zap.Int("total_components_sent", len(payloads)),
	)

	return batchesResult, nil
}

// mergeFindings stitches all batch responses into a single ComponentQualityResult.
// Each finding's batch-local Index is shifted by the batch's offset to produce
// a globally consistent component index that matches the original component slice.
func mergeFindings(ctx context.Context, batches []batchResult, totalComponents int) *ComponentQualityResult {
	log := logger.FromContext(ctx)

	log.Debug("Starting to merge batch findings",
		zap.Int("batch_count", len(batches)),
		zap.Int("total_components", totalComponents),
	)

	result := &ComponentQualityResult{
		FindingsByCompIndex: make(map[int][]Finding),
		TotalComponents:     totalComponents,
	}

	totalFindings := 0
	for batchNum, b := range batches {
		log.Debug("Processing batch findings",
			zap.Int("batch_num", batchNum+1),
			zap.Int("batch_offset", b.offset),
			zap.Int("findings_in_batch", len(b.response.Findings)),
		)

		for _, f := range b.response.Findings {
			globalIdx := b.offset + f.Index
			result.FindingsByCompIndex[globalIdx] = append(result.FindingsByCompIndex[globalIdx], f)
			totalFindings++
		}
		if b.response.Tier != "" {
			result.Tier = b.response.Tier
			log.Debug("Set result tier from batch response",
				zap.String("tier", b.response.Tier),
			)
		}
	}

	log.Debug("Completed merging findings",
		zap.Int("total_batches_processed", len(batches)),
		zap.Int("total_findings", totalFindings),
		zap.Int("components_with_findings", len(result.FindingsByCompIndex)),
		zap.String("final_tier", result.Tier),
	)

	return result
}

// parseRetryAfter parses the Retry-After header value (seconds integer or HTTP date).
// Falls back to defaultRetryWait on parse failure.
func parseRetryAfter(ctx context.Context, header string) time.Duration {
	log := logger.FromContext(ctx)

	log.Debug("Parsing Retry-After header",
		zap.String("header_value", header),
	)

	if header == "" {
		log.Debug("Retry-After header empty, using default wait",
			zap.Duration("default_wait", defaultRetryWait),
		)
		return defaultRetryWait
	}

	if secs, err := strconv.Atoi(strings.TrimSpace(header)); err == nil && secs >= 0 {
		wait := time.Duration(secs) * time.Second
		log.Debug("Parsed Retry-After as seconds",
			zap.Int("seconds", secs),
			zap.Duration("wait_duration", wait),
		)
		return wait
	}

	if t, err := http.ParseTime(header); err == nil {
		if d := time.Until(t); d > 0 {
			log.Debug("Parsed Retry-After as HTTP date",
				zap.Time("retry_time", t),
				zap.Duration("wait_duration", d),
			)
			return d
		}
		log.Debug("Retry-After HTTP date is in the past, using default wait",
			zap.Time("retry_time", t),
			zap.Duration("default_wait", defaultRetryWait),
		)
		return defaultRetryWait
	}

	log.Debug("Failed to parse Retry-After header, using default wait",
		zap.String("header_value", header),
		zap.Duration("default_wait", defaultRetryWait),
	)
	return defaultRetryWait
}

func countFindings(ctx context.Context, r *ComponentQualityResult) int {
	log := logger.FromContext(ctx)

	total := 0
	for _, findings := range r.FindingsByCompIndex {
		total += len(findings)
	}

	log.Debug("Counted total findings across all components",
		zap.Int("components_with_findings", len(r.FindingsByCompIndex)),
		zap.Int("total_findings", total),
	)

	return total
}
