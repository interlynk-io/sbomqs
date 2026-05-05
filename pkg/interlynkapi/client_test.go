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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const second = time.Second

// makeFakeComponents returns n minimal sbom.Component values (name + version)
// that satisfy sbom.GetComponent without requiring a real parsed SBOM.
func makeFakeComponents(n int) []sbom.GetComponent {
	comps := make([]sbom.GetComponent, n)
	for i := range comps {
		c := sbom.NewComponent()
		c.Name = fmt.Sprintf("comp-%d", i)
		c.Version = "1.0.0"
		comps[i] = c
	}
	return comps
}

// happyResponse is a minimal valid API response used across tests.
var happyResponse = DoctorResponse{
	Findings: []Finding{
		{Index: ptrInt(0), CheckCode: "IDT-PURL-001", Domain: "identifier", Severity: "high", Message: "PURL not resolvable"},
		{Index: ptrInt(2), CheckCode: "IDT-CPE-001", Domain: "identifier", Severity: "medium", Message: "CPE not in NVD"},
	},
	Summary: Summary{
		Total:             2,
		ComponentsChecked: 3,
	},
	Tier:      "unauthenticated",
	ChecksRun: []string{"IDT-PURL-001", "IDT-CPE-001"},
}

// serveJSON is a test helper that returns a fixed JSON body and status code.
func serveJSON(t *testing.T, status int, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
}

// ptrInt returns a pointer to an int (helper for test literals)
func ptrInt(i int) *int {
	return &i
}

// --- batch size ---

func TestBatchSize_Unauthenticated(t *testing.T) {
	c := NewClient("http://example.com", "")
	assert.Equal(t, unauthBatchSize, c.batchSize())
}

func TestBatchSize_Authenticated(t *testing.T) {
	c := NewClient("http://example.com", "secret")
	assert.Equal(t, authBatchSize, c.batchSize())
}

// --- happy path: POST succeeds, findings merged correctly ---

func TestFetchComponentQuality_HappyPath(t *testing.T) {
	srv := serveJSON(t, http.StatusOK, happyResponse)
	defer srv.Close()

	ctx := context.Background()
	client := NewClient(srv.URL, "")

	comps := makeFakeComponents(3)
	result, err := client.FetchComponentQuality(ctx, comps)

	require.NoError(t, err)
	assert.Equal(t, 3, result.TotalComponents)
	assert.Equal(t, "unauthenticated", result.Tier)

	// Component at index 0 should have the PURL finding
	require.Len(t, result.FindingsByCompIndex[0], 1)
	assert.Equal(t, "IDT-PURL-001", result.FindingsByCompIndex[0][0].CheckCode)

	// Component at index 2 should have the CPE finding
	require.Len(t, result.FindingsByCompIndex[2], 1)
	assert.Equal(t, "IDT-CPE-001", result.FindingsByCompIndex[2][0].CheckCode)

	// Component at index 1 should have no findings
	assert.Empty(t, result.FindingsByCompIndex[1])
}

// --- empty component list: no API call, zero-value result ---
func TestFetchComponentQuality_EmptyComponents(t *testing.T) {
	// Server should never be called; use a closed server to catch accidental calls.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("API should not be called for empty component list")
	}))
	srv.Close()

	ctx := context.Background()
	client := NewClient(srv.URL, "")

	result, err := client.FetchComponentQuality(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, result.TotalComponents)
	assert.Empty(t, result.FindingsByCompIndex)
}

// --- non-200 response: error returned, caller logs warning and continues ---
func TestFetchComponentQuality_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx := context.Background()
	client := NewClient(srv.URL, "")

	_, err := client.FetchComponentQuality(ctx, makeFakeComponents(1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// --- 429 retry: exhausts retries and returns error ---
func TestFetchComponentQuality_RateLimitExhausted(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "0") // immediate retry for test speed
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	ctx := context.Background()
	client := NewClient(srv.URL, "")

	_, err := client.FetchComponentQuality(ctx, makeFakeComponents(1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate limited")
	assert.Equal(t, maxRetries, calls, "should attempt exactly maxRetries times")
}

// --- 429 then success: retries and succeeds on second attempt ---
func TestFetchComponentQuality_RateLimitThenSuccess(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DoctorResponse{Tier: "unauthenticated"})
	}))
	defer srv.Close()

	ctx := context.Background()
	client := NewClient(srv.URL, "")

	result, err := client.FetchComponentQuality(ctx, makeFakeComponents(1))
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.Equal(t, "unauthenticated", result.Tier)
}

// --- auth header: API key is sent as Bearer token ---
func TestFetchComponentQuality_BearerToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DoctorResponse{Tier: "authenticated"})
	}))
	defer srv.Close()

	ctx := context.Background()
	client := NewClient(srv.URL, "my-api-key")

	_, err := client.FetchComponentQuality(ctx, makeFakeComponents(1))
	require.NoError(t, err)
	assert.Equal(t, "Bearer my-api-key", gotAuth)
}

// no auth header when no key
func TestFetchComponentQuality_NoAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DoctorResponse{Tier: "unauthenticated"})
	}))
	defer srv.Close()

	ctx := context.Background()
	client := NewClient(srv.URL, "")

	_, err := client.FetchComponentQuality(ctx, makeFakeComponents(1))
	require.NoError(t, err)
	assert.Empty(t, gotAuth)
}

// --- parseRetryAfter tests: various header formats and edge cases ---
func TestParseRetryAfter(t *testing.T) {
	pastTime := time.Now().UTC().Add(-1 * time.Hour).Format(http.TimeFormat)

	tests := []struct {
		name         string
		header       string
		wantDuration time.Duration
	}{
		{
			name:         "seconds",
			header:       "30",
			wantDuration: 30 * second,
		},
		{
			name:         "empty",
			header:       "",
			wantDuration: defaultRetryWait,
		},
		{
			name:         "invalid",
			header:       "not-a-number",
			wantDuration: defaultRetryWait,
		},
		{
			name:         "http_date_in_past",
			header:       pastTime,
			wantDuration: defaultRetryWait,
		},
		{
			name:         "zero_seconds",
			header:       "0",
			wantDuration: time.Duration(0),
		},
		{
			name:         "negative_seconds",
			header:       "-1",
			wantDuration: defaultRetryWait,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := parseRetryAfterTime(context.Background(), tt.header)
			assert.Equal(t, tt.wantDuration, d)
		})
	}
}
