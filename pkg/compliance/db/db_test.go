// Copyright 2024 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package db

import (
	"fmt"
	"math/rand"
	"testing"
)

const (
	numRecords = 1000000 // Number of records to test with
)

// Generate large data set
func generateRecords(n int) []*Record {
	var records []*Record
	for i := 0; i < n; i++ {
		records = append(records, &Record{
			CheckKey:   rand.Intn(1000), // #nosec
			CheckValue: fmt.Sprintf("value_%d", i),
			ID:         fmt.Sprintf("id_%d", rand.Intn(1000)), // #nosec
			Score:      rand.Float64() * 100,                  // #nosec
			Required:   rand.Intn(2) == 0,                     // #nosec
		})
	}
	return records
}

// Benchmark original db implementation
func BenchmarkOriginalDB(b *testing.B) {
	records := generateRecords(numRecords)
	db := NewDB()

	// Benchmark insertion
	b.Run("Insert", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.AddRecords(records)
		}
	})

	// Benchmark retrieval by key
	b.Run("GetByKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.GetRecords(rand.Intn(1000)) // #nosec
		}
	})

	// Benchmark retrieval by ID
	b.Run("GetByID", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.GetRecordsByID(fmt.Sprintf("id_%d", rand.Intn(1000))) // #nosec
		}
	})

	// Benchmark for combined retrieval by key and ID case
	b.Run("GetByKeyAndIDTogether", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			key := rand.Intn(1000)                      // #nosec
			id := fmt.Sprintf("id_%d", rand.Intn(1000)) // #nosec
			db.GetRecordsByKeyID(key, id)
		}
	})

	// Benchmark for retrieval of all IDs case
	b.Run("GetAllIDs", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.GetAllIDs()
		}
	})
}
