package compliance

import (
	"fmt"
	"math/rand"
	"testing"
)

const (
	numRecords = 1000000 // Number of records to test with
)

// Generate large data set
func generateRecords(n int) []*record {
	var records []*record
	for i := 0; i < n; i++ {
		records = append(records, &record{
			checkKey:   rand.Intn(1000), // #nosec
			checkValue: fmt.Sprintf("value_%d", i),
			id:         fmt.Sprintf("id_%d", rand.Intn(1000)), // #nosec
			score:      rand.Float64() * 100,                  // #nosec
			required:   rand.Intn(2) == 0,                     // #nosec
		})
	}
	return records
}

// Benchmark original db implementation
func BenchmarkOriginalDB(b *testing.B) {
	records := generateRecords(numRecords)
	db := newDB()

	// Benchmark insertion
	b.Run("Insert", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.addRecords(records)
		}
	})

	// Benchmark retrieval by key
	b.Run("GetByKey", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.getRecords(rand.Intn(1000)) // #nosec
		}
	})

	// Benchmark retrieval by ID
	b.Run("GetByID", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.getRecordsByID(fmt.Sprintf("id_%d", rand.Intn(1000))) // #nosec
		}
	})

	// Benchmark for combined retrieval by key and ID case
	b.Run("GetByKeyAndIDTogether", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			key := rand.Intn(1000)                      // #nosec
			id := fmt.Sprintf("id_%d", rand.Intn(1000)) // #nosec
			db.getRecordsByKeyID(key, id)
		}
	})

	// Benchmark for retrieval of all IDs case
	b.Run("GetAllIDs", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			db.getAllIDs()
		}
	})
}
