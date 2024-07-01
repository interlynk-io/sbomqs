package compliance

import (
	"fmt"
	"sync"
)

type db struct {
	mu      sync.RWMutex
	records map[int][]*record            // store record as a value of a Map with a key as a "check_key"
	ids     map[string][]*record         // store record as a value of a Map with a key as a "id"
	keyIds  map[string]map[int][]*record // store record as a value of a Map with a key as a "check_key an id"
	allIds  map[string]struct{}          // Set of all unique ids
}

// newDB initializes and returns a new database instance.
func newDB() *db {
	return &db{
		records: make(map[int][]*record),
		ids:     make(map[string][]*record),
		keyIds:  make(map[string]map[int][]*record),
		allIds:  make(map[string]struct{}),
	}
}

// addRecord adds a single record to the database
func (d *db) addRecord(r *record) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// store record using a key
	d.records[r.check_key] = append(d.records[r.check_key], r)

	// store record using a id
	d.ids[r.id] = append(d.ids[r.id], r)
	if d.keyIds[r.id] == nil {
		d.keyIds[r.id] = make(map[int][]*record)
	}

	// store record using a key and id
	d.keyIds[r.id][r.check_key] = append(d.keyIds[r.id][r.check_key], r)

	d.allIds[r.id] = struct{}{}
}

// addRecords adds multiple records to the database
func (d *db) addRecords(rs []*record) {
	for _, r := range rs {
		d.addRecord(r)
	}
}

// getRecords retrieves records by the given "check_key"
func (d *db) getRecords(key int) []*record {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.records[key]
}

// getAllIds retrieves all unique ids in the database
func (d *db) getAllIds() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	ids := make([]string, 0, len(d.allIds))
	for id := range d.allIds {
		ids = append(ids, id)
	}
	return ids
}

// getRecordsById retrieves records by the given "id"
func (d *db) getRecordsById(id string) []*record {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ids[id]
}

// getRecordsByKeyId retrieves records by the given "check_key" and "id"
func (d *db) getRecordsByKeyId(key int, id string) []*record {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.keyIds[id][key]
}

// dumpAll prints all records, optionally filtered by the given keys
func (d *db) dumpAll(keys []int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, records := range d.records {
		for _, r := range records {
			if len(keys) == 0 {
				fmt.Printf("id: %s, key: %d, value: %s\n", r.id, r.check_key, r.check_value)
				continue
			}
			for _, k := range keys {
				if r.check_key == k {
					fmt.Printf("id: %s, key: %d, value: %s\n", r.id, r.check_key, r.check_value)
				}
			}
		}
	}
}
