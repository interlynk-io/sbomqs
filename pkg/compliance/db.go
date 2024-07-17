package compliance

import (
	"fmt"
)

type db struct {
	keyRecords   map[int][]*record            // store record as a value of a Map with a key as a "check_key"
	idRecords    map[string][]*record         // store record as a value of a Map with a key as a "id"
	idKeyRecords map[string]map[int][]*record // store record as a value of a Map with a key as a "check_key an id"
	allIds       map[string]struct{}          // Set of all unique ids
}

// newDB initializes and returns a new database instance.
func newDB() *db {
	return &db{
		keyRecords:   make(map[int][]*record),
		idRecords:    make(map[string][]*record),
		idKeyRecords: make(map[string]map[int][]*record),
		allIds:       make(map[string]struct{}),
	}
}

// addRecord adds a single record to the database
func (d *db) addRecord(r *record) {
	// store record using a key
	d.keyRecords[r.check_key] = append(d.keyRecords[r.check_key], r)

	// store record using a id
	d.idRecords[r.id] = append(d.idRecords[r.id], r)
	if d.idKeyRecords[r.id] == nil {
		d.idKeyRecords[r.id] = make(map[int][]*record)
	}

	// store record using a key and id
	d.idKeyRecords[r.id][r.check_key] = append(d.idKeyRecords[r.id][r.check_key], r)

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
	return d.keyRecords[key]
}

// getAllIds retrieves all unique ids in the database
func (d *db) getAllIds() []string {
	ids := make([]string, 0, len(d.allIds))
	for id := range d.allIds {
		ids = append(ids, id)
	}
	return ids
}

// getRecordsById retrieves records by the given "id"
func (d *db) getRecordsById(id string) []*record {
	return d.idRecords[id]
}

// getRecordsByKeyId retrieves records by the given "check_key" and "id"
func (d *db) getRecordsByKeyId(key int, id string) []*record {
	return d.idKeyRecords[id][key]
}

// dumpAll prints all records, optionally filtered by the given keys
func (d *db) dumpAll(keys []int) {
	for _, records := range d.keyRecords {
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
