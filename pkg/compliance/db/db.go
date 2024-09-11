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
)

type DB struct {
	keyRecords   map[int][]*Record            // store record as a value of a Map with a key as a "check_key"
	idRecords    map[string][]*Record         // store record as a value of a Map with a key as a "id"
	idKeyRecords map[string]map[int][]*Record // store record as a value of a Map with a key as a "check_key an id"
	allIDs       map[string]struct{}          // Set of all unique ids
}

// newDB initializes and returns a new database instance.
func NewDB() *DB {
	return &DB{
		keyRecords:   make(map[int][]*Record),
		idRecords:    make(map[string][]*Record),
		idKeyRecords: make(map[string]map[int][]*Record),
		allIDs:       make(map[string]struct{}),
	}
}

// addRecord adds a single record to the database
func (d *DB) AddRecord(r *Record) {
	// store record using a key
	d.keyRecords[r.CheckKey] = append(d.keyRecords[r.CheckKey], r)

	// store record using a id
	d.idRecords[r.ID] = append(d.idRecords[r.ID], r)
	if d.idKeyRecords[r.ID] == nil {
		d.idKeyRecords[r.ID] = make(map[int][]*Record)
	}

	// store record using a key and id
	d.idKeyRecords[r.ID][r.CheckKey] = append(d.idKeyRecords[r.ID][r.CheckKey], r)

	d.allIDs[r.ID] = struct{}{}
}

// addRecords adds multiple records to the database
func (d *DB) AddRecords(rs []*Record) {
	for _, r := range rs {
		d.AddRecord(r)
	}
}

// getRecords retrieves records by the given "check_key"
func (d *DB) GetRecords(key int) []*Record {
	return d.keyRecords[key]
}

// getAllIDs retrieves all unique ids in the database
func (d *DB) GetAllIDs() []string {
	ids := make([]string, 0, len(d.allIDs))
	for id := range d.allIDs {
		ids = append(ids, id)
	}
	return ids
}

// getRecordsByID retrieves records by the given "id"
func (d *DB) GetRecordsByID(id string) []*Record {
	return d.idRecords[id]
}

// getRecordsByKeyID retrieves records by the given "check_key" and "id"
func (d *DB) GetRecordsByKeyID(key int, id string) []*Record {
	return d.idKeyRecords[id][key]
}

// dumpAll prints all records, optionally filtered by the given keys
// nolint
func (d *DB) dumpAll(keys []int) {
	for _, records := range d.keyRecords {
		for _, r := range records {
			if len(keys) == 0 {
				fmt.Printf("id: %s, key: %d, value: %s\n", r.ID, r.CheckKey, r.CheckValue)
				continue
			}
			for _, k := range keys {
				if r.CheckKey == k {
					fmt.Printf("id: %s, key: %d, value: %s\n", r.ID, r.CheckKey, r.CheckValue)
				}
			}
		}
	}
}
