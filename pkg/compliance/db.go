package compliance

import (
	"fmt"

	"github.com/samber/lo"
)

type db struct {
	records []*record
}

func newDB() *db {
	return &db{}
}

func (d *db) addRecord(r *record) {
	d.records = append(d.records, r)
}

func (d *db) addRecords(rs []*record) {
	d.records = append(d.records, rs...)
}

func (d *db) getRecords(key int) []record {
	var rs []record
	for _, r := range d.records {
		if r.check_key == key {
			rs = append(rs, *r)
		}
	}
	return rs
}

func (d *db) getAllIds() []string {
	var ids []string
	for _, r := range d.records {
		ids = append(ids, r.id)
	}

	return lo.Uniq(ids)
}

func (d *db) getRecordsById(id string) []record {
	var rs []record
	for _, r := range d.records {
		if r.id == id {
			rs = append(rs, *r)
		}
	}
	return rs
}

func (d *db) getRecordsByKeyId(key int, id string) []record {
	var rs []record
	for _, r := range d.records {
		if r.check_key == key && r.id == id {
			rs = append(rs, *r)
		}
	}
	return rs
}

func (d *db) dumpAll(key []int) {
	for _, r := range d.records {
		if len(key) == 0 {
			fmt.Printf("id: %s, key: %d, value: %s\n", r.id, r.check_key, r.check_value)
			continue
		}
		for _, k := range key {
			if r.check_key == k {
				fmt.Printf("id: %s, key: %d, value: %s\n", r.id, r.check_key, r.check_value)
			}
		}
	}
}
