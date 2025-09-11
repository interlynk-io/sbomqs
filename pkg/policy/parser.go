// Copyright 2025 Interlynk.io
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

package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// parseRuleString parses a rule string like:
//
//	"field=license,values=MIT,Apache-2.0"
//
// It returns a Rule with Field, Values, Patterns populated.
// This implementation finds all "key=" positions first, then treats the
// value for each key as the substring up to the next key= (or end of string).
func parseRuleString(s string) (Rule, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Rule{}, fmt.Errorf("empty rule string")
	}

	// Regex to find keys followed by '='. Key must start with a letter/underscore
	// and contain letters, numbers or underscores (common flag-like identifiers).
	re := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)=`)

	locs := re.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		return Rule{}, fmt.Errorf("no key=value pairs found in rule: %q", s)
	}

	kv := map[string]string{}
	for i, match := range locs {
		// match[0],match[1] = full match start,end (the "key=")
		// match[2],match[3] = group1 (key) start,end
		key := s[match[2]:match[3]]
		valueStart := match[1] // position right after '='
		var valueEnd int
		if i+1 < len(locs) {
			valueEnd = locs[i+1][0] // start of next key=
		} else {
			valueEnd = len(s)
		}
		// Extract the raw value substring and trim spaces and optional leading/trailing commas
		rawVal := strings.TrimSpace(s[valueStart:valueEnd])
		rawVal = strings.Trim(rawVal, ", ") // remove stray commas/spaces
		if rawVal != "" {
			kv[strings.ToLower(key)] = rawVal
		} else {
			kv[strings.ToLower(key)] = ""
		}
	}

	// 'field' is required
	field, ok := kv["field"]
	if !ok || strings.TrimSpace(field) == "" {
		return Rule{}, fmt.Errorf("field is required in rule")
	}

	r := Rule{Field: strings.ToLower(strings.TrimSpace(field))}

	// parse values (comma-separated list inside the value string)
	if v, ok := kv["values"]; ok && v != "" {
		r.Values = splitCommaList(v)
	}

	// parse patterns (comma-separated)
	if p, ok := kv["patterns"]; ok && p != "" {
		r.Patterns = splitCommaList(p)
		// validate regexes early
		for _, pat := range r.Patterns {
			if _, err := regexp.Compile(pat); err != nil {
				return Rule{}, fmt.Errorf("invalid pattern %q: %w", pat, err)
			}
		}
	}

	return r, nil
}

func splitCommaList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
