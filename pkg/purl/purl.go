// Copyright 2023 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package purl

import (
	pkg_purl "github.com/package-url/packageurl-go"
)

type PURL string

func NewPURL(prl string) PURL {
	return PURL(prl)
}

func (p PURL) Valid() bool {
	_, err := pkg_purl.FromString(p.String())
	return err == nil
}

func (p PURL) String() string {
	return string(p)
}
