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
package cpe

import (
	"regexp"
)

type CPE string

const cpeRegex = (`^([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9\._\-~%]*){0,6})`) +
	(`|(cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^\x60\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^\x60\{\|}~]))+(\?*|\*?))|[\*\-])){4})$`)

func (cpe CPE) Valid() bool {
	return regexp.MustCompile(cpeRegex).MatchString(cpe.String())
}

func NewCPE(cpe string) CPE {
	return CPE(cpe)
}

func (meta CPE) String() string {
	return string(meta)
}
