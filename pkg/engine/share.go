// Copyright 2023 Interlynk.io
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

package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/interlynk-io/sbomqs/pkg/share"
)

func ShareRun(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.ShareRun()")

	if len(ep.Path) <= 0 {
		log.Fatal("path is required")
	}
	file, _, err := retrieveFiles(ctx, []string{ep.Path[0]})
	if err != nil {
		return err
	}

	doc, err := getSbom(ctx, file[0], sbom.NewSBOMDocument)
	if err != nil {
		return err
	}
	sr := getScore(ctx, doc, ep)

	url, err := share.Share(ctx, doc, sr, ep.Path[0])
	if err != nil {
		fmt.Printf("Error sharing file %s: %s", ep.Path, err)
		return err
	}
	nr := reporter.NewReport(ctx,
		[]sbom.Document{doc},
		[]scorer.Scores{sr},
		[]string{ep.Path[0]},
		reporter.WithFormat(strings.ToLower("basic")))
	nr.Report()
	fmt.Printf("ShareLink: %s\n", url)

	return nil
}
