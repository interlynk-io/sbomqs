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

package engine

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/reporter"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer"
	"github.com/interlynk-io/sbomqs/v2/pkg/share"
)

func ShareRun(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.ShareRun()")

	if len(ep.Path) == 0 {
		log.Fatal("path is required")
	}

	if ep.Path != nil {
		pathInfo, err := os.Stat(ep.Path[0])
		if err != nil {
			return nil
		}

		if pathInfo.IsDir() {
			// log.Fatal("Sharing directories is not supported. Please provide a file path.")
			return fmt.Errorf("Sharing doesn't support directories. Please provide a file path %s, it's not a file", ep.Path[0])
		}
	}

	doc, scores, err := processFile(ctx, ep, ep.Path[0], nil)
	if err != nil {
		return err
	}

	url, err := share.Share(ctx, doc, scores, ep.Path[0])
	if err != nil {
		fmt.Printf("Error sharing file %s: %s", ep.Path, err)
		return err
	}
	nr := reporter.NewReport(ctx,
		[]sbom.Document{doc},
		[]scorer.Scores{scores},
		[]string{ep.Path[0]},
		reporter.WithFormat(strings.ToLower(common.ReportBasic)))
	nr.Report()
	fmt.Printf("ShareLink: %s\n", url)

	return nil
}
