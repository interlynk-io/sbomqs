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
	"os"
	"path/filepath"
	"strings"

	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
)

func RunScvs(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.Run()")
	log.Debug(ep)

	if len(ep.Path) <= 0 {
		log.Fatal("path is required")
	}

	return handleScvsPaths(ctx, ep)
}

func handleScvsPaths(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.handlePaths()")

	var docs []sbom.Document
	var paths []string
	var scores []scorer.ScvsScores

	for _, path := range ep.Path {
		log.Debugf("Processing path :%s\n", path)
		pathInfo, _ := os.Stat(path)
		if pathInfo.IsDir() {
			files, err := os.ReadDir(path)
			if err != nil {
				log.Debugf("os.ReadDir failed for path:%s\n", path)
				log.Debugf("%s\n", err)
				continue
			}
			for _, file := range files {
				log.Debugf("Processing file :%s\n", file.Name())
				if file.IsDir() {
					continue
				}
				path := filepath.Join(path, file.Name())
				doc, scs, err := processScvsFile(ctx, ep, path)
				if err != nil {
					continue
				}
				docs = append(docs, doc)
				scores = append(scores, scs)
				paths = append(paths, path)
			}
			continue
		}

		doc, scs, err := processScvsFile(ctx, ep, path)
		if err != nil {
			continue
		}
		docs = append(docs, doc)
		scores = append(scores, scs)
		paths = append(paths, path)
	}

	reportFormat := "detailed"
	if ep.Basic {
		reportFormat = "basic"
	} else if ep.Json {
		reportFormat = "json"
	}

	nr := reporter.NewScvsReport(ctx,
		docs,
		scores,
		paths,
		reporter.WithFormat(strings.ToLower(reportFormat)))

	fmt.Println("Print the scvs report")
	nr.ScvsReport()

	return nil
}

func processScvsFile(ctx context.Context, ep *Params, path string) (sbom.Document, scorer.ScvsScores, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Processing file :%s\n", path)

	if _, err := os.Stat(path); err != nil {
		log.Debugf("os.Stat failed for file :%s\n", path)
		fmt.Printf("failed to stat %s\n", path)
		return nil, nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		log.Debugf("os.Open failed for file :%s\n", path)
		fmt.Printf("failed to open %s\n", path)
		return nil, nil, err
	}
	defer f.Close()

	doc, err := sbom.NewSBOMDocument(ctx, f)
	if err != nil {
		log.Debugf("failed to create sbom document for  :%s\n", path)
		log.Debugf("%s\n", err)
		fmt.Printf("failed to parse %s : %s\n", path, err)
		return nil, nil, err
	}

	sr := scorer.NewScvsScorer(ctx, doc)

	scores := sr.ScvsScore()
	return doc, scores, nil
}
