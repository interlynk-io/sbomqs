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

type Params struct {
	Path []string

	Category string
	Features []string

	Json     bool
	Basic    bool
	Detailed bool
	Pdf      bool

	Spdx bool
	Cdx  bool

	Recurse bool

	Debug bool

	ConfigPath string

	Ntia bool
	Cra  bool
}

func Run(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.Run()")
	log.Debug(ep)

	if len(ep.Path) <= 0 {
		log.Fatal("path is required")
	}

	return generateReport(ctx, ep)
}

func validatePath(path string) error {
	if _, err := os.Stat(path); err != nil {
		fmt.Printf("failed to stat %s\n", path)
		return err
	}

	return nil
}

// retrieveFiles: retrieve all files from provided path
func retrieveFiles(ctx context.Context, paths []string) ([]string, []string, error) {
	var allFiles []string
	var allPaths []string
	log := logger.FromContext(ctx)
	log.Debug("engine.retrieveFiles()")

	for _, path := range paths {
		allPaths = append(allPaths, path)
		err := validatePath(path)
		if err != nil {
			log.Debugf("Path validation failed for %s: %v", path, err)
			return allFiles, allPaths, err
		}
		log.Debugf("Processing path :%s\n", path)

		pathInfo, err := os.Stat(path)
		if err != nil {
			return allFiles, allPaths, err
		}

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
				filePath := filepath.Join(path, file.Name())
				allFiles = append(allFiles, filePath)
			}
		}
		allFiles = append(allFiles, path)

	}
	return allFiles, allPaths, nil
}

func generateReport(ctx context.Context, ep *Params) error {
	var docs []sbom.Document
	var scores []scorer.Scores

	files, paths, err := retrieveFiles(ctx, ep.Path)
	if err != nil {
		return err
	}

	for _, file := range files {
		doc, err := getSbom(ctx, file)
		if err != nil {
			continue
		}
		sr := getScore(ctx, doc, ep)
		docs = append(docs, doc)
		scores = append(scores, sr)
	}

	gr := getReport(ctx, ep, docs, scores, paths)
	gr.Report()

	return nil
}

func getReport(ctx context.Context, ep *Params, docs []sbom.Document, scores []scorer.Scores, paths []string) *reporter.Reporter {
	reportFormat := "detailed"
	if ep.Basic {
		reportFormat = "basic"
	} else if ep.Json {
		reportFormat = "json"
	}

	return reporter.NewReport(ctx, docs, scores, paths, reporter.WithFormat(strings.ToLower(reportFormat)))
}

func getSbom(ctx context.Context, file string) (sbom.Document, error) {
	log := logger.FromContext(ctx)
	log.Debugf("getSbom :%s\n", file)

	f, err := os.Open(file)
	if err != nil {
		log.Debugf("os.Open failed for file :%s\n", file)
		fmt.Printf("failed to open %s\n", file)
		return nil, err
	}
	defer f.Close()

	doc, err := sbom.NewSBOMDocument(ctx, f)
	if err != nil {
		log.Debugf("failed to create sbom document for  :%s\n", file)
		log.Debugf("%s\n", err)
		fmt.Printf("failed to parse %s : %s\n", file, err)
		return nil, err
	}

	return doc, err
}

func getScore(ctx context.Context, doc sbom.Document, ep *Params) scorer.Scores {
	log := logger.FromContext(ctx)
	log.Debugf("getScore")

	sr := scorer.NewScorer(ctx, doc)

	if ep.Category != "" {
		sr.AddFilter(ep.Category, scorer.Category)
	}

	if len(ep.Features) > 0 {
		for _, feature := range ep.Features {
			if len(feature) <= 0 {
				continue
			}
			sr.AddFilter(feature, scorer.Feature)
		}
	}

	if ep.ConfigPath != "" {
		filters, er := scorer.ReadConfigFile(ep.ConfigPath)
		if er != nil {
			log.Fatalf("failed to read config file %s : %s", ep.ConfigPath, er)
		}

		if len(filters) <= 0 {
			log.Fatalf("no enabled filters found in config file %s", ep.ConfigPath)
		}

		for _, filter := range filters {
			sr.AddFilter(filter.Name, filter.Ftype)
		}
	}

	return sr.Score()
}
