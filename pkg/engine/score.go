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

	"github.com/interlynk-io/sbomqs/pkg/logger"
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
	Oct  bool
}

func ValidateFile(ctx context.Context, filePath string) (*os.File, error) {
	if _, err := os.Stat(filePath); err != nil {
		return nil, fmt.Errorf("failed to stat %s", filePath)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s", filePath)
	}
	return f, nil
}

func ProcessScore(ctx context.Context, ep *Params) ([]sbom.Document, []string, []scorer.Scores, error) {
	log := logger.FromContext(ctx)
	log.Debugf("ProcessScore \n")

	var docs []sbom.Document
	var scores []scorer.Scores
	var allPaths []string

	// get all files from path
	getFilesWithPath := HandlePaths(ctx, ep.Path)

	fmt.Println("allFilesWithPath: ", getFilesWithPath)

	// loop all files path to get files
	for _, filesPath := range getFilesWithPath {

		f, err := ValidateFile(ctx, filesPath)
		if err != nil {
			continue
		}
		f.Close()

		// get docs and score for each file
		doc, score, err := GetDocsAndScore(ctx, f, ep)
		if err != nil {
			fmt.Printf("Error: %v for path %s\n", err, filesPath)
			continue
		}

		docs = append(docs, doc)
		scores = append(scores, score)
		allPaths = append(allPaths, filesPath)
	}

	return docs, allPaths, scores, nil
}

func HandlePaths(ctx context.Context, paths []string) []string {
	log := logger.FromContext(ctx)
	log.Debugf("Handling paths: %v\n", paths)

	var allFilesPath []string

	for _, path := range paths {
		log.Debugf("Handling path: %s\n", path)
		err := filepath.Walk(path, func(filePath string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				log.Debugf("filepath.Walk error for path %s: %v\n", filePath, err)
				return nil
			}
			if !fileInfo.IsDir() {
				allFilesPath = append(allFilesPath, filePath)
			}
			return nil
		})
		if err != nil {
			log.Debugf("filepath.Walk encountered an error for path %s: %v\n", path, err)
			continue
		}
	}
	return allFilesPath
}

func GetDocsAndScore(ctx context.Context, f *os.File, ep *Params) (sbom.Document, scorer.Scores, error) {
	log := logger.FromContext(ctx)

	doc, err := sbom.NewSBOMDocument(ctx, f)
	if err != nil {
		return nil, nil, err
	}

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

	score := sr.Score()
	return doc, score, nil
}
