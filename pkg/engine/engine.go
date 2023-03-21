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
	"github.com/interlynk-io/sbomqs/pkg/share"
	"github.com/samber/lo"
	"gopkg.in/yaml.v2"
)

type Params struct {
	Path string

	Category string
	Features []string

	Json     bool
	Basic    bool
	Detailed bool

	Spdx bool
	Cdx  bool

	Recurse bool

	Debug bool

	ConfigPath string
}

type Record struct {
	Name     string     `yaml:"name" json:"name"`
	Enabled  bool       `yaml:"enabled" json:"enabled"`
	Criteria []criteria `yaml:"criteria" json:"criteria"`
}

type criteria struct {
	Name        string `yaml:"shortName" json:"shortName"`
	Description string `yaml:"description" json:"description"`
	Enabled     bool   `yaml:"enabled" json:"enabled"`
}

type Config struct {
	Record []Record `yaml:"category" json:"category"`
}

func ShareRun(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.ShareRun()")

	if ep.Path == "" {
		log.Fatal("path is required")
	}

	doc, scores, err := processFile(ctx, ep, nil)
	if err != nil {
		return err
	}

	url, err := share.Share(ctx, doc, scores, ep.Path)

	if err != nil {
		fmt.Printf("Error sharing file %s: %s", ep.Path, err)
		return err
	}
	nr := reporter.NewReport(ctx,
		[]sbom.Document{doc},
		[]scorer.Scores{scores},
		[]string{ep.Path},
		reporter.WithFormat(strings.ToLower("basic")))
	nr.Report()
	fmt.Printf("ShareLink: %s\n", url)

	return nil
}

func Run(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.Run()")

	if ep.Path == "" {
		log.Fatal("path is required")
	}

	var criterias []string
	if ep.Features != nil {
		for _, f := range ep.Features {
			if lo.Contains(scorer.CriteriaArgs, f) {
				criterias = append(criterias, string(scorer.CriteriaArgMap[scorer.CriteriaArg(f)]))
			}
		}
	}

	if ep.ConfigPath != "" {
		err := processConfigFile(ctx, ep.ConfigPath, criterias)
		if err != nil {
			return err
		}

	}

	return handlePath(ctx, ep, criterias)
}

func handlePath(ctx context.Context, ep *Params, criterias []string) error {
	log := logger.FromContext(ctx)
	log.Debugf("processing path: %s\n", ep.Path)
	var err error

	pInfo, err := os.Stat(ep.Path)
	if err != nil {
		return err
	}

	var docs []sbom.Document
	var paths []string
	var scores []scorer.Scores

	if pInfo.IsDir() {
		files, err := os.ReadDir(ep.Path)
		if err != nil {
			log.Debugf("os.ReadDir failed for path:%s\n", ep.Path)
			log.Debugf("%s\n", err)
			return err
		}

		for _, file := range files {
			if file.IsDir() {
				continue
			}
			path := filepath.Join(ep.Path, file.Name())
			doc, scs, err := processFile(ctx, ep, criterias)
			if err != nil {
				continue
			}
			docs = append(docs, doc)
			scores = append(scores, scs)
			paths = append(paths, path)
		}
	} else {
		doc, scs, err := processFile(ctx, ep, criterias)
		if err != nil {
			return err
		}
		docs = append(docs, doc)
		scores = append(scores, scs)
		paths = append(paths, ep.Path)
	}

	reportFormat := "detailed"
	if ep.Basic {
		reportFormat = "basic"
	} else if ep.Json {
		reportFormat = "json"
	}

	nr := reporter.NewReport(ctx,
		docs,
		scores,
		paths,
		reporter.WithFormat(strings.ToLower(reportFormat)))

	nr.Report()

	return nil
}

func processFile(ctx context.Context, ep *Params, criterias []string) (sbom.Document, scorer.Scores, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Processing file :%s\n", ep.Path)

	if _, err := os.Stat(ep.Path); err != nil {
		log.Debugf("os.Stat failed for file :%s\n", ep.Path)
		fmt.Printf("failed to stat %s\n", ep.Path)
		return nil, nil, err
	}

	f, err := os.Open(ep.Path)
	if err != nil {
		log.Debugf("os.Open failed for file :%s\n", ep.Path)
		fmt.Printf("failed to open %s\n", ep.Path)
		return nil, nil, err
	}
	defer f.Close()

	doc, err := sbom.NewSBOMDocument(ctx, f)
	if err != nil {
		log.Debugf("failed to create sbom document for  :%s\n", ep.Path)
		log.Debugf("%s\n", err)
		fmt.Printf("failed to parse %s : %s\n", ep.Path, err)
		return nil, nil, err
	}

	sr := scorer.NewScorer(ctx,
		doc,
		scorer.WithCategory(ep.Category),
		scorer.WithFeature(criterias))

	scores := sr.Score()
	return doc, scores, nil
}

func processConfigFile(ctx context.Context, filePath string, criterias []string) error {
	log := logger.FromContext(ctx)
	cnf := Config{}
	log.Debugf("Processing file :%s\n", filePath)
	if _, err := os.Stat(filePath); err != nil {
		log.Debugf("os.Stat failed for file :%s\n", filePath)
		fmt.Printf("failed to stat %s\n", filePath)
		return err
	}
	f, err := os.ReadFile(filePath)
	if err != nil {
		log.Debugf("os.Open failed for file :%s\n", filePath)
		fmt.Printf("failed to open %s\n", filePath)
		return err
	}
	err = yaml.Unmarshal(f, &cnf)
	if err != nil {
		return err
	}

	for _, r := range cnf.Record {
		if r.Enabled {
			for _, c := range r.Criteria {
				if c.Enabled {
					criterias = append(criterias, c.Description)
				}
			}
		}
	}

	return nil
}
