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

	"github.com/go-git/go-billy/v5"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/sbomqs"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
)

type Params struct {
	Path []string

	Categories []string
	Features   []string

	JSON     bool
	Basic    bool
	Detailed bool
	Pdf      bool

	Spdx bool
	Cdx  bool

	Recurse bool
	Missing bool

	Debug bool
	Show  bool

	ConfigPath string

	Ntia  bool
	Bsi   bool
	BsiV2 bool
	Oct   bool
	Fsct  bool

	Color     bool
	Signature string
	PublicKey string
	Blob      string
}

func Run(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.Run()")
	log.Debug(ep)

	if len(ep.Path) <= 0 {
		log.Fatal("path is required")
	}

	return executeScoring(ctx, ep)
}

func parseSbomqsConfig(ep *Params) sbomqs.Config {
	return sbomqs.Config{
		Categories:      ep.Categories,
		Features:        ep.Features,
		ConfigFile:      ep.ConfigPath,
		SignatureBundle: sbom.Signature{SigValue: ep.Signature, PublicKey: ep.PublicKey, Blob: ep.Blob},
	}
}

func executeScoring(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.executeScoring()")

	// convert ep params to sbomqs.Config
	config := parseSbomqsConfig(ep)

	// results, err := sbomqs.ScoreSBOM(ctx, config, ep.Path)
	// path := ep.Path

	// blob, signature, publicKey, err := common.GetSignatureBundle(ctx, path[0], ep.Signature, ep.PublicKey)
	// if err != nil {
	// 	log.Debugf("common.GetSignatureBundle failed for file :%s\n", path[0])
	// 	fmt.Printf("failed to get signature bundle for %s\n", path[0])
	// 	// return err
	// }

	// // sig := sbom.Signature{}

	// var docs []sbom.Document
	// var paths []string
	// var scores []scorer.Scores

	// // Convert Params to sbomqs.Config
	// config := sbomqs.Config{
	// 	Categories: ep.Categories,
	// 	Features:   ep.Features,
	// 	ConfigFile: ep.ConfigPath,
	// 	// SignatureBundle: sig,
	// }

	// for _, path := range ep.Path {
	// 	if utils.IsURL(path) {
	// 		log.Debugf("Processing Git URL path :%s\n", path)

	// 		url, sbomFilePath := path, path
	// 		var err error

	// 		if utils.IsGit(url) {
	// 			sbomFilePath, url, err = utils.HandleURL(path)
	// 			if err != nil {
	// 				log.Fatal("failed to get sbomFilePath, rawURL: %w", err)
	// 			}
	// 		}

	// 		data, err := utils.DownloadURL(url)
	// 		if err != nil {
	// 			return err
	// 		}

	// 		result, err := sbomqs.ScoreSBOMData(ctx, data, config)
	// 		if err != nil {
	// 			log.Debugf("failed to score SBOM from URL %s: %v\n", url, err)
	// 			return err
	// 		}

	// 		docs = append(docs, result.Document())
	// 		scores = append(scores, result.RawScores())
	// 		paths = append(paths, sbomFilePath)
	// 	} else {
	// 		log.Debugf("Processing path :%s\n", path)
	// 		pathInfo, err := os.Stat(path)
	// 		if err != nil {
	// 			log.Debugf("os.Stat failed for path:%s\n", path)
	// 			log.Infof("%s\n", err)
	// 			continue
	// 		}

	// 		if pathInfo.IsDir() {
	// 			files, err := os.ReadDir(path)
	// 			if err != nil {
	// 				log.Debugf("os.ReadDir failed for path:%s\n", path)
	// 				log.Debugf("%s\n", err)
	// 				continue
	// 			}
	// 			for _, file := range files {
	// 				log.Debugf("Processing file :%s\n", file.Name())
	// 				if file.IsDir() {
	// 					continue
	// 				}
	// 				path := filepath.Join(path, file.Name())
	// 				result, err := sbomqs.Score(ctx, path, config)
	// 				if err != nil {
	// 					log.Debugf("failed to score file %s: %v\n", path, err)
	// 					continue
	// 				}
	// 				docs = append(docs, result.Document())
	// 				scores = append(scores, result.RawScores())
	// 				paths = append(paths, path)
	// 			}
	// 			continue
	// 		}

	// 		result, err := sbomqs.Score(ctx, path, config)
	// 		if err != nil {
	// 			log.Debugf("failed to score file %s: %v\n", path, err)
	// 			continue
	// 		}
	// 		docs = append(docs, result.Document())
	// 		scores = append(scores, result.RawScores())
	// 		paths = append(paths, path)
	// 	}
	// }

	reportFormat := "detailed"
	if ep.Basic {
		reportFormat = "basic"
	} else if ep.JSON {
		reportFormat = "json"
	}
	coloredOutput := ep.Color

	results, err := sbomqs.ScoreSBOM(ctx, config, ep.Path)
	if err != nil {
		log.Fatalf("failed to score SBOMs: %v", err)
	}

	docs, scores, paths := ConvertScoreResults(ctx, results)

	nr := reporter.NewReport(ctx,
		docs,
		scores,
		paths,
		reporter.WithFormat(strings.ToLower(reportFormat)), reporter.WithColor(coloredOutput))

	nr.Report()

	return nil
}

func ConvertScoreResults(ctx context.Context, results []sbomqs.ScoreResult) (docs []sbom.Document, scores []scorer.Scores, paths []string) {
	log := logger.FromContext(ctx)
	log.Debug("Converting ScoreResults to Documents, Scores, and Paths")

	for _, result := range results {
		doc := result.Document()
		score := result.RawScores()

		docs = append(docs, doc)
		scores = append(scores, score)
		paths = append(paths, result.FileName)
	}

	return docs, scores, paths
}

func processFile(ctx context.Context, ep *Params, path string, fs billy.Filesystem, sig sbom.Signature) (sbom.Document, scorer.Scores, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Processing file :%s\n", path)
	var doc sbom.Document

	if fs != nil {
		f, err := fs.Open(path)
		if err != nil {
			log.Debugf("os.Open failed for file :%s\n", path)
			fmt.Printf("failed to open %s\n", path)
			return nil, nil, err
		}
		defer f.Close()

		doc, err = sbom.NewSBOMDocument(ctx, f, sig)
		if err != nil {
			log.Debugf("failed to create sbom document for  :%s\n", path)
			log.Debugf("%s\n", err)
			fmt.Printf("failed to parse %s : %s\n", path, err)
			return nil, nil, err
		}
	} else {
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

		doc, err = sbom.NewSBOMDocument(ctx, f, sig)
		if err != nil {
			log.Debugf("failed to create sbom document for  :%s\n", path)
			log.Debugf("%s\n", err)
			fmt.Printf("failed to parse %s : %s\n", path, err)
			return nil, nil, err
		}
	}

	sr := scorer.NewScorer(ctx, doc)

	if len(ep.Features[0]) > 0 && len(ep.Categories[0]) > 0 {
		fmt.Println("Adding mix of features and categories")
		for _, cat := range ep.Categories {
			if len(cat) <= 0 {
				continue
			}
			for _, feat := range ep.Features {
				if len(feat) <= 0 {
					continue
				}
				filter := scorer.Filter{
					Name:     feat,
					Ftype:    scorer.Mix,
					Category: cat,
				}
				sr.AddFilter(filter)
			}
		}
	} else if len(ep.Categories[0]) > 0 {
		for _, category := range ep.Categories {
			if len(category) <= 0 {
				continue
			}
			filter := scorer.Filter{
				Name:  category,
				Ftype: scorer.Category,
			}
			sr.AddFilter(filter)
		}
	} else if len(ep.Features[0]) > 0 {
		for _, feature := range ep.Features {
			if len(feature) <= 0 {
				continue
			}
			filter := scorer.Filter{
				Name:  feature,
				Ftype: scorer.Feature,
			}
			sr.AddFilter(filter)
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
			sr.AddFilter(filter)
		}
	}

	scores := sr.Score()
	return doc, scores, nil
}
