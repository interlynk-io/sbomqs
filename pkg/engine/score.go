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
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-billy/v5"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/spf13/afero"
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
	Bsi  bool
	Oct  bool
}

func Run(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.Run()")
	log.Debug(ep)

	if len(ep.Path) <= 0 {
		log.Fatal("path is required")
	}

	return handlePaths(ctx, ep)
}

func handleURL(path string) (string, string, error) {
	u, err := url.Parse(path)
	if err != nil {
		log.Fatalf("Failed to parse urlPath: %v", err)
	}

	parts := strings.Split(u.Path, "/")
	if len(parts) < 5 {
		log.Fatalf("invalid GitHub URL: %v", path)
	}

	if len(parts) < 5 {
		log.Fatalf("invalid GitHub URL: %v", path)
	}
	fmt.Println("Parts: ", parts)

	sbomFilePath := strings.Join(parts[5:], "/")
	fmt.Println("sbomFilePath: ", sbomFilePath)

	rawURL := strings.Replace(path, "github.com", "raw.githubusercontent.com", 1)
	rawURL = strings.Replace(rawURL, "/blob/", "/", 1)
	fmt.Println("rawURL: ", rawURL)

	return sbomFilePath, rawURL, err
}

func IsURL(in string) bool {
	return regexp.MustCompile("^(http|https)://").MatchString(in)
}

func IsGit(in string) bool {
	return regexp.MustCompile("^(http|https)://github.com").MatchString(in)
}

func handlePaths(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.handlePaths()")

	var docs []sbom.Document
	var paths []string
	var scores []scorer.Scores

	for _, path := range ep.Path {
		if IsURL(path) {
			if !IsGit(path) {
				return fmt.Errorf("path is not a git URL: %s", path)
			}
			fmt.Println("It's a GitHub URL: ", path)
			sbomFilePath, rawURL, err := handleURL(path)
			if err != nil {
				log.Fatal("failed to get sbomFilePath, rawURL: %w", err)
			}

			fs := afero.NewMemMapFs()

			file, err := fs.Create(sbomFilePath)
			if err != nil {
				return err
			}

			resp, err := http.Get(rawURL)
			if err != nil {
				log.Fatalf("failed to get data: %v", err)
			}
			defer resp.Body.Close()

			// Ensure the response is OK
			if resp.StatusCode != http.StatusOK {
				log.Fatalf("failed to download file: %s", resp.Status)
			}
			_, err = io.Copy(file, resp.Body)
			if err != nil {
				log.Fatalf("failed to copy in file: %w", err)
			}

			doc, err := sbom.NewSBOMDocument(ctx, file)
			if err != nil {
				log.Fatalf("failed to parse SBOM document: %w", err)
			}

			sr := scorer.NewScorer(ctx, doc)
			score := sr.Score()

			docs = append(docs, doc)
			scores = append(scores, score)
			paths = append(paths, sbomFilePath)
		} else {

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
					doc, scs, err := processFile(ctx, ep, path, nil)
					if err != nil {
						continue
					}
					docs = append(docs, doc)
					scores = append(scores, scs)
					paths = append(paths, path)
				}
				continue
			}

			doc, scs, err := processFile(ctx, ep, path, nil)
			if err != nil {
				continue
			}
			docs = append(docs, doc)
			scores = append(scores, scs)
			paths = append(paths, path)
		}
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

func processFile(ctx context.Context, ep *Params, path string, fs billy.Filesystem) (sbom.Document, scorer.Scores, error) {
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

		doc, err = sbom.NewSBOMDocument(ctx, f)
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

		doc, err = sbom.NewSBOMDocument(ctx, f)
		if err != nil {
			log.Debugf("failed to create sbom document for  :%s\n", path)
			log.Debugf("%s\n", err)
			fmt.Printf("failed to parse %s : %s\n", path, err)
			return nil, nil, err
		}
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

	scores := sr.Score()
	return doc, scores, nil
}
