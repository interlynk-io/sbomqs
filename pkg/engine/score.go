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
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/interlynk-io/sbomqs/pkg/source"
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

func handlePaths(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.handlePaths()")

	var docs []sbom.Document
	var paths []string
	var scores []scorer.Scores

	for _, path := range ep.Path {
		if source.IsGit(path) {
			fmt.Println("Yes, it's a git url: ", path)

			fs := memfs.New()

			gitURL, err := url.Parse(path)
			if err != nil {
				log.Fatalf("err:%v ", err)
			}
			fmt.Println("parse gitURL: ", gitURL)

			pathElems := strings.Split(gitURL.Path[1:], "/")
			if len(pathElems) <= 1 {
				log.Fatalf("invalid URL path %s - expected https://github.com/:owner/:repository/:branch (without --git-branch flag) OR https://github.com/:owner/:repository/:directory (with --git-branch flag)", gitURL.Path)
			}

			fmt.Println("pathElems: ", pathElems)
			fmt.Println("Before gitURL.Path: ", gitURL.Path)

			var gitBranch string

			if strings.Contains(strings.Join(pathElems, " "), "main") {
				gitBranch = "main"
			} else if strings.Contains(strings.Join(pathElems, " "), "master") {
				gitBranch = "master"
			} else {
				gitBranch = "null"
			}
			fmt.Println("gitBranch: ", gitBranch)

			gitURL.Path = strings.Join([]string{pathElems[0], pathElems[1]}, "/")
			fmt.Println("After gitURL.Path: ", gitURL.Path)

			repoURL := gitURL.String()
			fmt.Println("repoURL: ", repoURL)

			fileOrDirPath := strings.Join(pathElems[4:], "/")
			fmt.Println("lastPathElement: ", fileOrDirPath)

			cloneOptions := &git.CloneOptions{
				URL:           repoURL,
				ReferenceName: plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", gitBranch)),
				Depth:         1,
				Progress:      os.Stdout,
				SingleBranch:  true,
			}

			_, err = git.Clone(memory.NewStorage(), fs, cloneOptions)
			if err != nil {
				log.Fatalf("Failed to clone repository: %s", err)
			}

			var baths []string
			if baths, err = source.ProcessPath(fs, fileOrDirPath); err != nil {
				log.Fatalf("Error processing path: %v", err)
			}
			fmt.Println("baths: ", paths)

			for _, p := range baths {
				fmt.Println("File Path:", p)

				doc, scs, err := processFile(ctx, ep, p, fs)
				if err != nil {
					continue
				}
				fmt.Println("scs.AvgScore: ", scs.AvgScore())

				docs = append(docs, doc)
				scores = append(scores, scs)
				paths = append(paths, p)
				fmt.Println("PATHS: ", paths)
			}

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
	fmt.Println("Outside for loop and git condition")

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
	fmt.Println("Inside processFile function")
	defer fmt.Println("Exit processFile function")
	log := logger.FromContext(ctx)
	log.Debugf("Processing file :%s\n", path)
	var doc sbom.Document

	if fs != nil {
		fmt.Println("Yes fs contains files")
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
