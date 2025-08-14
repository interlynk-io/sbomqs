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
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-billy/v5"
	"github.com/interlynk-io/sbomqs/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/pkg/logger"
	"github.com/interlynk-io/sbomqs/pkg/reporter"
	"github.com/interlynk-io/sbomqs/pkg/sbom"
	"github.com/interlynk-io/sbomqs/pkg/scorer"
	"github.com/spf13/afero"
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

	return handlePaths(ctx, ep)
}

func handleURL(path string) (string, string, error) {
	u, err := url.Parse(path)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse urlPath: %w", err)
	}

	parts := strings.Split(u.Path, "/")
	containSlash := strings.HasSuffix(u.Path, "/")
	var sbomFilePath string

	if containSlash {
		if len(parts) < 7 {
			return "", "", fmt.Errorf("invalid GitHub URL: %v", path)
		}
		sbomFilePath = strings.Join(parts[5:len(parts)-1], "/")
	} else {
		if len(parts) < 6 {
			return "", "", fmt.Errorf("invalid GitHub URL: %v", path)
		}
		sbomFilePath = strings.Join(parts[5:], "/")
	}

	rawURL := strings.Replace(path, "github.com", "raw.githubusercontent.com", 1)
	rawURL = strings.Replace(rawURL, "/blob/", "/", 1)

	return sbomFilePath, rawURL, err
}

func IsURL(in string) bool {
	return regexp.MustCompile("^(http|https)://").MatchString(in)
}

func IsGit(in string) bool {
	return regexp.MustCompile("^(http|https)://github.com").MatchString(in)
}

func ProcessURL(url string, file afero.File) (afero.File, error) {
	//nolint: gosec
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}
	defer resp.Body.Close()

	// Ensure the response is OK
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download file: %s", resp.Status)
	}
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to copy in file: %w", err)
	}

	// Check if the file is empty
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	if info.Size() == 0 {
		return nil, fmt.Errorf("downloaded file is empty: %v", info.Size())
	}

	return file, err
}

func handlePaths(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("engine.handlePaths()")

	var docs []sbom.Document
	var paths []string
	var scores []scorer.Scores

	for _, path := range ep.Path {
		if IsURL(path) {
			log.Debugf("Processing Git URL path :%s\n", path)

			url, sbomFilePath := path, path
			var err error

			if IsGit(url) {
				sbomFilePath, url, err = handleURL(path)
				if err != nil {
					log.Fatal("failed to get sbomFilePath, rawURL: %w", err)
				}
			}
			fs := afero.NewMemMapFs()

			file, err := fs.Create(sbomFilePath)
			if err != nil {
				return err
			}

			f, err := ProcessURL(url, file)
			if err != nil {
				return err
			}

			blob, signature, publicKey, err := common.GetSignatureBundle(ctx, path, ep.Signature, ep.PublicKey)
			if err != nil {
				log.Debugf("common.GetSignatureBundle failed for file :%s\n", path)
				fmt.Printf("failed to get signature bundle for %s\n", path)
				return err
			}

			sig := sbom.Signature{
				SigValue:  signature,
				PublicKey: publicKey,
				Blob:      blob,
			}

			doc, err := sbom.NewSBOMDocument(ctx, f, sig)
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
			pathInfo, err := os.Stat(path)
			if err != nil {
				log.Debugf("os.Stat failed for path:%s\n", path)
				log.Infof("%s\n", err)
				continue
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
	} else if ep.JSON {
		reportFormat = "json"
	}
	coloredOutput := ep.Color

	nr := reporter.NewReport(ctx,
		docs,
		scores,
		paths,
		reporter.WithFormat(strings.ToLower(reportFormat)), reporter.WithColor(coloredOutput))

	nr.Report()

	return nil
}

func processFile(ctx context.Context, ep *Params, path string, fs billy.Filesystem) (sbom.Document, scorer.Scores, error) {
	log := logger.FromContext(ctx)
	log.Debugf("Processing file :%s\n", path)
	var doc sbom.Document

	blob, signature, publicKey, err := common.GetSignatureBundle(ctx, path, ep.Signature, ep.PublicKey)
	if err != nil {
		log.Debugf("common.GetSignatureBundle failed for file :%s\n", path)
		fmt.Printf("failed to get signature bundle for %s\n", path)
		return nil, nil, err
	}

	sig := sbom.Signature{
		SigValue:  signature,
		PublicKey: publicKey,
		Blob:      blob,
	}

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

	if len(ep.Categories) > 0 {
		if len(ep.Features) == 0 {
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
		} else if len(ep.Features) > 0 {
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
		}
	} else if len(ep.Features) > 0 {
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
