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
	pkgcommon "github.com/interlynk-io/sbomqs/v2/pkg/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/compliance/common"
	"github.com/interlynk-io/sbomqs/v2/pkg/logger"
	"github.com/interlynk-io/sbomqs/v2/pkg/reporter"
	v2 "github.com/interlynk-io/sbomqs/v2/pkg/reporter/v2"
	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/api"
	"github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/config"
	score "github.com/interlynk-io/sbomqs/v2/pkg/scorer/v2/score"
	"go.uber.org/zap"

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

	Color bool
	Blob  string

	Legacy   bool
	Profiles []string
}

func Run(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)

	log.Info("Starting scoring run",
		zap.Bool("legacy", ep.Legacy),
		zap.Int("path_count", len(ep.Path)),
	)

	if len(ep.Path) == 0 {
		log.Error("Scoring run failed: no input paths provided")
		return fmt.Errorf("path is required")
	}

	if ep.Legacy {
		log.Info("Using legacy scoring engine",
			zap.Bool("legacy", ep.Legacy),
		)
		return handlePaths(ctx, ep)
	}

	log.Info("Using v2 scoring engine")
	return runV2Score(ctx, ep)
}

// scored runs the v2 scoring engine once and returns the results.
func scored(ctx context.Context, ep *Params) ([]api.Result, error) {
	log := logger.FromContext(ctx)
	log.Info("Executing v2 scoring engine",
		zap.Strings("paths", ep.Path),
		zap.Strings("categories", ep.Categories),
		zap.Strings("features", ep.Features),
		zap.Strings("profiles", ep.Profiles),
	)

	cfg := config.Config{
		Categories: ep.Categories,
		Features:   ep.Features,
		ConfigFile: ep.ConfigPath,
		Profile:    ep.Profiles,
	}

	results, err := score.ScoreSBOM(ctx, cfg, ep.Path)
	if err != nil {
		log.Error("v2 scoring engine failed",
			zap.Error(err),
		)
		return nil, err
	}

	log.Info("v2 scoring engine completed",
		zap.Int("result_count", len(results)),
	)

	return results, nil
}

func renderReport(ctx context.Context, ep *Params, results []api.Result) {
	log := logger.FromContext(ctx)

	reportFormat := pkgcommon.ReportDetailed
	if ep.Basic {
		reportFormat = pkgcommon.ReportBasic
	} else if ep.JSON {
		reportFormat = pkgcommon.FormatJSON
	}

	log.Info("Rendering score report",
		zap.String("format", reportFormat),
		zap.Int("results", len(results)),
		zap.Bool("color", ep.Color),
	)

	nr := v2.NewReport(ctx, results, reportFormat)
	nr.Report()
}

// runV2Score handle v2 scoring and v2 reporting
func runV2Score(ctx context.Context, ep *Params) error {
	log := logger.FromContext(ctx)
	log.Debug("Starting v2 scoring workflow")

	results, err := scored(ctx, ep)
	if err != nil {
		return err
	}

	renderReport(ctx, ep, results)
	log.Info("v2 scoring workflow completed")

	return nil
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
	log := logger.FromContext(context.Background())
	//nolint: gosec
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("Failed to close HTTP response body",
				zap.Error(err),
			)
		}
	}()

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
	log.Info("Starting legacy scoring workflow",
		zap.Strings("paths", ep.Path),
	)

	var docs []sbom.Document
	var paths []string
	var scores []scorer.Scores

	for _, path := range ep.Path {
		log.Info("Processing input path",
			zap.String("path", path),
		)

		if IsURL(path) {
			log.Info("Processing SBOM from URL",
				zap.String("url", path),
			)
			url, sbomFilePath := path, path
			var err error

			if IsGit(url) {
				sbomFilePath, url, err = handleURL(path)
				if err != nil {
					log.Error("Failed to resolve GitHub URL",
						zap.String("url", path),
						zap.Error(err),
					)
					return err
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

			_, signature, publicKey, err := common.GetSignatureBundle(ctx, path, "", "")
			if err != nil {
				log.Error("Failed to fetch signature bundle",
					zap.String("path", path),
					zap.Error(err),
				)
				return err
			}

			sig := sbom.Signature{
				SigValue:  signature,
				PublicKey: publicKey,
			}

			doc, err := sbom.NewSBOMDocument(ctx, f, sig)
			if err != nil {
				return err
			}

			sr := scorer.NewScorer(ctx, doc)
			score := sr.Score()

			docs = append(docs, doc)
			scores = append(scores, score)
			paths = append(paths, sbomFilePath)
		} else {
			pathInfo, err := os.Stat(path)
			if err != nil {
				log.Warn("Skipping invalid path",
					zap.String("path", path),
					zap.Error(err),
				)
				continue
			}

			if pathInfo.IsDir() {
				files, err := os.ReadDir(path)
				if err != nil {
					log.Warn("Failed to read directory",
						zap.String("path", path),
						zap.Error(err),
					)
					continue
				}
				for _, file := range files {
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

	reportFormat := pkgcommon.ReportDetailed
	if ep.Basic {
		reportFormat = pkgcommon.ReportBasic
	} else if ep.JSON {
		reportFormat = pkgcommon.FormatJSON
	}
	coloredOutput := ep.Color

	log.Info("Rendering legacy score report",
		zap.String("format", reportFormat),
		zap.Int("documents", len(docs)),
	)

	nr := reporter.NewReport(ctx,
		docs,
		scores,
		paths,
		reporter.WithFormat(strings.ToLower(reportFormat)), reporter.WithColor(coloredOutput))

	nr.Report()

	log.Info("Legacy scoring workflow completed")
	return nil
}

func processFile(ctx context.Context, ep *Params, path string, fs billy.Filesystem) (sbom.Document, scorer.Scores, error) {
	log := logger.FromContext(ctx)
	log.Debug("Processing SBOM file",
		zap.String("path", path),
	)

	var doc sbom.Document

	_, signature, publicKey, err := common.GetSignatureBundle(ctx, path, "", "")
	if err != nil {
		log.Error("Failed to fetch signature bundle",
			zap.String("path", path),
			zap.Error(err),
		)
		return nil, nil, err
	}

	sig := sbom.Signature{
		SigValue:  signature,
		PublicKey: publicKey,
	}

	if fs != nil {
		f, err := fs.Open(path)
		if err != nil {
			log.Error("Failed to fetch signature bundle",
				zap.String("path", path),
				zap.Error(err),
			)
			return nil, nil, err
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Warn("Failed to close SBOM file",
					zap.String("path", path),
					zap.Error(err),
				)
			}
		}()

		doc, err = sbom.NewSBOMDocument(ctx, f, sig)
		if err != nil {
			log.Error("Failed to parse SBOM document",
				zap.String("path", path),
				zap.Error(err),
			)
			return nil, nil, err
		}
	} else {
		if _, err := os.Stat(path); err != nil {
			log.Debug("failed to stat file", zap.String("path", path), zap.Error(err))
			return nil, nil, err
		}

		// #nosec G304 -- User-provided paths are expected for CLI tool
		f, err := os.Open(path)
		if err != nil {
			log.Debug("failed to open file", zap.String("path", path), zap.Error(err))
			return nil, nil, err
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Warn("Failed to close SBOM file",
					zap.String("path", path),
					zap.Error(err),
				)
			}
		}()

		doc, err = sbom.NewSBOMDocument(ctx, f, sig)
		if err != nil {
			log.Error("Failed to parse SBOM document",
				zap.String("path", path),
				zap.Error(err),
			)
			return nil, nil, err
		}
	}

	sr := scorer.NewScorer(ctx, doc)

	if len(ep.Categories) > 0 {
		if len(ep.Features) == 0 {
			for _, category := range ep.Categories {
				if len(category) == 0 {
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
				if len(cat) == 0 {
					continue
				}
				for _, feat := range ep.Features {
					if len(feat) == 0 {
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
			if len(feature) == 0 {
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
		filters, err := scorer.ReadConfigFile(ep.ConfigPath)
		if err != nil {
			log.Error("Failed to parse SBOM document",
				zap.String("path", path),
				zap.Error(err),
			)
			return nil, nil, err
		}

		for _, filter := range filters {
			sr.AddFilter(filter)
		}
	}

	scores := sr.Score()
	return doc, scores, nil
}
