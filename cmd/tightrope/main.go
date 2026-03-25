package main

import (
	"fmt"
	"os"

	"github.com/TFMV/tightrope/internal/audit"
	"github.com/TFMV/tightrope/internal/custom_rules"
	"github.com/TFMV/tightrope/internal/fs"
	"github.com/TFMV/tightrope/internal/parser"
	"github.com/TFMV/tightrope/internal/report"
	"github.com/TFMV/tightrope/pkg"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
)

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	var format string

	app := &cli.App{
		Name:  "tightrope",
		Usage: "Audit configuration files for best practices and security.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "format",
				Value:       "markdown",
				Usage:       "Output format (markdown, json, html, dot)",
				Destination: &format,
			},
		},
		Action: func(c *cli.Context) error {
			scanPath := c.Args().Get(0)
			if scanPath == "" {
				scanPath = "."
			}

			walker := fs.NewWalker()
			files, err := walker.Walk(scanPath)
			if err != nil {
				return fmt.Errorf("error finding config files: %w", err)
			}

			var configs []*pkg.ConfigData
			p := parser.NewParser()
			for _, file := range files {
				config, err := p.ParseFile(file)
				if err != nil {
					logger.Warn().Err(err).Str("file", file).Msg("Skipping file due to parsing error")
					continue
				}
				configs = append(configs, config)
			}

			// Load custom rules
			customRules, err := custom_rules.LoadCustomRules(".tightrope.yaml")
			if err != nil {
				if !os.IsNotExist(err) {
					logger.Warn().Err(err).Msg("Failed to load custom rules")
				}
			}

			engine, err := audit.NewEngine(customRules)
			if err != nil {
				return fmt.Errorf("failed to create audit engine: %w", err)
			}

			auditReport := engine.AuditConfigs(configs, scanPath)

			generator := report.NewGenerator()
			reportOutput, err := generator.GenerateReport(auditReport, format)
			if err != nil {
				return fmt.Errorf("failed to generate report: %w", err)
			}

			fmt.Println(reportOutput)

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Fatal().Err(err).Msg("Application error")
	}
}
