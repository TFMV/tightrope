package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/TFMV/tightrope/internal/audit"
	"github.com/TFMV/tightrope/internal/fs"
	"github.com/TFMV/tightrope/internal/parser"
	"github.com/TFMV/tightrope/internal/report"
	"github.com/TFMV/tightrope/pkg"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const version = "v0.1.0"

var (
	scanPath     string
	outputFormat string
	verbose      bool
)

func main() {
	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "tightrope",
	Short: "Configuration auditor",
	Long: `Tightrope is a minimalist, enterprise-grade configuration auditor that 
recursively scans directories for common config files and detects various 
configuration issues including key conflicts, shadowing, secrets in plain text, 
deprecated fields, and redundant values.`,
	SilenceUsage: true,
}

var auditCmd = &cobra.Command{
	Use:   "audit [flags]",
	Short: "Audit configuration files in a directory",
	Long: `Recursively scan a directory for configuration files (*.yaml, *.yml, *.json, *.toml)
and audit them for common issues:

- Key Conflicts: Identical keys with differing values across files
- Shadowing: Same key repeated in nested scopes within a file  
- Secrets in Plain Text: Detect passwords, tokens, or API keys using heuristics
- Deprecated Fields: Match against built-in list of deprecated keys
- Redundant Values: Flag identical key-value pairs repeated across files

Examples:
  tightrope audit                           # Audit current directory
  tightrope audit --path /path/to/configs   # Audit specific directory
  tightrope audit --format json             # Output as JSON
  tightrope audit --format html > report.html # Generate HTML report`,
	RunE: runAudit,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version information",
	Long:  "Display the current version of tightrope",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("tightrope %s\n", version)
	},
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(versionCmd)

	// Audit command flags
	auditCmd.Flags().StringVarP(&scanPath, "path", "p", ".", "Directory to scan for configuration files")
	auditCmd.Flags().StringVarP(&outputFormat, "format", "f", pkg.FormatMarkdown,
		"Output format: markdown, json, html")
	auditCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")

	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
}

func runAudit(cmd *cobra.Command, args []string) error {
	// Set log level based on verbose flag
	if verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Validate output format
	if outputFormat != pkg.FormatMarkdown &&
		outputFormat != pkg.FormatJSON &&
		outputFormat != pkg.FormatHTML {
		return fmt.Errorf("unsupported output format: %s (supported: markdown, json, html)", outputFormat)
	}

	// Validate scan path
	if _, err := os.Stat(scanPath); os.IsNotExist(err) {
		return fmt.Errorf("scan path does not exist: %s", scanPath)
	}

	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	log.Info().
		Str("path", absPath).
		Str("format", outputFormat).
		Msg("Starting configuration audit")

	// Initialize components
	walker := fs.NewWalker()
	parser := parser.NewParser()
	auditEngine, err := audit.NewEngine()
	if err != nil {
		return fmt.Errorf("failed to initialize audit engine: %w", err)
	}
	reportGenerator := report.NewGenerator()

	// Step 1: Discover configuration files
	log.Info().Msg("Discovering configuration files...")
	configFiles, err := walker.Walk(absPath)
	if err != nil {
		return fmt.Errorf("failed to walk directory: %w", err)
	}

	if len(configFiles) == 0 {
		log.Warn().Msg("No configuration files found")
		fmt.Println("No configuration files found in the specified path.")
		return nil
	}

	log.Info().
		Int("count", len(configFiles)).
		Msg("Configuration files discovered")

	// Step 2: Parse configuration files
	log.Info().Msg("Parsing configuration files...")
	var configData []*pkg.ConfigData
	parseErrors := 0

	for _, filePath := range configFiles {
		relPath, err := fs.GetRelativePath(absPath, filePath)
		if err != nil {
			log.Warn().
				Err(err).
				Str("file", filePath).
				Msg("Failed to get relative path")
			relPath = filePath
		}

		config, err := parser.ParseFile(filePath)
		if err != nil {
			log.Error().
				Err(err).
				Str("file", relPath).
				Msg("Failed to parse configuration file")
			parseErrors++
			continue
		}

		// Update file path to relative path for cleaner reporting
		config.FilePath = relPath
		configData = append(configData, config)
	}

	if parseErrors > 0 {
		log.Warn().
			Int("errors", parseErrors).
			Int("total", len(configFiles)).
			Msg("Some files failed to parse")
	}

	if len(configData) == 0 {
		return fmt.Errorf("no configuration files could be parsed successfully")
	}

	log.Info().
		Int("parsed", len(configData)).
		Msg("Configuration files parsed successfully")

	// Step 3: Run audit
	log.Info().Msg("Running configuration audit...")
	auditReport := auditEngine.AuditConfigs(configData, absPath)

	// Step 4: Generate report
	log.Info().
		Str("format", outputFormat).
		Msg("Generating audit report...")

	reportContent, err := reportGenerator.GenerateReport(auditReport, outputFormat)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	// Output report to stdout
	fmt.Print(reportContent)

	// Log summary to stderr
	log.Info().
		Int("findings", auditReport.Summary.TotalFindings).
		Int("files_scanned", auditReport.FilesScanned).
		Int("critical", auditReport.Summary.FindingsBySeverity[pkg.SeverityCritical]).
		Int("warning", auditReport.Summary.FindingsBySeverity[pkg.SeverityWarning]).
		Int("info", auditReport.Summary.FindingsBySeverity[pkg.SeverityInfo]).
		Msg("Audit completed")

	// Exit with non-zero status if critical issues found
	if auditReport.Summary.FindingsBySeverity[pkg.SeverityCritical] > 0 {
		os.Exit(1)
	}

	return nil
}

// Help command override to show detailed usage
func init() {
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "Help about any command or detailed usage information",
		Long: `Help provides help for any command in the application.
Simply type tightrope help [path to command] for full details.

AUDIT RULES:
  Key Conflicts      - Identical keys with different values across files
  Shadowing         - Same key repeated in nested scopes within a file
  Secrets in Plain  - Potential secrets detected using pattern matching
  Deprecated Fields - Usage of deprecated configuration fields
  Redundant Values  - Identical key-value pairs across multiple files

SUPPORTED FORMATS:
  YAML (.yaml, .yml)  - YAML configuration files
  JSON (.json)        - JSON configuration files  
  TOML (.toml)        - TOML configuration files

OUTPUT FORMATS:
  markdown (default)  - Human-readable Markdown format
  json               - Machine-readable JSON format
  html               - Rich HTML format for web viewing

EXAMPLES:
  tightrope audit                          # Audit current directory, output Markdown
  tightrope audit --path ./configs         # Audit specific directory
  tightrope audit --format json            # Output JSON to stdout
  tightrope audit --format html > report.html  # Generate HTML report file
  tightrope audit --verbose               # Enable detailed logging`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				rootCmd.Help()
				return
			}
			if subCmd, _, err := rootCmd.Find(args); err == nil {
				subCmd.Help()
			} else {
				fmt.Printf("Unknown command: %s\n", args[0])
				rootCmd.Help()
			}
		},
	})
}
