# Tightrope

## Configuration Auditor

Tightrope is a Go-based configuration auditor that scans directories for config files and detects issues like key conflicts, shadowing, secrets in plain text, deprecated fields, and redundant values.

## Features

- **Audit Rules**: Detects key conflicts, shadowing, secrets in plain text, deprecated fields, and redundant values.
- **File Formats**: Supports YAML, JSON, and TOML with line number extraction for YAML.
- **Output Formats**: Markdown (default), JSON, and HTML.
- **Enterprise Ready**: Cross-platform, performance-optimized, structured logging, and graceful error handling.

## Quick Start

### Installation

```bash
git clone https://github.com/TFMV/tightrope.git
cd tightrope
go build -o tightrope ./cmd/tightrope
```

### Usage

```bash
./tightrope audit [--path PATH] [--format FORMAT] [--verbose]
./tightrope version
```

## Architecture

- `cmd/tightrope/main.go`: CLI entry point
- `internal/audit/`: Audit engine and rules
- `internal/fs/`: File system operations
- `internal/parser/`: Configuration parsers
- `internal/report/`: Report generation
- `pkg/types.go`: Shared type definitions
- `tests/`: Unit tests
- `examples/`: Sample configuration files

## Audit Rules

- **Key Conflicts**: Same key with different values across files.
- **Shadowing**: Key repeated in nested scopes within a file.
- **Secrets in Plain Text**: Potential secrets detected via patterns and key names.
- **Deprecated Fields**: Known deprecated fields for Kubernetes, Docker, and Terraform.
- **Redundant Values**: Identical key-value pairs across files.

## Testing

Run tests with `go test ./tests/`.

## � roulette️ Configuration

- Command-line flags for path, format, and verbosity.
- Environment variable `TIGHTROPE_LOG_LEVEL` for logging.

## Development

- Requires Go 1.21+.
- Build with `go build -o tightrope ./cmd/tightrope`.

## Performance

Optimized for memory efficiency and speed, handles large directories.

## License

MIT License.
