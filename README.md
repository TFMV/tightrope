# Tightrope

**A fast and lightweight configuration auditor.**

Tightrope is a configuration auditor that helps you maintain clean and secure configurations. It scans your configuration files and identifies potential issues, such as conflicting keys, duplicate values, and secrets stored in plaintext.

## Key Features

- **Speed and Efficiency:** Tightrope is designed to be fast and lightweight, making it ideal for use in CI/CD pipelines and large-scale deployments.
- **Comprehensive Auditing:** It performs a wide range of checks to ensure the integrity and security of your configurations.
- **Flexible Output:** Tightrope supports multiple output formats, including JSON, Markdown, HTML, and DOT.
- **Customizable Rules:** You can extend Tightrope's functionality by adding your own custom rules to enforce organization-specific policies.
- **Multi-Format Support:** Supports a wide variety of configuration file formats.

## Supported File Formats

Tightrope can parse and audit the following file formats:

- **YAML** (`.yaml`, `.yml`)
- **JSON** (`.json`)
- **TOML** (`.toml`)
- **Terraform** (`.tf`)
- **Environment Variables** (`.env`)
- **Java Properties** (`.properties`)
- **INI Files** (`.ini`)
- **XML** (`.xml`)
- **Dockerfiles** (`Dockerfile`)

## Getting Started

### Installation

To install Tightrope, you'll need to have Go installed on your system. You can then install Tightrope by running the following command:

```bash
go get -u github.com/TFMV/tightrope
```

### Usage

To run Tightrope, simply specify the path to the directory containing your configuration files:

```bash
tightrope /path/to/your/configs
```

Tightrope will recursively scan the specified directory and generate a report of its findings.

### Command-Line Options

- `--format` - Output format: `json`, `markdown`, `html`, `dot` (default: `markdown`)
- `--output` - Output file path (optional)
- `--verbose` - Enable verbose logging

### CI/CD Integration

To integrate Tightrope into your CI/CD pipeline, you can use the following command:

```bash
tightrope --format=json /path/to/your/configs > report.json
```

This will generate a JSON report that you can then use to fail your build or trigger other actions in your pipeline.

## Rules

Tightrope includes a number of built-in rules that cover a wide range of common configuration issues. These rules include:

### Security Rules

- **SecretInPlainText:** Detects secrets stored in plaintext, including:
  - Keys containing `password`, `api_key`, `token`, `secret`, `private_key`
  - AWS access keys (AKIA...)
  - Stripe keys (sk-...)
  - GitHub tokens (ghp_..., gho_..., github_pat_...)
  - Database connection strings with embedded credentials (postgres://, mysql://, mongodb://, redis://)
  - Private keys (BEGIN PRIVATE KEY)

- **SuspiciousValue:** Detects suspicious values such as:
  - Hardcoded localhost/127.0.0.1 addresses
  - Plaintext passwords in values
  - Admin/root credentials
  - Dangerous functions (eval, exec, system)
  - XSS patterns (javascript:, script tags)

- **HardcodedIP:** Detects hardcoded IP addresses in configuration values.

- **InsecureURL:** Detects HTTP URLs (non-HTTPS) that could expose data in transit.

### Integrity Rules

- **KeyConflict:** This rule checks for keys that are defined with different values in multiple files. This helps catch configuration drift across environments.

- **KeyShadowing:** This rule checks for keys that are defined multiple times within the same file, which can lead to unexpected behavior.

- **RedundantValue:** This rule checks for keys that have the same value as other keys in the same file.

### Compatibility Rules

- **DeprecatedField:** Detects deprecated fields and suggests replacements. Currently checks for deprecated Kubernetes API versions (e.g., `extensions/v1beta1`).

### Custom Rules

You can create your own custom rules by creating a `.tightrope.yaml` file in your project:

```yaml
custom_rules:
  - name: "No Debug Mode in Production"
    pattern: "debug:\\s*(true|1|yes)"
    severity: "Critical"
    message: "Debug mode should not be enabled in production"
```

## Examples

The `examples/` directory contains sample configuration files that demonstrate various issues that Tightrope can detect:

- `app.env` - Environment variables with secrets and conflicting values
- `application.properties` - Java properties with database credentials
- `config.ini` - INI files with duplicate keys
- `config.xml` - XML configuration with secrets
- `Dockerfile` - Dockerfiles with environment variables containing secrets
- `config1.yaml`, `config2.yaml` - Kubernetes manifests with key conflicts

Run Tightrope on the examples to see the auditor in action:

```bash
tightrope examples/
```

## Contributing

We welcome contributions to Tightrope! If you would like to contribute, please fork the repository and submit a pull request.

## License

Tightrope is licensed under the MIT License.
