## Release Notes: Tightrope v0.1.0

We are excited to announce the first official release of Tightrope, a fast and lightweight configuration auditor designed to help you maintain clean, secure, and consistent configuration files across your projects.

### Key Features

This initial release includes a robust set of features to get you started with configuration auditing:

*   **Comprehensive Auditing Rules:**
    *   **Key Conflicts:** Detects when the same key has different values across multiple configuration files.
    *   **Key Shadowing:** Identifies when a key is redefined within the same file, which can lead to unexpected behavior.
    *   **Secrets in Plaintext:** Scans for potential secrets (e.g., passwords, API keys) that are stored in plaintext.
    *   **Deprecated Fields:** Warns developers about the use of deprecated fields in common configuration formats.

*   **Multiple File Format Support:** Scans `YAML` and `JSON` files to ensure broad compatibility with modern applications.

*   **Flexible Reporting:** Generates reports in various formats, including:
    *   `Markdown` (default) for human-readable output.
    *   `JSON` for easy integration with CI/CD pipelines and other automated tools.

*   **Accurate Line Number Reporting:** Pinpoints the exact location of issues within your configuration files, making them easier to find and fix.

*   **Simple Command-Line Interface (CLI):** An easy-to-use CLI for scanning directories and specifying the output format.

### Getting Started

To get started with Tightrope, make sure you have Go installed, then follow these simple steps:

**Install Tightrope:**
```bash
go get -u github.com/TFMV/tightrope
```

**Run an Audit:**
```bash
tightrope /path/to/your/configs
```

**Integrate with CI/CD:**
For CI/CD pipelines, you can output the report in JSON format for easier processing:
```bash
tightrope --format=json /path/to/your/configs > report.json
```

### What's Next?

This is just the beginning for Tightrope. We are already working on new features for future releases, including an expanded set of audit rules and support for more configuration file formats.

We welcome your feedback and contributions! Please feel free to open an issue or submit a pull request on our GitHub repository.
