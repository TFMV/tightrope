# Tightrope

**A fast and lightweight configuration auditor.**

Tightrope is a configuration auditor that helps you maintain clean and secure configurations. It scans your configuration files and identifies potential issues, such as conflicting keys, duplicate values, and secrets stored in plaintext.

## Key Features

- **Speed and Efficiency:** Tightrope is designed to be fast and lightweight, making it ideal for use in CI/CD pipelines and large-scale deployments.
- **Comprehensive Auditing:** It performs a wide range of checks to ensure the integrity and security of your configurations.
- **Flexible Output:** Tightrope supports multiple output formats, including JSON and Markdown, so you can easily integrate it with your existing tools and workflows.
- **Customizable Rules:** You can extend Tightrope's functionality by adding your own custom rules to enforce organization-specific policies.

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

## CI/CD Integration

To integrate Tightrope into your CI/CD pipeline, you can use the following command:

```bash
tightrope --format=json /path/to/your/configs > report.json
```

This will generate a JSON report that you can then use to fail your build or trigger other actions in your pipeline.

## Rules

Tightrope includes a number of built-in rules that cover a wide range of common configuration issues. These rules include:

- **Key Conflicts:** This rule checks for keys that are defined with different values in multiple files.
- **Duplicate Values:** This rule checks for keys that have the same value as other keys in the same file.
- **Secrets in Plaintext:** This rule checks for secrets that are stored in plaintext.

You can also create your own custom rules to enforce organization-specific policies.

## Contributing

We welcome contributions to Tightrope! If you'd like to contribute, please fork the repository and submit a pull request.

## License

Tightrope is licensed under the MIT License.

## Contact

If you have any questions or feedback, please feel free to contact us at [email protected]
