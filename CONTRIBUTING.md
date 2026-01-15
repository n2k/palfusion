# Contributing to ngx_http_cfml_module

Thank you for your interest in contributing to the nginx CFML module!

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a new branch for your feature/fix

## Development Setup

### Prerequisites

- nginx source code (1.18.0 or later)
- GCC compiler
- PCRE library
- OpenSSL library
- Make

### Building

```bash
# Get nginx source
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar xzf nginx-1.24.0.tar.gz
cd nginx-1.24.0

# Configure with module
./configure --add-module=/path/to/ngx_http_cfml_module

# Build
make
```

### Running Tests

```bash
# Start nginx with test configuration
./objs/nginx -c /path/to/test.conf

# Run test suite
cd t && prove -r .
```

## Code Style

- Follow nginx coding conventions
- Use 4-space indentation
- Keep lines under 80 characters when possible
- Comment complex logic

## Submitting Changes

1. Ensure your code compiles without warnings
2. Add tests for new functionality
3. Update documentation as needed
4. Create a pull request with a clear description

## Pull Request Guidelines

- One feature/fix per PR
- Include test cases
- Update README if adding new features
- Reference any related issues

## Reporting Issues

- Use GitHub Issues
- Include nginx version
- Provide minimal reproduction case
- Include relevant configuration

## Feature Requests

Feature requests are welcome! Please describe:

- The use case
- Expected behavior
- Any implementation ideas

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
