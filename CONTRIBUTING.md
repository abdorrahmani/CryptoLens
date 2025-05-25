 # Contributing to CryptoLens

Thank you for your interest in contributing to CryptoLens! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in the Issues section
2. If not, create a new issue with a clear title and description
3. Include steps to reproduce the bug
4. Add any relevant screenshots or error messages

### Suggesting Features

1. Check if the feature has already been suggested
2. Create a new issue with a clear title and description
3. Explain why this feature would be useful
4. Include any relevant examples or use cases

### Pull Requests

1. Fork the repository
2. Create a new branch for your feature/fix
3. Make your changes
4. Write or update tests as needed
5. Update documentation
6. Submit a pull request

### Development Setup

1. Install Go 1.21 or later
2. Fork and clone the repository
3. Install dependencies:
   ```bash
   go mod download
   ```
4. Run tests:
   ```bash
   go test ./...
   ```

### Code Style

- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` to format your code
- Write clear, descriptive commit messages
- Include comments for complex logic

### Testing

- Write tests for new features
- Ensure all tests pass before submitting a PR
- Include both unit tests and integration tests where appropriate

## Documentation

- Update README.md if needed
- Add comments to new code
- Update any relevant documentation

## License

By contributing to CryptoLens, you agree that your contributions will be licensed under the project's MIT License.