# Contributing to BRS-XSS

**Project:** BRS-XSS (Brabus Recon Suite - XSS Module)  
**Company:** EasyProTech LLC (www.easypro.tech)  
**Contact:** https://t.me/EasyProTech  
**License:** MIT License

## License Migration Notice

**IMPORTANT:** As of v2.1.0 (October 26, 2025), BRS-XSS has migrated from dual GPL/Commercial licensing to MIT License.

### Code Ownership

- **All code prior to v2.1.0:** Owned by EasyProTech LLC
- **No external contributors:** All commits authored by project maintainers
- **License migration:** Legally valid as single copyright holder

## How to Contribute

We welcome contributions to BRS-XSS! Here's how you can help:

### Getting Started

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create** a feature branch: `git checkout -b feature/amazing-feature`
4. **Make** your changes
5. **Test** thoroughly
6. **Submit** a pull request

### Development Setup

```bash
# Clone the repository
git clone https://github.com/EPTLLC/brs-xss.git
cd brs-xss

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e .
pip install -r requirements/dev.txt

# Install pre-commit hooks
pre-commit install
```

### Code Standards

- **Language:** Python 3.10+
- **Style:** Follow PEP 8
- **Linting:** Use `ruff check .`
- **Type Hints:** Required for all new code
- **Tests:** Required for all new features
- **Documentation:** Update docstrings and README as needed

### Commit Guidelines

- **Format:** `type: description`
- **Types:** feat, fix, docs, style, refactor, test, chore
- **Examples:**
  - `feat: add new payload generation algorithm`
  - `fix: resolve WAF detection false positives`
  - `docs: update installation instructions`

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=brsxss

# Run specific test file
pytest tests/core/test_scanner.py
```

### Pull Request Process

1. **Update** documentation for any new features
2. **Add** tests for new functionality
3. **Ensure** all tests pass
4. **Update** CHANGELOG.md with your changes
5. **Request** review from maintainers

### License Agreement

By contributing to BRS-XSS, you agree that:

1. **Your contributions** will be licensed under the MIT License
2. **You have the right** to submit your contributions
3. **You grant** EasyProTech LLC perpetual rights to your contributions
4. **You understand** this is an open source project under MIT License

### Developer Certificate of Origin (DCO)

All contributions must include a "Signed-off-by" line in the commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

By adding this line, you certify that:
- You wrote the code or have the right to submit it
- You agree to license your contribution under the project's MIT License
- Your contribution complies with the Developer Certificate of Origin v1.1

**How to sign commits:**
```bash
git commit -s -m "your commit message"
```

The `-s` flag automatically adds the Signed-off-by line.

### Code of Conduct

- **Be respectful** and professional
- **Focus on** constructive feedback
- **Help others** learn and grow
- **Report** inappropriate behavior to https://t.me/EasyProTech

### Security Contributions

For security-related contributions:

- **Follow** our Security Policy (SECURITY.md)
- **Contact us** privately before submitting public PRs
- **Use** responsible disclosure practices

### Areas We Need Help

- **Testing:** More test coverage, edge cases
- **Documentation:** Examples, tutorials, API docs
- **Payloads:** New XSS vectors and techniques
- **WAF Bypass:** New evasion techniques
- **Internationalization:** Translations
- **Bug Fixes:** Check our Issues page

### Questions?

- **General Questions:** https://t.me/EasyProTech
- **Bug Reports:** GitHub Issues
- **Feature Requests:** GitHub Issues
- **Security Issues:** See SECURITY.md

### Recognition

Contributors will be:
- **Listed** in CONTRIBUTORS.md
- **Credited** in release notes
- **Mentioned** in project documentation

---

**Thank you for contributing to BRS-XSS!**

**Last Updated:** Thu 14 Nov 2025 03:30:00 UTC  
**Version:** 2.1.1
