# BRS-XSS v2.1.1 Release Notes
- **Date**: 2025-11-14
- **Tag**: `v2.1.1`
- **Build**: 2025.11.14

## Code Quality & Performance Improvements

**Knowledge Base Refactoring & Report Optimization**

This release focuses on code maintainability improvements and report optimization without breaking changes.

### Improved
- **Knowledge Base Refactoring**: Refactored 8 large knowledge_base modules (>300 lines) into modular structure
  - Split large files into organized directories: `description.py`, `attack_vectors.py`, `remediation.py`
  - Improved code maintainability and adherence to 300-line file limit standard
  - All functionality preserved - fully backward compatible
  - All tests passing (16/16 knowledge_base tests)

- **HTML Report Optimization**: Significantly reduced report file sizes
  - Removed duplicate Knowledge Base information from each vulnerability entry
  - Added centralized Knowledge Base section at the beginning of reports
  - Each vulnerability now references KB section instead of duplicating content
  - **Result**: 75.5% reduction in HTML report size (1.11 MB → 0.27 MB)
  - **Result**: 9x reduction in line count (42,921 → 4,826 lines)
  - Improved report readability and performance

### Changed
- Knowledge Base modules now use modular directory structure instead of single files
- HTML reports use reference-based KB information instead of inline duplication
- Version updated to 2.1.1 across all project files

### Technical Details
- All refactored modules maintain full backward compatibility
- Verified functionality on real targets (testphp.vulnweb.com, easypro.tech)
- No breaking changes - existing code continues to work

### Migration Guide
- No code changes required - fully backward compatible
- Just update via pip: `pip install -U brs-xss==2.1.1`
- All existing integrations continue to work

### Installation
```bash
# PyPI (recommended)
pip install brs-xss==2.1.1

# Docker
docker pull ghcr.io/eptllc/brs-xss:2.1.1
docker pull ghcr.io/eptllc/brs-xss:latest

# From source
git clone https://github.com/EPTLLC/brs-xss.git
cd brs-xss
git checkout v2.1.1
pip install -e .
```

---

# BRS-XSS v2.1.0 Release Notes
- **Date**: 2025-10-26
- **Tag**: `v2.1.0`
- **Build**: 2025.10.26

## MIT License Migration - Major Breaking Change

**Welcome to MIT in v2.1.0!**

This is a MAJOR release with complete license change affecting ALL users and usage terms.

### Breaking Changes
- **MIT License Migration**: MAJOR CHANGE - Migrated from dual GPL/Commercial license to MIT License
  - This is a complete license change affecting all usage terms
  - Previous commercial license restrictions removed
  - Full open source release under MIT terms
  - Contact method changed to Telegram only (https://t.me/EasyProTech)

### License & Legal Updates
- **Contact Policy**: Removed email contacts, now using Telegram only
- **Documentation**: Updated all license references from GPL/Commercial to MIT
- **Legal Files**: Updated LICENSE with MIT license terms

### Distribution & Publishing
- **PyPI Publication**: Package published to PyPI with MIT license
- **Build Process**: Updated for modern standards (SPDX license format)
- **Version Management**: Updated to v2.1.0 across all project files

### What This Means for You
- **Free Usage**: No restrictions - use, modify, distribute freely
- **Commercial Use**: Fully allowed without separate licensing
- **Attribution**: Only requirement is to include MIT license text
- **Support**: Available via Telegram: https://t.me/EasyProTech

### Migration Guide
- No code changes required - fully backward compatible
- License automatically updated - just update via pip
- Contact support via Telegram: https://t.me/EasyProTech

### Installation
```bash
# PyPI (recommended)
pip install brs-xss==2.1.0

# Docker
docker pull ghcr.io/eptllc/brs-xss:2.1.0
docker pull ghcr.io/eptllc/brs-xss:latest

# From source
git clone https://github.com/EPTLLC/brs-xss.git
cd brs-xss
pip install -e .
```

---

**BRS-XSS v2.1.0** | **EasyProTech LLC** | **https://t.me/EasyProTech**

*Now fully open source under MIT License - use freely!*