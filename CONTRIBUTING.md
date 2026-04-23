# Contributing to Aegis-SOC

Thank you for your interest in contributing to Aegis-SOC.
This document outlines how to get started.

---

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your feature or fix
4. Make your changes
5. Test thoroughly
6. Submit a Pull Request

---

## Development Setup

```bash
git clone https://github.com/yourusername/Aegis-SOC.git
cd Aegis-SOC
pip install -r requirements.txt
cp .env.example .env
# Add your API keys to .env
python main.py
```

---

## Areas Open for Contribution

- New attack vector simulations in simulator/
- Additional threat intel sources in enrichment/
- New response playbooks in playbooks/
- Dashboard UI improvements in dashboard/
- Unit tests in tests/
- Documentation improvements

---

## Code Guidelines

- Follow existing code style and structure
- Each module should have a single responsibility
- Add docstrings to all functions
- Test your changes before submitting

---

## Reporting Issues

Open a GitHub issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior

---

## Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Reference any related issues
- Update README if needed
- Ensure no API keys or sensitive data are included

---

```
[ AEGIS-SOC ] — CONTRIBUTIONS WELCOME
```