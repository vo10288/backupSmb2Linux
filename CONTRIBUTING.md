# Contributing to Backup Rotazionale

Thanks for your interest in contributing! Here's how you can help.

## How to Contribute

### Reporting Bugs

Open an issue with:
- A clear title and description
- Steps to reproduce the problem
- Your environment (OS, Python version, etc.)
- Relevant log output (from `/var/log/backup_system/`)

### Suggesting Features

Open an issue tagged `enhancement` with:
- What problem does it solve?
- How should it work?
- Any alternatives you've considered?

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Make your changes
4. Test thoroughly (especially mount/umount and LUKS operations — use `dry_run: true`)
5. Commit with clear messages
6. Push to your fork and open a PR

## Code Guidelines

- Python 3.10+ with type hints
- Follow existing code style (no external formatter enforced, just be consistent)
- Add logging for any new operation (`logger.info` / `logger.error`)
- All mount/umount operations must have proper cleanup in `finally` blocks
- Never hardcode paths — use the config

## Security

If you discover a security vulnerability, please **do not** open a public issue. Instead, contact the maintainer directly.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
