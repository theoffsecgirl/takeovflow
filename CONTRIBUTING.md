# Contributing to takeovflow

Thanks for your interest. Contributions are welcome.

## What you can contribute

- New CNAME fingerprints (service + pattern)
- False positive fixes
- New service detection logic
- Bug fixes
- Documentation improvements

## How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Open a PR against `main` describing what you added and why

## Adding a new fingerprint

Fingerprints live in the detection logic inside `takeovflow.py`.  
For each new service include:
- CNAME pattern (regex or string match)
- Service name
- Example of a vulnerable response
- Reference (writeup, nuclei template, etc.) if available

## Guidelines

- Keep changes focused — one thing per PR
- Test against a live or mock environment before submitting

## Contact

[info@theoffsecgirl.com](mailto:info@theoffsecgirl.com)
