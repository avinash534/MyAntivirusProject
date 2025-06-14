# Security Policy

## Supported Versions

This project is a demo and does not have official releases. The latest version in the `main` branch is the only supported version for security updates.

| Version  | Supported          |
|----------|--------------------|
| main     | ✅                 |

## Reporting a Vulnerability

If you discover a security vulnerability in MyAntivirusProject, please report it responsibly by emailing me directly at https://github.com/avinash534/MyAntivirusProject/graphs/community. Include the following details:

- A description of the vulnerability.
- Steps to reproduce the issue.
- Potential impact (e.g., what an attacker could do).
- Any suggested fixes, if applicable.

I will acknowledge your report within 48 hours and work to address the issue as quickly as possible. Since this is a demo project, I may not be able to provide regular security updates, but I’ll do my best to fix critical vulnerabilities.

Please do not disclose the vulnerability publicly (e.g., in a GitHub issue) until it has been resolved, to avoid putting users at risk.

## Security Best Practices for Users

- **Run in a Safe Environment**: Since this is an antivirus demo, only test it with known, safe files (e.g., the EICAR test file). Do not use it to scan untrusted or malicious files, as the program is not designed for production use.
- **Exclude Test Directory from Antivirus**: If using the EICAR test file, exclude the test directory (e.g., `C:\Test`) from your antivirus scans to avoid interference.
- **Run as Administrator**: Some features (e.g., file access, monitoring) may require administrative privileges on Windows.
