# MyAntivirusProject

A simple antivirus scanner for Windows built in C.

## Overview
This project is an antivirus scanner that can:
- Scan entire directories.
- Load signatures from a database (`signatures.txt`).
- Monitor a directory in real-time for new or modified files and scan them automatically.
- Interactive console menu to control scanning and monitoring.

Future features will include more advanced detection methods.

## How to Run
- Clone the repository: `git clone https://github.com/YourUsername/MyAntivirusProject.git`
- Create a `C:\Test` directory for monitoring.
- Add virus signatures (MD5 hashes) to `signatures.txt`.
- Open the `.sln` file in Visual Studio.
- Build and run the project.
