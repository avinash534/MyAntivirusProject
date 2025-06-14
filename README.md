#MyAntivirusProject
A simple antivirus program for Windows that scans directories, monitors file changes in real-time, and detects threats using hash-based signature matching. This project is a demo to showcase basic antivirus functionality, including efficient signature detection using a hash map.
Features

Hash-Based Threat Detection: Uses SHA-256 hashes to identify known threats by comparing file hashes against a signature database.
Efficient Signature Matching: Implements a hash map for O(1) average-case lookup of signatures, making the program scalable for larger databases.
Signature Database: Includes 19 simulated threat hashes in signatures.txt, including the EICAR test file for testing antivirus functionality.
Directory Scanning: Scans a specified directory for files matching known threat signatures.
Real-Time Monitoring: Monitors a directory for file changes (e.g., creation, modification) and scans new or modified files.
Interactive Menu: Allows users to scan directories, start monitoring, or change the working directory.

Requirements

Operating System: Windows 10 or later (tested on Windows 11).
Permissions: Write access to the directory where the program runs (to create files like signatures.txt if needed).
Antivirus Exclusion: If using the EICAR test file, exclude the working directory (e.g., C:\Test) from your antivirus scans to avoid interference.

Setup Instructions

Clone the Repository:
git clone https://github.com/avinash534/MyAntivirusProject.git
cd MyAntivirusProject


Build the Project:

Open the project in Visual Studio (tested with Visual Studio 2022).
Build the solution in Debug or Release mode (e.g., press F5 to build and run).


Prepare the Test Directory:

Create a directory C:\Test (or use the menu to change to a different directory).
The program will automatically create test files (test1.txt, test2.txt) in C:\Test on first run.


Set Up the Signature Database:

Ensure signatures.txt is in the same directory as the executable (e.g., x64\Debug or x64\Release).
The file should contain SHA-256 hashes of known threats in the format <hash>|Threat-Name, one per line. Example:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f|EICAR-Test-File
<hash_of_test1.txt>|Simulated-Malware-1
<hash_of_test2.txt>|Simulated-Malware-2


The program includes 19 simulated threat hashes, including the EICAR test file for testing.


Handle Antivirus Interference:

If using the EICAR test file (eicar.txt), your antivirus may block it. Add an exclusion for C:\Test in your antivirus settings (e.g., Windows Defender > Virus & Threat Protection > Manage Settings > Add or remove exclusions > Add folder C:\Test).


Run the Program:

Run the executable (e.g., MyAntivirusProject.exe).
Use the interactive menu to scan directories, start real-time monitoring, or change the working directory.



Usage

Menu Options:

Scan Directory: Scans the current directory (default: C:\Test) for files matching known threat signatures.
Start Real-Time Monitoring: Monitors the current directory for file changes and scans new or modified files.
Change Directory: Change the directory to scan or monitor.
Exit: Exit the program.


Example:
=== MyAntivirusProject Menu ===
Current directory: C:\Test
1. Scan directory
2. Start real-time monitoring
3. Change directory
4. Exit
Enter your choice (1-4): 1
Performing scan on C:\Test...
Threat detected in C:\Test\eicar.txt: EICAR-Test-File (SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f)!
Threat detected in C:\Test\test1.txt: Simulated-Malware-1 (SHA-256: <hash1>)!



Files

signatures.txt: Contains SHA-256 hashes of known threats in the format <hash>|Threat-Name. Currently includes 19 simulated threats, including the EICAR test file.
MyAntivirusProject.exe: The compiled executable (found in x64\Debug or x64\Release after building).
main.c: Contains the main program logic, including the interactive menu and OS version check.
file_handling.c: Implements core functionality (hash computation, scanning, monitoring, hash map).

Limitations

Currently supports Windows 10 and later only.
Does not yet include logging of events (planned for future updates).
Limited to hash-based detection; does not detect polymorphic or zero-day threats.

Future Improvements

Add logging of all events (scans, monitoring, detections) to scan_log.txt.
Enhance the menu to allow viewing of logs.
Improve error handling for edge cases (e.g., invalid signatures, file access issues).
Add support for dynamic signature updates (e.g., downloading new hashes from a server).

License
This project is for educational purposes only and is not licensed for production use.

