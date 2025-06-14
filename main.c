#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0A00 // Windows 10 and later (including Windows 11)
#define NTDDI_VERSION 0x0A00000B // Windows 10 21H2, compatible with Windows 11

#include <stdio.h>
#include <windows.h>
#include <VersionHelpers.h> // For IsWindows10OrGreater

// Declare functions and variables from file_handling.c
extern char signatures[10][33]; // Updated MAX_SIG_LENGTH to 33
extern int num_signatures;
extern volatile int keep_monitoring;
void load_signatures(const char* sig_file);
void scan_directory(const char* dir_path);
void monitor_directory(const char* dir_path);

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType);

// Function to create a test file if it doesn't exist
void create_test_file(const char* filename, const char* content) {
    FILE* file = NULL;
    errno_t err = fopen_s(&file, filename, "r");
    if (err != 0 || file == NULL) {
        err = fopen_s(&file, filename, "w");
        if (err != 0 || file == NULL) {
            printf("Error creating file %s! Error code: %d\n", filename, err);
            return;
        }
        fprintf(file, "%s\n", content);
        fclose(file);
        printf("Created test file: %s\n", filename);
    }
    else {
        fclose(file);
    }
}

// Function to check the OS version at runtime using VersionHelpers
BOOL CheckOSVersion() {
    if (IsWindows10OrGreater()) {
        // Get the build number for informational purposes
        DWORD buildNumber = 0;
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD size = sizeof(DWORD);
            RegQueryValueExA(hKey, "CurrentBuildNumber", NULL, NULL, (LPBYTE)&buildNumber, &size);
            RegCloseKey(hKey);
        }
        printf("OS Version: Windows 10 or later (Build %lu)\n", buildNumber);
        return TRUE;
    }
    else {
        printf("This program requires Windows 10 or later.\n");
        return FALSE;
    }
}

int main() {
    if (!CheckOSVersion()) {
        return 1;
    }

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        printf("Error setting Ctrl+C handler in main!\n");
        return 1;
    }

    create_test_file("C:\\Test\\test1.txt", "This contains malware");
    create_test_file("C:\\Test\\test2.txt", "This is a trojan test");

    load_signatures("signatures.txt");
    printf("Loaded %d signatures.\n", num_signatures);

    char directory[MAX_PATH] = "C:\\Test"; // Default directory
    char input_path[MAX_PATH];
    int choice;

    while (1) {
        printf("\n=== MyAntivirusProject Menu ===\n");
        printf("Current directory: %s\n", directory);
        printf("1. Scan directory\n");
        printf("2. Start real-time monitoring\n");
        printf("3. Change directory\n");
        printf("4. Exit\n");
        printf("Enter your choice (1-4): ");
        scanf_s("%d", &choice);

        while (getchar() != '\n');

        switch (choice) {
        case 1:
            printf("Performing scan on %s...\n", directory);
            scan_directory(directory);
            break;
        case 2:
            monitor_directory(directory);
            break;
        case 3:
            printf("Enter new directory path (e.g., C:\\Path\\To\\Folder): ");
            fgets(input_path, MAX_PATH, stdin);
            input_path[strcspn(input_path, "\n")] = 0; // Remove newline
            if (strlen(input_path) != 0) { // Fix signed/unsigned mismatch
                // Check if the directory exists
                DWORD attributes = GetFileAttributesA(input_path);
                if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    printf("No directory found in this drive: %s\n", input_path);
                    printf("Keeping current directory: %s\n", directory);
                }
                else {
                    strncpy_s(directory, MAX_PATH, input_path, _TRUNCATE);
                    printf("Directory changed to %s\n", directory);
                }
            }
            else {
                printf("Invalid path. Keeping current directory: %s\n", directory);
            }
            break;
        case 4:
            printf("Exiting program.\n");
            SetConsoleCtrlHandler(CtrlHandler, FALSE);
            return 0;
        default:
            printf("Invalid choice! Please enter a number between 1 and 4.\n");
        }
    }

    return 0;
}