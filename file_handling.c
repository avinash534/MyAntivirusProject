#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0A00 // Windows 10

#include <stdio.h>
#include <string.h>
#include <windows.h>

#define MAX_SIGNATURES 10
#define MAX_SIG_LENGTH 50

char signatures[MAX_SIGNATURES][MAX_SIG_LENGTH];
int num_signatures = 0;
volatile int keep_monitoring = 1;

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT) {
        printf("\nCtrl+C detected. Stopping monitoring...\n");
        keep_monitoring = 0;
        return TRUE;
    }
    return FALSE;
}

void load_signatures(const char* sig_file) {
    FILE* file = NULL;
    errno_t err = fopen_s(&file, sig_file, "r");
    if (err != 0 || file == NULL) {
        printf("Error opening signatures file %s! Error code: %d\n", sig_file, err);
        return;
    }

    while (num_signatures < MAX_SIGNATURES && fgets(signatures[num_signatures], MAX_SIG_LENGTH, file)) {
        signatures[num_signatures][strcspn(signatures[num_signatures], "\n")] = 0;
        num_signatures++;
    }

    fclose(file);
}

int scan_file(const char* filename) {
    FILE* file = NULL;
    errno_t err = fopen_s(&file, filename, "r");
    if (err != 0 || file == NULL) {
        printf("Error opening file %s! Error code: %d\n", filename, err);
        return 0;
    }

    char buffer[100];
    while (fgets(buffer, sizeof(buffer), file)) {
        for (int i = 0; i < num_signatures; i++) {
            if (strstr(buffer, signatures[i])) {
                printf("Signature '%s' detected in %s!\n", signatures[i], filename);
                fclose(file);
                return 1;
            }
        }
    }

    printf("No threats found in %s.\n", filename);
    fclose(file);
    return 0;
}

void scan_directory(const char* dir_path) {
    WIN32_FIND_DATAA find_file_data;
    HANDLE hFind;
    char search_path[MAX_PATH];

    snprintf(search_path, MAX_PATH, "%s\\*", dir_path);

    hFind = FindFirstFileA(search_path, &find_file_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("Error accessing directory %s!\n", dir_path);
        return;
    }

    do {
        if (strcmp(find_file_data.cFileName, ".") == 0 || strcmp(find_file_data.cFileName, "..") == 0) {
            continue;
        }

        char full_path[MAX_PATH];
        snprintf(full_path, MAX_PATH, "%s\\%s", dir_path, find_file_data.cFileName);

        if (!(find_file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            scan_file(full_path);
        }
    } while (FindNextFileA(hFind, &find_file_data) != 0);

    FindClose(hFind);
}

void monitor_directory(const char* dir_path) {
    keep_monitoring = 1; // Reset the flag before starting monitoring

    WCHAR w_dir_path[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, dir_path, -1, w_dir_path, MAX_PATH);

    HANDLE hDir = CreateFileW(
        w_dir_path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        printf("Error opening directory %s for monitoring!\n", dir_path);
        return;
    }

    printf("Monitoring directory: %s (Press Ctrl+C to stop)\n", dir_path);

    char buffer[1024];
    DWORD bytes_returned;
    FILE_NOTIFY_INFORMATION* pNotify;

    while (keep_monitoring) {
        if (ReadDirectoryChangesW(
            hDir,
            buffer,
            sizeof(buffer),
            FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytes_returned,
            NULL,
            NULL
        )) {
            pNotify = (FILE_NOTIFY_INFORMATION*)buffer;

            do {
                char filename[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, pNotify->FileName, pNotify->FileNameLength / sizeof(WCHAR),
                    filename, MAX_PATH, NULL, NULL);
                filename[pNotify->FileNameLength / sizeof(WCHAR)] = '\0';

                char full_path[MAX_PATH];
                snprintf(full_path, MAX_PATH, "%s\\%s", dir_path, filename);

                if (pNotify->Action == FILE_ACTION_ADDED || pNotify->Action == FILE_ACTION_MODIFIED) {
                    printf("File %s was %s. Scanning...\n", filename,
                        pNotify->Action == FILE_ACTION_ADDED ? "created" : "modified");
                    scan_file(full_path);
                }

                if (pNotify->NextEntryOffset == 0) break;
                pNotify = (FILE_NOTIFY_INFORMATION*)((char*)pNotify + pNotify->NextEntryOffset);
            } while (1);
        }
    }

    CloseHandle(hDir);
    printf("Monitoring stopped.\n");
}