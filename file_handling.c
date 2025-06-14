#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0A00 // Windows 10 and later (including Windows 11)
#define NTDDI_VERSION 0x0A00000B // Windows 10 21H2, compatible with Windows 11

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h> // For MD5 hash computation

#define MAX_SIGNATURES 10
#define MAX_SIG_LENGTH 33 // MD5 hash is 32 chars + null terminator

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

// Compute MD5 hash of a file
int compute_file_hash(const char* filename, char* hash_str) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error opening file %s for hash computation!\n", filename);
        return 0;
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        printf("CryptAcquireContext failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 0;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        printf("CryptCreateHash failed: %lu\n", GetLastError());
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return 0;
    }

    BYTE buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            printf("CryptHashData failed: %lu\n", GetLastError());
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return 0;
        }
    }

    BYTE hash[16]; // MD5 hash is 16 bytes
    DWORD hashLen = sizeof(hash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        printf("CryptGetHashParam failed: %lu\n", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return 0;
    }

    // Convert hash to hexadecimal string
    for (int i = 0; i < hashLen; i++) {
        snprintf(hash_str + (i * 2), 3, "%02x", hash[i]);
    }
    hash_str[32] = 0; // Null terminate

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return 1;
}

int scan_file(const char* filename) {
    char file_hash[MAX_SIG_LENGTH];
    if (!compute_file_hash(filename, file_hash)) {
        printf("Failed to compute hash for %s.\n", filename);
        return 0;
    }

    for (int i = 0; i < num_signatures; i++) {
        if (_stricmp(file_hash, signatures[i]) == 0) {
            printf("Threat detected in %s (MD5: %s)!\n", filename, file_hash);
            return 1;
        }
    }

    printf("No threats found in %s (MD5: %s).\n", filename, file_hash);
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
    keep_monitoring = 1;

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