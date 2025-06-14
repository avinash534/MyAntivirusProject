#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0A00 // Windows 10 and later (including Windows 11)
#define NTDDI_VERSION 0x0A00000B // Windows 10 21H2, compatible with Windows 11

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>
#include <time.h>

#define MAX_SIGNATURES 1000 // Increased for larger database
#define MAX_SIG_LENGTH 65 // SHA-256 hash is 64 chars + null terminator
#define HASH_TABLE_SIZE 100 // Size of hash table (adjust based on expected signatures)

// Hash map node structure
typedef struct HashNode {
    char signature[MAX_SIG_LENGTH];
    struct HashNode* next;
} HashNode;

// Hash table structure
HashNode* hash_table[HASH_TABLE_SIZE] = { NULL };
int num_signatures = 0;
volatile int keep_monitoring = 1;

// Simple hash function for strings
unsigned int hash_function(const char* str) {
    unsigned int hash = 0;
    for (int i = 0; str[i] != '\0'; i++) {
        hash = 31 * hash + str[i];
    }
    return hash % HASH_TABLE_SIZE;
}

// Insert a signature into the hash table
void insert_signature(const char* signature) {
    unsigned int index = hash_function(signature);
    HashNode* new_node = (HashNode*)malloc(sizeof(HashNode));
    strncpy(new_node->signature, signature, MAX_SIG_LENGTH);
    new_node->next = NULL;

    if (hash_table[index] == NULL) {
        hash_table[index] = new_node;
    }
    else {
        // Handle collision by adding to the linked list
        HashNode* current = hash_table[index];
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_node;
    }
}

// Check if a signature exists in the hash table
int find_signature(const char* signature) {
    unsigned int index = hash_function(signature);
    HashNode* current = hash_table[index];

    while (current != NULL) {
        if (strcmp(current->signature, signature) == 0) {
            return 1; // Found
        }
        current = current->next;
    }
    return 0; // Not found
}

// Function to log messages to scan_log.txt with timestamp
void log_message(const char* message) {
    FILE* log_file = NULL;
    errno_t err = fopen_s(&log_file, "scan_log.txt", "a");
    if (err != 0 || log_file == NULL) {
        printf("Error opening log file! Error code: %d\n", err);
        return;
    }

    time_t now;
    time(&now);
    char timestamp[26];
    ctime_s(timestamp, sizeof(timestamp), &now);
    timestamp[strcspn(timestamp, "\n")] = 0;

    fprintf(log_file, "[%s] %s\n", timestamp, message);
    fclose(log_file);
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT) {
        printf("\nCtrl+C detected. Stopping monitoring...\n");
        log_message("Monitoring stopped by user (Ctrl+C)");
        keep_monitoring = 0;
        return TRUE;
    }
    return FALSE;
}

void load_signatures(const char* sig_file) {
    FILE* file = NULL;
    errno_t err = fopen_s(&file, sig_file, "r");
    if (err != 0 || file == NULL) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Error opening signatures file %s! Error code: %d", sig_file, err);
        printf("%s\n", log_msg);
        log_message(log_msg);
        return;
    }

    char buffer[MAX_SIG_LENGTH];
    while (num_signatures < MAX_SIGNATURES && fgets(buffer, MAX_SIG_LENGTH, file)) {
        buffer[strcspn(buffer, "\n")] = 0;
        if (strlen(buffer) == 64) { // Validate SHA-256 hash length
            insert_signature(buffer);
            num_signatures++;
        }
    }

    fclose(file);
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Loaded %d signatures from %s", num_signatures, sig_file);
    log_message(log_msg);
}

int compute_file_hash(const char* filename, char* hash_str) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Error opening file %s for hash computation!\n", filename);
        return 0;
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        printf("CryptAcquireContext failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 0;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
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

    BYTE hash[32];
    DWORD hashLen = sizeof(hash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        printf("CryptGetHashParam failed: %lu\n", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return 0;
    }

    for (int i = 0; i < hashLen; i++) {
        snprintf(hash_str + (i * 2), 3, "%02x", hash[i]);
    }
    hash_str[64] = 0;

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return 1;
}

int scan_file(const char* filename) {
    char file_hash[MAX_SIG_LENGTH];
    if (!compute_file_hash(filename, file_hash)) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Failed to compute hash for %s", filename);
        printf("%s.\n", log_msg);
        log_message(log_msg);
        return 0;
    }

    if (find_signature(file_hash)) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Threat detected in %s (SHA-256: %s)", filename, file_hash);
        printf("Threat detected in %s (SHA-256: %s)!\n", filename, file_hash);
        log_message(log_msg);
        return 1;
    }

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "No threats found in %s (SHA-256: %s)", filename, file_hash);
    printf("No threats found in %s (SHA-256: %s).\n", filename, file_hash);
    log_message(log_msg);
    return 0;
}

void scan_directory(const char* dir_path) {
    WIN32_FIND_DATAA find_file_data;
    HANDLE hFind;
    char search_path[MAX_PATH];

    snprintf(search_path, MAX_PATH, "%s\\*", dir_path);

    hFind = FindFirstFileA(search_path, &find_file_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Error accessing directory %s", dir_path);
        printf("%s!\n", log_msg);
        log_message(log_msg);
        return;
    }

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Started scanning directory: %s", dir_path);
    log_message(log_msg);

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

    snprintf(log_msg, sizeof(log_msg), "Finished scanning directory: %s", dir_path);
    log_message(log_msg);
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
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Error opening directory %s for monitoring", dir_path);
        printf("%s!\n", log_msg);
        log_message(log_msg);
        return;
    }

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Started monitoring directory: %s", dir_path);
    printf("Monitoring directory: %s (Press Ctrl+C to stop)\n", dir_path);
    log_message(log_msg);

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
                    snprintf(log_msg, sizeof(log_msg), "File %s was %s. Scanning...", filename,
                        pNotify->Action == FILE_ACTION_ADDED ? "created" : "modified");
                    printf("File %s was %s. Scanning...\n", filename,
                        pNotify->Action == FILE_ACTION_ADDED ? "created" : "modified");
                    log_message(log_msg);
                    scan_file(full_path);
                }

                if (pNotify->NextEntryOffset == 0) break;
                pNotify = (FILE_NOTIFY_INFORMATION*)((char*)pNotify + pNotify->NextEntryOffset);
            } while (1);
        }
    }

    CloseHandle(hDir);
    snprintf(log_msg, sizeof(log_msg), "Monitoring stopped for directory: %s", dir_path);
    printf("Monitoring stopped.\n");
    log_message(log_msg);
}