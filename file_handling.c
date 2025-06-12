#include <stdio.h>
#include <string.h>
#include <windows.h>

#define MAX_SIGNATURES 10
#define MAX_SIG_LENGTH 50

char signatures[MAX_SIGNATURES][MAX_SIG_LENGTH];
int num_signatures = 0;

void load_signatures(const char* sig_file) {
    FILE* file = fopen(sig_file, "r");
    if (file == NULL) {
        printf("Error opening signatures file %s!\n", sig_file);
        return;
    }

    while (num_signatures < MAX_SIGNATURES && fgets(signatures[num_signatures], MAX_SIG_LENGTH, file)) {
        signatures[num_signatures][strcspn(signatures[num_signatures], "\n")] = 0;
        num_signatures++;
    }

    fclose(file);
}

int scan_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error opening file %s!\n", filename);
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
    WIN32_FIND_DATAA find_file_data; // Use WIN32_FIND_DATAA for ANSI
    HANDLE hFind;
    char search_path[MAX_PATH];

    snprintf(search_path, MAX_PATH, "%s\\*", dir_path);

    hFind = FindFirstFileA(search_path, &find_file_data); // Use FindFirstFileA
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
    } while (FindNextFileA(hFind, &find_file_data) != 0); // Use FindNextFileA

    FindClose(hFind);
}