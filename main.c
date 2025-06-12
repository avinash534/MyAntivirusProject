#include <stdio.h>

// Declare functions and variables from file_handling.c
extern char signatures[10][50]; // Matches MAX_SIGNATURES and MAX_SIG_LENGTH
extern int num_signatures;
void load_signatures(const char* sig_file);
void scan_directory(const char* dir_path);

int main() {
    load_signatures("signatures.txt");
    printf("Loaded %d signatures.\n", num_signatures);

    const char* directory = "C:\\Test";
    printf("Scanning directory: %s\n", directory);
    scan_directory(directory);
    return 0;
}