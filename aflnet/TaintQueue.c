#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <fn> <out_dir> <config_file> [debug]\n", argv[0]);
        return 1;
    }

    char* fn = argv[1];
    char* out_dir = argv[2];
    const char* config_file = argv[3];
    int debug = (argc >= 5) ? atoi(argv[4]) : 0;

    char out_dir_copy[PATH_MAX];
    strncpy(out_dir_copy, out_dir, sizeof(out_dir_copy) - 1);
    out_dir_copy[sizeof(out_dir_copy) - 1] = '\0';

    char* dir_path = dirname(out_dir_copy);

    if (chdir(dir_path) != 0) {
        perror("chdir failed");
        return 1;
    }

    initialize_queue(fn, out_dir, config_file, debug);

    printf("initialize_queue completed successfully.\n");
    return 0;
}
