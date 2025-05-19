#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "../aflnet/aflnet.h"
#include "../aflnet/alloc-inl.h"

#define RETRY_DELAY 2

char *debug_dir = NULL;

void recursive_remove(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) {
        perror("Error opening directory");
        exit(2);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat stat_buf;
        if (stat(full_path, &stat_buf) == 0) {
            if (S_ISDIR(stat_buf.st_mode)) {
                recursive_remove(full_path);
            } else {
                if (remove(full_path) != 0) {
                    perror("Error removing file");
                    exit(2);
                }
            }
        }
    }
    closedir(dir);

    if (rmdir(path) != 0) {
        perror("Error removing directory");
        exit(2);
    }
}

void create_debug_dir() {
    if (access(debug_dir, F_OK) == 0) {
        recursive_remove(debug_dir);
    }

    if (mkdir(debug_dir, 0777) != 0) {
        perror("Error creating debug directory");
        exit(2);
    }
}

double calculate_new_average(const char *file_path, double new_avg, int new_count) {
    FILE *file = fopen(file_path, "r");
    if (!file) {
        return new_avg;
    }

    double existing_avg = 0;
    int existing_count = 0;

    if (fscanf(file, "%lf %d", &existing_avg, &existing_count) != 2) {
        fprintf(stderr, "Error reading from %s. Overwriting with new data.\n", file_path);
        fclose(file);
        return new_avg;
    }
    fclose(file);

    int total_count = existing_count + new_count;
    return ((existing_avg * existing_count) + (new_avg * new_count)) / total_count;
}

void write_avg_response_time(double avg, int count) {
    char avg_file_path[256];
    snprintf(avg_file_path, sizeof(avg_file_path), "%s/avg_response_time", debug_dir);
    double final_avg = calculate_new_average(avg_file_path, avg, count);

    FILE *file = fopen(avg_file_path, "w");
    if (!file) {
        perror("Error opening avg_response_time file");
        exit(2);
    }

    fprintf(file, "%lf %d\n", final_avg, count);
    fclose(file);
}

void write_debug_files(int request_id, const char *request, unsigned int request_len, const char *response, unsigned int response_len) {
    char dir_name[256];
    snprintf(dir_name, sizeof(dir_name), "%s/%d", debug_dir, request_id);
    mkdir(dir_name, 0777);

    char send_request_file[256];
    snprintf(send_request_file, sizeof(send_request_file), "%s/send_request", dir_name);
    FILE *send_file = fopen(send_request_file, "wb");
    if (!send_file) {
        perror("Error opening send_request file");
        exit(2);
    }
    fwrite(request, 1, request_len, send_file);
    fclose(send_file);

    if (response && response_len) {
        char received_response_file[256];
        snprintf(received_response_file, sizeof(received_response_file), "%s/received_response", dir_name);
        FILE *response_file = fopen(received_response_file, "wb");
        if (!response_file) {
            perror("Error opening received_response file");
            exit(2);
        }
        fwrite(response, 1, response_len, response_file);
        fclose(response_file);
    }
}


int main(int argc, char *argv[]) {
    int debug_mode = 0;
    char *send_next_region;

    char *region_delimiter = getenv("REGION_DELIMITER");
    if (region_delimiter == NULL) {
        fprintf(stderr, "Error: REGION_DELIMITER environment variable is not set.\n");
        exit(1);
    }

    printf("REGION_DELIMITER: ");
    for (size_t i = 0; i < strlen(region_delimiter); i++) {
        unsigned char byte = (unsigned char)region_delimiter[i];
        printf("\\x%02X", byte);
    }
    printf("\n");

    char *env_var = getenv("DEBUG_FUZZ");
    if (env_var) {
        debug_mode = atoi(env_var);
    }

    env_var = getenv("DEBUG");
    if (env_var) {
        debug_mode = atoi(env_var);
    }

    env_var = getenv("DEBUG_DIR");
    if (env_var) {
        debug_dir = env_var;
    }

    if (debug_mode) {
        if (access("debug", F_OK) == 0)
            system("rm -r debug > /dev/null 2>&1");
        mkdir("debug", 0777);
    }

    if (argc != 6 && !debug_mode) {
        fprintf(stderr, "Usage: %s <requests_file> <log_file_path> <server_ip> <server_port> <timeout_sec>\n", argv[0]);
        exit(2);
    }

    char *requests_file = argv[1];
    char *log_file_path = argv[2];
    char *server_ip = argv[3];
    int server_port = atoi(argv[4]);
    int timeout_sec = atoi(argv[5]);

    if (debug_mode) {
        create_debug_dir();
    }

    FILE *file = fopen(requests_file, "r");
    if (!file) {
        perror("Error opening requests file");
        exit(2);
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    char *requests = malloc(file_size + 1);
    if (!requests) {
        perror("Error allocating memory for requests");
        fclose(file);
        exit(2);
    }

    fread(requests, 1, file_size, file);
    fclose(file);
    requests[file_size] = '\0';

    printf("Loaded %ld bytes of requests from file.\n", file_size);

    int shm_fd = shm_open(SEND_NEXT_REGION, O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        exit(EXIT_FAILURE);
    }

    if (ftruncate(shm_fd, sizeof(char)) == -1) {
        perror("ftruncate");
        exit(EXIT_FAILURE);
    }

    send_next_region = mmap(NULL, sizeof(char), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (send_next_region == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    *send_next_region = 0;
    printf("send_next_region initialized to: %d\n", *send_next_region);

    close(shm_fd);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        free(requests);
        exit(2);
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(server_port),
    };

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        close(sockfd);
        free(requests);
        exit(2);
    }

    printf("Connecting to %s:%d...\n", server_ip, server_port);
    int connected = 0;
    while (!connected) {
        if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Error connecting to server");
            sleep(RETRY_DELAY);
        } else {
            connected = 1;
        }
    }
    printf("Connection established.\n");

    struct timeval timeout = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    char *current_request = requests;
    size_t remaining_len = file_size;
    int request_id = 0;
    double total_response_time = 0;
    int total_requests = 0;

    while (remaining_len > 0) {
        struct timespec start_time, end_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);

        size_t delim_len = strlen(region_delimiter);
        char *next_request = memmem(current_request, remaining_len, region_delimiter, delim_len);
        size_t request_len = next_request ? (size_t)(next_request - current_request) : remaining_len;

        printf("LEN_: %zu\n", request_len);

        *send_next_region = 1;
        usleep(500000);

        printf("Sending request %d (%zu bytes)\n", request_id, request_len);
        int res = 0;
        char *response_buf = NULL;
        unsigned int response_len = 0;

retry:
        res = net_send(sockfd, timeout, current_request, request_len);
        if (res <= 0) {
            fprintf(stderr, "Error sending request\n");
            close(sockfd);
            exit(2);
        }

        printf("Sent request %d (%d bytes)\n", request_id, res);

        if (debug_mode) {
            write_debug_files(request_id, current_request, request_len, NULL, 0);
        }

        res = net_recv(sockfd, timeout, &response_buf, &response_len, HTTP);
        if (res == 0 || res == 1) {
            clock_gettime(CLOCK_MONOTONIC, &end_time);
            double response_time_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                                    (end_time.tv_nsec - start_time.tv_nsec) / 1e6;

            total_response_time += response_time_ms;
            total_requests++;

            printf("Response time for request %d (%u bytes) (res = %d, errno = %d): %lf ms 0x%lx\n", request_id, response_len, res, errno, response_time_ms, (unsigned long)response_buf);

            if (debug_mode) {
                write_debug_files(request_id, current_request, request_len, response_buf, response_len);
            }

            ck_free(response_buf);
        } else if (res == 2) {
            fprintf(stderr, "Timeout!\n");
        }

        if (res == 1 || res == 3) {
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd < 0) {
                perror("Error creating socket");
                sleep(RETRY_DELAY);
                continue;
            }

            printf("Connecting to %s:%d...\n", server_ip, server_port);
            int reconnected = 0;
            while (!reconnected) {
                if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                    perror("Error connecting to server");
                    sleep(RETRY_DELAY);
                } else {
                    reconnected = 1;
                }
            }
            printf("Connection re-established.\n");

            if (res == 3) goto retry;
        }

        if (next_request) {
            size_t consumed = (next_request - current_request) + delim_len;
            current_request += consumed;
            remaining_len -= consumed;
        } else {
            break;
        }

        request_id++;
    }

    if (debug_mode && total_requests > 0) {
        double avg_response_time_ms = total_response_time / total_requests;
        printf("Average response time: %lf ms\n", avg_response_time_ms);
        write_avg_response_time(avg_response_time_ms, total_requests);
    }

    close(sockfd);
    free(requests);

    return 0;
}