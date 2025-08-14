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
#include <errno.h>
#include <arpa/inet.h>
#include "../aflnet/aflnet.h"
#include "../aflnet/alloc-inl.h"

#define RETRY_DELAY 2

char *debug_dir = NULL;

void recursive_remove(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;

        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        struct stat stat_buf;
        if (stat(full_path, &stat_buf) == 0) {
            if (S_ISDIR(stat_buf.st_mode)) {
                recursive_remove(full_path);
            } else {
                remove(full_path);
            }
        }
    }
    closedir(dir);
    rmdir(path);
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
    if (!file) return new_avg;

    double existing_avg = 0;
    int existing_count = 0;
    if (fscanf(file, "%lf %d", &existing_avg, &existing_count) != 2) {
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
    fwrite(request, 1, request_len, send_file);
    fclose(send_file);

    if (response && response_len) {
        char received_response_file[256];
        snprintf(received_response_file, sizeof(received_response_file), "%s/received_response", dir_name);
        FILE *response_file = fopen(received_response_file, "wb");
        fwrite(response, 1, response_len, response_file);
        fclose(response_file);
    }
}

void print_request(const char *data, size_t len) {
    printf("\n======= REQUEST BEGIN =======\n");
    fwrite(data, 1, len, stdout);
    printf("\n======= REQUEST END   =======\n\n");
}

int main(int argc, char *argv[]) {
    int debug_mode = 0, manual_mode = 0, num_attempts = -1;
    char *send_next_region;

    char *region_delimiter = getenv("REGION_DELIMITER");
    if (!region_delimiter) {
        fprintf(stderr, "Error: REGION_DELIMITER not set.\n");
        exit(1);
    }

    printf("REGION_DELIMITER: ");
    for (size_t i = 0; i < strlen(region_delimiter); i++)
        printf("\\x%02X", (unsigned char)region_delimiter[i]);
    printf("\n");

    char *env_var = getenv("DEBUG_FUZZ");
    if (env_var) debug_mode = atoi(env_var);

    env_var = getenv("DEBUG");
    if (env_var) debug_mode = atoi(env_var);

    env_var = getenv("DEBUG_DIR");
    if (env_var) debug_dir = env_var;
    else debug_mode = 0;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--manual") || !strcmp(argv[i], "--interactive"))
            manual_mode = 1;
    }

    if (debug_mode && access("debug", F_OK) == 0)
        system("rm -r debug > /dev/null 2>&1");
    if (debug_mode)
        mkdir("debug", 0777);

    if (argc < 5) {
        fprintf(stderr, "Usage: %s <requests_file> <server_ip> <server_port> <timeout_sec> [num_attempts] [--manual]\n", argv[0]);
        exit(2);
    }

    char *requests_file = argv[1];
    char *server_ip = argv[2];
    int server_port = atoi(argv[3]);
    int timeout_sec = atoi(argv[4]);
    if (argc >= 6 && argv[5][0] != '-') {
        num_attempts = atoi(argv[5]);
        if (num_attempts <= 0) num_attempts = -1;
    }
    if (debug_mode) create_debug_dir();

    FILE *file = fopen(requests_file, "rb");
    if (!file) {
        perror("Error opening requests file");
        exit(2);
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    char *requests = malloc(file_size + 1);
    fread(requests, 1, file_size, file);
    fclose(file);
    requests[file_size] = '\0';

    printf("Loaded %ld bytes of requests from file.\n", file_size);

    int shm_fd = shm_open(SEND_NEXT_REGION, O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
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
        exit(2);
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(server_port),
    };

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP");
        exit(2);
    }
    
    int attempt = 0;
    while (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to server");
        attempt++;
        if (num_attempts != -1 && attempt >= num_attempts) {
            fprintf(stderr, "Reached maximum connection attempts (%d). Exiting.\n", num_attempts);
            exit(2);
        }
        sleep(RETRY_DELAY);
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
        int retry_times = 0;
        if (manual_mode) {
            printf("[Press Enter to send next request, or 'q' + Enter to quit]: ");
            char input_buf[8];
            if (!fgets(input_buf, sizeof(input_buf), stdin) || input_buf[0] == 'q') {
                printf("Manual replay aborted by user.\n");
                break;
            }
        }

        size_t delim_len = strlen(region_delimiter);
        char *next_request = memmem(current_request, remaining_len, region_delimiter, delim_len);
        size_t request_len = next_request ? (size_t)(next_request - current_request) : remaining_len;

        print_request(current_request, request_len);
        *send_next_region = 1;
        usleep(500000);

        printf("Sending request %d (%zu bytes)\n", request_id, request_len);
        int res = 0;
        char *response_buf = NULL;
        unsigned int response_len = 0;

        struct timespec start_time, end_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);

retry:
        res = net_send(sockfd, timeout, current_request, request_len);
        if (res <= 0) {
            fprintf(stderr, "Error sending request\n");
            close(sockfd);
            exit(2);
        }

        if (debug_mode)
            write_debug_files(request_id, current_request, request_len, NULL, 0);

        res = net_recv(sockfd, timeout, &response_buf, &response_len, HTTP);
        clock_gettime(CLOCK_MONOTONIC, &end_time);

        if (res == 0 || res == 1) {
            double response_time_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 +
                                      (end_time.tv_nsec - start_time.tv_nsec) / 1e6;

            total_response_time += response_time_ms;
            total_requests++;

            printf("Response time for request %d: %lf ms (%u bytes)\n", request_id, response_time_ms, response_len);

            if (debug_mode)
                write_debug_files(request_id, current_request, request_len, response_buf, response_len);

            ck_free(response_buf);
        } else if (res == 2) {
            fprintf(stderr, "Timeout!\n");
        }

        if ((res == 1 || res == 3) && retry_times < 2) {
            retry_times++;
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd < 0) {
                perror("Error recreating socket");
                break;
            }

            int reconnected = 0;
            int reconnect_attempt = 0;
            while (num_attempts == -1 || reconnect_attempt < num_attempts) {
                if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
                    reconnected = 1;
                    break;
                }
                perror("Reconnecting...");
                reconnect_attempt++;
                sleep(RETRY_DELAY);
            }

            if (!reconnected) {
                fprintf(stderr, "Failed to reconnect after %d attempts. Skipping request.\n",
                        num_attempts == -1 ? reconnect_attempt : num_attempts);
                break;
            }

            printf("Reconnected.\n");
            sleep(1);
            
            if (res == 3)
                goto retry;
        } else if (retry_times >= 2) {
            fprintf(stderr, "Request %d failed after 2 retries. Skipping to next.\n", request_id);
        }

        if (next_request) {
            size_t consumed = (next_request - current_request) + delim_len;
            current_request += consumed;
            remaining_len -= consumed;
        } else break;

        request_id++;
    }

    if (debug_mode && total_requests > 0) {
        double avg_response_time = total_response_time / total_requests;
        printf("Average response time: %lf ms\n", avg_response_time);
        write_avg_response_time(avg_response_time, total_requests);
    }

    close(sockfd);
    free(requests);
    return 0;
}
