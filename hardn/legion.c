#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <sys/inotify.h>
#include <libyara.h>

#define MAX_SIGNATURES 100
#define EVENT_SIZE (sizeof(struct inotify_event) + 256)
#define BUFFER_LEN (1024 * EVENT_SIZE)
#define LOG_FILE "/var/log/legion_scan.log"
#define YARA_RULES_FILE "rules.yar"
#define UPDATE_SCRIPT "./update_signatures.sh"

char *signatures[MAX_SIGNATURES];
int signature_count = 0;

// logs for Suricata, OSSEC, Wazuh
void log_detection(const char *message) {
    FILE *logfile = fopen(LOG_FILE, "a");
    if (!logfile) {
        perror("Error opening log file");
        return;
    }
    fprintf(logfile, "%s\n", message);
    fclose(logfile);
}

// update malware signatures
void update_signatures() {
    printf("[INFO] Updating malware signatures...\n");
    int status = system(UPDATE_SCRIPT);
    if (status == 0) {
        printf("[SUCCESS] Signatures updated successfully.\n");
    } else {
        printf("[ERROR] Failed to update signatures.\n");
    }
}

// load malware signatures from local file
void load_signatures(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening signatures file");
        exit(1);
    }

    char line[256];
    while (fgets(line, sizeof(line), file) && signature_count < MAX_SIGNATURES) {
        line[strcspn(line, "\n")] = '\0';
        signatures[signature_count] = strdup(line);
        signature_count++;
    }
    fclose(file);
}

// SHA-256 hash file computation 
void compute_sha256(const char *filename, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file for hashing");
        strcpy(output, "ERROR");
        return;
    }

    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }
    fclose(file);

    SHA256_Final(hash, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
}

// YARA rules
void scan_with_yara(const char *filename) {
    YR_RULES *rules;
    YR_COMPILER *compiler;
    YR_SCANNER *scanner;

    yr_initialize();
    yr_compiler_create(&compiler);
    FILE *rules_file = fopen(YARA_RULES_FILE, "r");

    if (!rules_file) {
        perror("Error opening YARA rules file");
        yr_finalize();
        return;
    }

    yr_compiler_add_file(compiler, rules_file, NULL, NULL);
    fclose(rules_file);
    yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);

    yr_scanner_create(rules, &scanner);
    if (yr_scanner_scan_file(scanner, filename) == 0) {
        printf("[YARA] No threats detected in %s\n", filename);
    } else {
        printf("[YARA] Potential malware found in %s\n", filename);
        log_detection("[YARA DETECTION] Potential malware found.");
    }

    yr_scanner_destroy(scanner);
    yr_rules_destroy(rules);
    yr_finalize();
}

// file for signatures + malware hashes. 
void *scan_file(void *arg) {
    char *filename = (char *)arg;
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Error opening file");
        pthread_exit(NULL);
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        perror("Error getting file size");
        close(fd);
        pthread_exit(NULL);
    }

    if (sb.st_size == 0) {
        printf("[EMPTY] %s\n", filename);
        close(fd);
        pthread_exit(NULL);
    }

    char *file_data = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_data == MAP_FAILED) {
        perror("Error mapping file");
        close(fd);
        pthread_exit(NULL);
    }

    int infected = 0;
    for (int i = 0; i < signature_count; i++) {
        if (memmem(file_data, sb.st_size, signatures[i], strlen(signatures[i]))) {
            printf("[INFECTED] %s contains malware signature: %s\n", filename, signatures[i]);
            log_detection("[SIGNATURE MATCH] Malware detected.");
            infected = 1;
            break;
        }
    }

    char file_hash[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
    compute_sha256(filename, file_hash);
    if (strcmp(file_hash, "ERROR") != 0) {
        printf("[HASH] %s SHA-256: %s\n", filename, file_hash);
        log_detection("[HASH DETECTION] File hash detected.");
    }

    scan_with_yara(filename);

    munmap(file_data, sb.st_size);
    close(fd);

    if (!infected) {
        printf("[CLEAN] %s is safe.\n", filename);
    }

    pthread_exit(NULL);
}

// monitor directory in real time 
void *monitor_directory(void *arg) {
    char *dir = (char *)arg;
    int inotify_fd = inotify_init();
    if (inotify_fd < 0) {
        perror("Error initializing inotify");
        return NULL;
    }

    int wd = inotify_add_watch(inotify_fd, dir, IN_CREATE | IN_MODIFY);
    if (wd < 0) {
        perror("Error adding watch");
        close(inotify_fd);
        return NULL;
    }

    char buffer[BUFFER_LEN];
    while (1) {
        int length = read(inotify_fd, buffer, BUFFER_LEN);
        if (length < 0) {
            perror("Error reading inotify events");
            continue;
        }

        for (int i = 0; i < length;) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len && (event->mask & (IN_CREATE | IN_MODIFY))) {
                printf("[REAL-TIME] Detected change in %s, scanning...\n", event->name);
                scan_file(event->name);
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(inotify_fd, wd);
    close(inotify_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <signatures_file> <directory_to_monitor>\n", argv[0]);
        return 1;
    }

    update_signatures();
    load_signatures(argv[1]);

    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, monitor_directory, argv[2]) != 0) {
        perror("Error creating monitoring thread");
        return 1;
    }

    pthread_join(monitor_thread, NULL);
    return 0;
}