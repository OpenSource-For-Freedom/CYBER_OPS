// adding whitelist and trying to increase false positive prevention while scanning and loads
// this file has the gui and deeper scan/ log capability for deploying action vs just scanning
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
#include <time.h>


void print_ascii_banner() {
    printf("\n"
           "  @@@       @@@@@@@@   @@@@@@@@  @@@   @@@@@@   @@@  @@@  \n"
           "  @@@       @@@@@@@@  @@@@@@@@@  @@@  @@@@@@@@  @@@@ @@@  \n"
           "  @@!       @@!       !@@        @@!  @@!  @@@  @@!@!@@@  \n"
           "  !@!       !@!       !@!        !@!  !@!  @!@  !@!!@!@!  \n"
           "  @!!       @!!!:!    !@! @!@!@  !!@  @!@  !@!  @!@ !!@!  \n"
           "  !!!       !!!!!:    !!! !!@!!  !!!  !@!  !!!  !@!  !!!  \n"
           "  !!:       !!:       :!!   !!:  !!:  !!:  !!!  !!:  !!!  \n"
           "   :!:      :!:       :!:   !::  :!:  :!:  !:!  :!:  !:!  \n"
           "  :: ::::   :: ::::   ::: ::::   ::  ::::: ::   ::   ::  \n"
           " : :: : :  : :: ::    :: :: :   :     : :  :   ::    :   \n"
           "\n"
           "---------------------------------------------------------\n"
           "   Legion - Linux Threat Scanner | Version 1.0 \n"
           "---------------------------------------------------------\n"
           "\n");
}

#define MAX_SIGNATURES 100
#define EVENT_SIZE (sizeof(struct inotify_event) + 256)
#define BUFFER_LEN (1024 * EVENT_SIZE)
#define LOG_FILE "/var/log/legion_scan.log"
#define WHITELIST_FILE "/etc/legion/whitelist.txt"
#define YARA_RULES_FILE "/etc/legion/rules.yar"
#define UPDATE_SCRIPT "/usr/local/bin/update_signatures.sh"

char *signatures[MAX_SIGNATURES];
int signature_count = 0;

// this just detects and logs 
void log_detection(const char *message) {
    FILE *logfile = fopen(LOG_FILE, "a");
    if (!logfile) {
        perror("Error opening log file");
        return;
    }
    time_t now = time(NULL);
    fprintf(logfile, "[%s] %s\n", ctime(&now), message);
    fclose(logfile);
}

// make sure sec tools are installed 
void check_dependencies() {
    const char *tools[] = {"clamdscan", "suricata", "yara", NULL};
    for (int i = 0; tools[i] != NULL; i++) {
        char command[256];
        snprintf(command, sizeof(command), "command -v %s >/dev/null 2>&1", tools[i]);
        if (system(command) != 0) {
            printf("[ERROR] %s is not installed. Please install it.\n", tools[i]);
            exit(1);
        }
    }
}

// keeps bad file signatures updated based on outbound resources 
void update_signatures() {
    printf("[INFO] Updating malware signatures...\n");
    int status = system(UPDATE_SCRIPT);
    if (status == 0) {
        printf("[SUCCESS] Signatures updated successfully.\n");
    } else {
        printf("[ERROR] Failed to update signatures.\n");
    }
}

// checks if a file is whitelisted
int is_whitelisted(const char *filename) {
    FILE *whitelist = fopen(WHITELIST_FILE, "r");
    if (!whitelist) {
        return 0;  // No whitelist available, assume not whitelisted
    }

    char line[256];
    int whitelisted = 0;
    while (fgets(line, sizeof(line), whitelist)) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, filename) == 0) {
            whitelisted = 1;
            break;
        }
    }
    fclose(whitelist);
    return whitelisted;
}

// loads malware stuff for scanning with error handling 
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

// computes sha encryption for scanning 
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

// YARA
void scan_with_yara(const char *filename, int *score) {
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
    if (yr_scanner_scan_file(scanner, filename) != 0) {
        printf("[YARA] Potential malware found in %s\n", filename);
        log_detection("[YARA DETECTION] Potential malware found.");
        (*score)++;  // Increase score for suspicious activity
    }

    yr_scanner_destroy(scanner);
    yr_rules_destroy(rules);
    yr_finalize();
}

//  Zenity gui
void show_alert(const char *filename, const char *filetype) {
    char command[512];
    snprintf(command, sizeof(command),
        "zenity --warning --title='Legion Alert' --text='Suspicious file detected!\\n\\nFile: %s\\nType: %s\\n\\nChoose an action:' --ok-label='Quarantine' --extra-button='Delete' --extra-button='Ignore'",
        filename, filetype);
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("Failed to run Zenity");
        return;
    }

    char response[128];
    fgets(response, sizeof(response), fp);
    pclose(fp);

    if (strstr(response, "Quarantine")) {
        snprintf(command, sizeof(command), "mv %s /var/lib/legion/quarantine/", filename);
        system(command);
        log_detection("[ACTION] File quarantined.");
    } else if (strstr(response, "Delete")) {
        snprintf(command, sizeof(command), "rm -f %s", filename);
        system(command);
        log_detection("[ACTION] File deleted.");
    } else {
        log_detection("[ACTION] User ignored the alert.");
    }
}

// watches for directory changes and monitors 
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

                if (is_whitelisted(event->name)) {
                    printf("[INFO] %s is whitelisted, skipping scan.\n", event->name);
                } else {
                    int score = 0;
                    scan_with_yara(event->name, &score);
                    
                    if (score > 0) { // Only alert if score is high enough
                        show_alert(event->name, "Unknown Type");
                    }
                }
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

    check_dependencies();
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
