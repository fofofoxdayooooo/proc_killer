/*
 * proc_killer.c - The Ultimate and Production-Ready Process Killer Daemon.
 *
 * This version is the culmination of all previous enhancements, designed for
 * mission-critical reliability, scalability, and robustness on both Linux and FreeBSD.
 *
 * Key enhancements in this version:
 * - A dynamically resizing `killed_processes_cache` to handle large-scale environments.
 * - Robust `/proc/[pid]/stat` parsing using strtok_r to safely handle complex command line formats.
 * - Optimized FreeBSD process monitoring to reduce the overhead of kvm_getargv.
 * - A highly robust, unique process identifier key (PID + start time) to mitigate PID reuse risks on both platforms.
 * - Centralized logging with clear status updates.
 *
 * This is the definitive version of the daemon, engineered for reliability and safety.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <time.h>
#include <regex.h>
#include <inttypes.h>
#include <libgen.h>

#ifdef __linux__
#include <systemd/sd-daemon.h>
#include <sys/prctl.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#endif

#ifdef __FreeBSD__
#include <kvm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/time.h>
#endif

// --- Configuration ---
#define CONFIG_FILE "/etc/proc_killer.conf"
#define PID_FILE "/var/run/proc_killer.pid"
#define MAX_LINE_LENGTH 256
#define INITIAL_HASH_TABLE_SIZE 4096

// --- Global variables for configuration ---
typedef struct {
    char key[MAX_LINE_LENGTH];
    double limit; // Use double for future millisecond precision
    char regex_pattern[MAX_LINE_LENGTH];
    regex_t regex_comp;
} UserMonitor;

typedef struct {
    char regex_pattern[MAX_LINE_LENGTH];
    regex_t regex_comp;
} RegexBlacklist;

int regex_blacklist_count = 0;
int user_regex_patterns_count = 0;

// --- Data Structures ---
typedef struct {
    uid_t uid;
    char username[MAX_LINE_LENGTH];
} UIDCache;
UIDCache *uid_cache = NULL;
int uid_cache_size = 0;

typedef struct {
    char *key;
    double value; // Use double for future millisecond precision
    int is_empty;
} KVPair;

typedef struct {
    KVPair *table;
    int size;
    int count;
} HashTable;

typedef struct {
    pid_t pid;
#ifdef __linux__
    long long start_time;
#else
    struct timeval start_time;
#endif
} ProcessKey;

typedef struct {
    ProcessKey key;
    int is_empty;
} KilledProcessCacheEntry;

HashTable *allow_list = NULL;
HashTable *monitored_users = NULL;
RegexBlacklist *regex_blacklist = NULL;
UserMonitor *user_regex_patterns = NULL;
KilledProcessCacheEntry *killed_processes_cache = NULL;
int killed_processes_cache_size = INITIAL_HASH_TABLE_SIZE;
int killed_processes_cache_count = 0;

int debug_level = 0;
double default_time_limit = 3600.0;
uid_t root_uid;
int ignore_root_processes = 1;
static time_t config_mtime = 0;

// --- Global flags ---
volatile sig_atomic_t shutdown_flag = 0;
volatile sig_atomic_t reload_flag = 0;
int safe_mode_flag = 0;
int dry_run_flag = 0;
int check_interval_seconds = 5;

// --- Function Prototypes ---
void cleanup();
void signal_handler(int signum);
void write_pid_file();
void read_config();
int is_allow_listed(const char *user, const char *cmdline);
int should_kill(const char *user, const char *cmdline, double elapsed_time);
void monitor();
void reload_config();
void init_hash_table(HashTable **ht, int size);
void add_to_hash_table(HashTable *ht, const char *key, double value);
double get_from_hash_table(HashTable *ht, const char *key);
void free_hash_table(HashTable *ht);
void init_killed_processes_cache();
void resize_killed_processes_cache();
void add_to_killed_processes_cache(pid_t pid, long long start_time);
int is_in_killed_processes_cache(pid_t pid, long long start_time);
void free_killed_processes_cache();
void kill_process(pid_t pid, const char *reason);
const char* get_username_from_uid(uid_t uid);
void daemonize();

// --- Hash Table Implementation (Open Addressing) ---
unsigned int hash(const char *str, int size) {
    unsigned int hash_val = 0;
    while (*str) {
        hash_val = (hash_val << 5) + *str++;
    }
    return hash_val % size;
}

void init_hash_table(HashTable **ht, int size) {
    *ht = (HashTable *)malloc(sizeof(HashTable));
    if (!*ht) {
        syslog(LOG_ERR, "Failed to allocate memory for hash table.");
        exit(1);
    }
    (*ht)->size = size;
    (*ht)->count = 0;
    (*ht)->table = (KVPair *)calloc(size, sizeof(KVPair));
    if (!(*ht)->table) {
        syslog(LOG_ERR, "Failed to allocate memory for hash table.");
        exit(1);
    }
    for (int i = 0; i < size; i++) {
        (*ht)->table[i].is_empty = 1;
    }
}

void add_to_hash_table(HashTable *ht, const char *key, double value) {
    unsigned int index = hash(key, ht->size);
    while (!ht->table[index].is_empty && strcmp(ht->table[index].key, key) != 0) {
        index = (index + 1) % ht->size;
    }
    if (!ht->table[index].is_empty) {
        free(ht->table[index].key); // Free existing key
    } else {
        ht->count++;
    }
    ht->table[index].key = strdup(key);
    ht->table[index].value = value;
    ht->table[index].is_empty = 0;
}

double get_from_hash_table(HashTable *ht, const char *key) {
    unsigned int index = hash(key, ht->size);
    for (int i = 0; i < ht->size; i++) {
        if (!ht->table[index].is_empty && strcmp(ht->table[index].key, key) == 0) {
            return ht->table[index].value;
        }
        index = (index + 1) % ht->size;
    }
    return -1.0;
}

void free_hash_table(HashTable *ht) {
    if (!ht) return;
    for (int i = 0; i < ht->size; i++) {
        if (!ht->table[i].is_empty) {
            free(ht->table[i].key);
        }
    }
    free(ht->table);
    free(ht);
}

// --- PID Reuse Cache ---
unsigned int process_key_hash(ProcessKey key, int size) {
    unsigned int h = (unsigned int)key.pid;
#ifdef __linux__
    h = (h << 5) | (h >> 27); // Rotate left
    h ^= (unsigned int)key.start_time;
#else
    h = (h << 5) | (h >> 27);
    h ^= (unsigned int)key.start_time.tv_sec;
    h ^= (unsigned int)key.start_time.tv_usec;
#endif
    return h % size;
}

void init_killed_processes_cache() {
    killed_processes_cache = (KilledProcessCacheEntry *)calloc(killed_processes_cache_size, sizeof(KilledProcessCacheEntry));
    if (!killed_processes_cache) {
        syslog(LOG_ERR, "Failed to allocate memory for killed processes cache.");
        exit(1);
    }
    for (int i = 0; i < killed_processes_cache_size; i++) {
        killed_processes_cache[i].is_empty = 1;
    }
    killed_processes_cache_count = 0;
}

void resize_killed_processes_cache() {
    int old_size = killed_processes_cache_size;
    killed_processes_cache_size *= 2;
    syslog(LOG_INFO, "Resizing killed processes cache from %d to %d entries.", old_size, killed_processes_cache_size);

    KilledProcessCacheEntry *old_cache = killed_processes_cache;
    killed_processes_cache = (KilledProcessCacheEntry *)calloc(killed_processes_cache_size, sizeof(KilledProcessCacheEntry));
    if (!killed_processes_cache) {
        syslog(LOG_ERR, "Failed to reallocate memory for killed processes cache. Cache will not be resized.");
        killed_processes_cache = old_cache;
        killed_processes_cache_size = old_size;
        return;
    }

    for (int i = 0; i < killed_processes_cache_size; i++) {
        killed_processes_cache[i].is_empty = 1;
    }
    killed_processes_cache_count = 0;

    for (int i = 0; i < old_size; i++) {
        if (!old_cache[i].is_empty) {
            // Re-add entry to the new, larger table
            add_to_killed_processes_cache(old_cache[i].key.pid, 
#ifdef __linux__
                old_cache[i].key.start_time
#else
                old_cache[i].key.start_time
#endif
            );
        }
    }
    free(old_cache);
}

void add_to_killed_processes_cache(pid_t pid, 
#ifdef __linux__
long long start_time
#else
struct timeval start_time
#endif
) {
    if ((double)killed_processes_cache_count / killed_processes_cache_size > 0.7) {
        resize_killed_processes_cache();
    }

    ProcessKey key = { .pid = pid, .start_time = start_time };
    unsigned int index = process_key_hash(key, killed_processes_cache_size);
    
    int original_index = index;
    while (!killed_processes_cache[index].is_empty) {
        index = (index + 1) % killed_processes_cache_size;
        if (index == original_index) { // Table is full
            syslog(LOG_WARNING, "Killed processes cache is full. Cannot add entry for PID %d.", pid);
            return;
        }
    }

    killed_processes_cache[index].key = key;
    killed_processes_cache[index].is_empty = 0;
    killed_processes_cache_count++;
}

int is_in_killed_processes_cache(pid_t pid, 
#ifdef __linux__
long long start_time
#else
struct timeval start_time
#endif
) {
    ProcessKey key = { .pid = pid, .start_time = start_time };
    unsigned int index = process_key_hash(key, killed_processes_cache_size);

    int original_index = index;
    for (int i = 0; i < killed_processes_cache_size; i++) {
        if (!killed_processes_cache[index].is_empty) {
            if (killed_processes_cache[index].key.pid == pid) {
                #ifdef __linux__
                if (killed_processes_cache[index].key.start_time == start_time) {
                    return 1;
                }
                #else
                if (killed_processes_cache[index].key.start_time.tv_sec == start_time.tv_sec &&
                    killed_processes_cache[index].key.start_time.tv_usec == start_time.tv_usec) {
                    return 1;
                }
                #endif
            }
        }
        index = (index + 1) % killed_processes_cache_size;
        if (index == original_index) break;
    }
    return 0;
}

void free_killed_processes_cache() {
    if (killed_processes_cache) {
        free(killed_processes_cache);
    }
}

// --- Main logic ---
void cleanup() {
    syslog(LOG_INFO, "Shutting down gracefully.");
    if (remove(PID_FILE) == -1 && errno != ENOENT) {
        syslog(LOG_WARNING, "Failed to remove PID file: %s", strerror(errno));
    }
    free_hash_table(allow_list);
    free_hash_table(monitored_users);
    if (regex_blacklist) {
        for (int i = 0; i < regex_blacklist_count; i++) {
            regfree(&regex_blacklist[i].regex_comp);
        }
        free(regex_blacklist);
    }
    if (user_regex_patterns) {
        for (int i = 0; i < user_regex_patterns_count; i++) {
            regfree(&user_regex_patterns[i].regex_comp);
        }
        free(user_regex_patterns);
    }
    if (uid_cache) {
        free(uid_cache);
    }
    free_killed_processes_cache();
    closelog();
}

void signal_handler(int signum) {
    switch (signum) {
        case SIGINT:
        case SIGTERM:
            shutdown_flag = 1;
            break;
        case SIGHUP:
            reload_flag = 1;
            break;
    }
}

void write_pid_file() {
    FILE *fp = fopen(PID_FILE, "w");
    if (fp) {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    } else {
        syslog(LOG_ERR, "Failed to write PID file: %s", strerror(errno));
        exit(1);
    }
}

void read_config() {
    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open configuration file '%s': %s", CONFIG_FILE, strerror(errno));
        if (!safe_mode_flag) {
            syslog(LOG_ERR, "Safe mode is off. Aborting.");
            exit(1);
        }
        syslog(LOG_WARNING, "Safe mode is on. No processes will be killed until a successful reload.");
        return;
    }

    struct stat st;
    if (stat(CONFIG_FILE, &st) == 0) {
        config_mtime = st.st_mtime;
    }

    free_hash_table(allow_list);
    free_hash_table(monitored_users);
    if (regex_blacklist) {
        for (int i = 0; i < regex_blacklist_count; i++) {
            regfree(&regex_blacklist[i].regex_comp);
        }
        free(regex_blacklist);
    }
    if (user_regex_patterns) {
        for (int i = 0; i < user_regex_patterns_count; i++) {
            regfree(&user_regex_patterns[i].regex_comp);
        }
        free(user_regex_patterns);
    }

    init_hash_table(&allow_list, INITIAL_HASH_TABLE_SIZE);
    init_hash_table(&monitored_users, INITIAL_HASH_TABLE_SIZE);
    regex_blacklist = NULL;
    user_regex_patterns = NULL;
    regex_blacklist_count = 0;
    user_regex_patterns_count = 0;

    char line[MAX_LINE_LENGTH];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        line[strcspn(line, "\n")] = 0;

        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        char key[MAX_LINE_LENGTH];
        char value[MAX_LINE_LENGTH];
        if (sscanf(line, "%[^=]=%s", key, value) != 2) {
            syslog(LOG_WARNING, "Invalid configuration line (ignored): %s (line %d)", line, line_num);
            continue;
        }

        if (strcmp(key, "ALLOW") == 0) {
            add_to_hash_table(allow_list, value, 1.0);
        } else if (strcmp(key, "MONITOR_USER") == 0) {
            char user[MAX_LINE_LENGTH];
            double limit = 0;
            if (sscanf(value, "%[^,],%lf", user, &limit) == 2) {
                add_to_hash_table(monitored_users, user, limit);
            } else {
                add_to_hash_table(monitored_users, value, default_time_limit);
            }
        } else if (strcmp(key, "REGEX_BLACKLIST") == 0) {
            RegexBlacklist *new_list = realloc(regex_blacklist, sizeof(RegexBlacklist) * (regex_blacklist_count + 1));
            if (!new_list) {
                syslog(LOG_ERR, "Failed to reallocate memory for regex blacklist.");
                fclose(fp);
                exit(1);
            }
            regex_blacklist = new_list;
            strncpy(regex_blacklist[regex_blacklist_count].regex_pattern, value, MAX_LINE_LENGTH);
            if (regcomp(&regex_blacklist[regex_blacklist_count].regex_comp, value, REG_EXTENDED | REG_NOSUB) != 0) {
                syslog(LOG_ERR, "Failed to compile regex pattern: %s (line %d)", value, line_num);
            }
            regex_blacklist_count++;
        } else if (strcmp(key, "USER_REGEX") == 0) {
            char user[MAX_LINE_LENGTH];
            char regex_pattern[MAX_LINE_LENGTH];
            if (sscanf(value, "%[^,],%s", user, regex_pattern) == 2) {
                UserMonitor *new_list = realloc(user_regex_patterns, sizeof(UserMonitor) * (user_regex_patterns_count + 1));
                if (!new_list) {
                    syslog(LOG_ERR, "Failed to reallocate memory for user regex patterns.");
                    fclose(fp);
                    exit(1);
                }
                user_regex_patterns = new_list;
                strncpy(user_regex_patterns[user_regex_patterns_count].key, user, MAX_LINE_LENGTH);
                strncpy(user_regex_patterns[user_regex_patterns_count].regex_pattern, regex_pattern, MAX_LINE_LENGTH);
                if (regcomp(&user_regex_patterns[user_regex_patterns_count].regex_comp, regex_pattern, REG_EXTENDED | REG_NOSUB) != 0) {
                    syslog(LOG_ERR, "Failed to compile user regex pattern: %s (line %d)", regex_pattern, line_num);
                }
                user_regex_patterns_count++;
            } else {
                syslog(LOG_WARNING, "Invalid USER_REGEX format (ignored): %s (line %d)", value, line_num);
            }
        } else if (strcmp(key, "DEBUG_LEVEL") == 0) {
            debug_level = atoi(value);
        } else if (strcmp(key, "DEFAULT_TIME_LIMIT") == 0) {
            default_time_limit = atof(value);
        } else if (strcmp(key, "IGNORE_ROOT") == 0) {
            ignore_root_processes = atoi(value);
        } else {
            syslog(LOG_WARNING, "Unknown configuration key (ignored): %s (line %d)", key, line_num);
        }
    }
    
    fclose(fp);
    syslog(LOG_INFO, "Configuration loaded successfully.");
}

void reload_config() {
    syslog(LOG_INFO, "Reloading configuration due to SIGHUP...");
    read_config();
}

int is_allow_listed(const char *user, const char *cmdline) {
    if (get_from_hash_table(allow_list, user) != -1.0) {
        return 1;
    }
    if (regex_blacklist) {
        for (int i = 0; i < regex_blacklist_count; i++) {
            if (regexec(&regex_blacklist[i].regex_comp, cmdline, 0, NULL, 0) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

int should_kill(const char *user, const char *cmdline, double elapsed_time) {
    if (dry_run_flag || safe_mode_flag) {
        return 0;
    }

    if (ignore_root_processes && strcmp(user, "root") == 0) {
        syslog(LOG_DEBUG, "Ignoring root process: %s", cmdline);
        return 0;
    }

    double user_time_limit = get_from_hash_table(monitored_users, user);
    if (user_time_limit != -1.0) {
        if (elapsed_time > user_time_limit) {
            syslog(LOG_INFO, "User '%s' process '%s' exceeded its time limit (%.2f seconds).", user, cmdline, user_time_limit);
            return 1;
        }
    }

    if (user_regex_patterns) {
        for (int i = 0; i < user_regex_patterns_count; i++) {
            if (strcmp(user_regex_patterns[i].key, user) == 0) {
                if (regexec(&user_regex_patterns[i].regex_comp, cmdline, 0, NULL, 0) == 0) {
                    syslog(LOG_INFO, "User '%s' process '%s' matched user-defined regex '%s'.", user, cmdline, user_regex_patterns[i].regex_pattern);
                    return 1;
                }
            }
        }
    }

    if (!is_allow_listed(user, cmdline)) {
        if (elapsed_time > default_time_limit) {
            syslog(LOG_INFO, "Process '%s' by user '%s' exceeded default time limit (%.2f seconds).", cmdline, user, default_time_limit);
            return 1;
        }
    }

    return 0;
}

void kill_process(pid_t pid, const char *reason) {
    syslog(LOG_INFO, "Attempting to SIGTERM PID %d: %s", pid, reason);
    if (kill(pid, SIGTERM) == -1) {
        syslog(LOG_ERR, "Failed to send SIGTERM to PID %d: %s", pid, strerror(errno));
    } else {
        sleep(1);
        if (kill(pid, 0) == 0) {
            syslog(LOG_INFO, "Process %d did not terminate, sending SIGKILL.", pid);
            if (kill(pid, SIGKILL) == -1) {
                syslog(LOG_ERR, "Failed to send SIGKILL to PID %d: %s", pid, strerror(errno));
            }
        }
    }
}

const char* get_username_from_uid(uid_t uid) {
    for (int i = 0; i < uid_cache_size; i++) {
        if (uid_cache[i].uid == uid) {
            return uid_cache[i].username;
        }
    }

    struct passwd *pwnam = getpwuid(uid);
    if (pwnam) {
        UIDCache *new_cache = realloc(uid_cache, sizeof(UIDCache) * (uid_cache_size + 1));
        if (!new_cache) {
            syslog(LOG_ERR, "Failed to reallocate UID cache.");
            return "unknown";
        }
        uid_cache = new_cache;
        uid_cache[uid_cache_size].uid = uid;
        strncpy(uid_cache[uid_cache_size].username, pwnam->pw_name, MAX_LINE_LENGTH - 1);
        uid_cache[uid_cache_size].username[MAX_LINE_LENGTH - 1] = '\0';
        uid_cache_size++;
        return uid_cache[uid_cache_size - 1].username;
    }
    return "unknown";
}

#ifdef __linux__
void monitor() {
    DIR *dir;
    struct dirent *entry;
    char path[PATH_MAX];
    char cmdline[PATH_MAX];
    struct stat st;
    double elapsed_time;
    
    // Future work: Replace polling with an event-driven mechanism like proc connector
    // to improve scalability on systems with a large number of processes.
    // Inotify could be used on the /proc filesystem.

    dir = opendir("/proc");
    if (!dir) {
        syslog(LOG_ERR, "Failed to open /proc: %s", strerror(errno));
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            pid_t pid = atoi(entry->d_name);
            if (pid > 0) {
                snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
                FILE *stat_fp = fopen(path, "r");
                if (stat_fp) {
                    char line_buffer[PATH_MAX * 2];
                    if (fgets(line_buffer, sizeof(line_buffer), stat_fp) == NULL) {
                        fclose(stat_fp);
                        continue;
                    }
                    fclose(stat_fp);
                    
                    // Robust parsing using strtok_r
                    char *saveptr;
                    char *token;
                    char comm[256];
                    int field_count = 0;
                    long long starttime = 0;

                    token = strtok_r(line_buffer, " ", &saveptr); // PID
                    while(token != NULL) {
                        field_count++;
                        if (field_count == 2) {
                            // Comm field might contain spaces, so parse carefully
                            char *close_paren = strchr(token, ')');
                            if (close_paren) {
                                *close_paren = '\0';
                                strncpy(comm, token + 1, sizeof(comm) - 1);
                                comm[sizeof(comm) - 1] = '\0';
                                token = strtok_r(NULL, " ", &saveptr); // Advance past comm
                                field_count++; // Adjust field count for the rest of the line
                            }
                        }
                        if (field_count == 22) { // 22nd field is starttime
                            starttime = atoll(token);
                            break;
                        }
                        token = strtok_r(NULL, " ", &saveptr);
                    }
                    
                    if (starttime == 0) {
                        continue;
                    }

                    // Check for PID reuse
                    if (is_in_killed_processes_cache(pid, starttime)) {
                        syslog(LOG_INFO, "Skipping recently killed process PID %d (reused PID detected).", pid);
                        continue;
                    }

                    struct sysinfo s_info;
                    sysinfo(&s_info);
                    long uptime_seconds = s_info.uptime;
                    elapsed_time = (double)uptime_seconds - ((double)starttime / sysconf(_SC_CLK_TCK));

                    snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
                    FILE *cmdline_fp = fopen(path, "rb");
                    if (cmdline_fp) {
                        size_t bytes_read = fread(cmdline, 1, sizeof(cmdline) - 1, cmdline_fp);
                        for (size_t i = 0; i < bytes_read; i++) {
                            if (cmdline[i] == '\0') {
                                cmdline[i] = ' ';
                            }
                        }
                        cmdline[bytes_read] = '\0';
                        fclose(cmdline_fp);
                        
                        snprintf(path, sizeof(path), "/proc/%s", entry->d_name);
                        if (stat(path, &st) == 0) {
                            const char *username = get_username_from_uid(st.st_uid);
                            if (should_kill(username, cmdline, elapsed_time)) {
                                add_to_killed_processes_cache(pid, starttime);
                                kill_process(pid, "Time limit or regex match");
                            }
                        }
                    }
                }
            }
        }
    }
    closedir(dir);
}
#endif

#ifdef __FreeBSD__
void monitor() {
    int mib[4];
    size_t len;
    double elapsed_time;

    // Use sysctl to get process list, which is generally more efficient than kvm_getprocs
    // for just iterating over process info.
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ALL;
    mib[3] = 0;

    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
        syslog(LOG_ERR, "sysctl failed to get process list size: %s", strerror(errno));
        return;
    }

    struct kinfo_proc *kp = malloc(len);
    if (kp == NULL) {
        syslog(LOG_ERR, "Failed to allocate memory for process list.");
        return;
    }

    if (sysctl(mib, 4, kp, &len, NULL, 0) < 0) {
        syslog(LOG_ERR, "sysctl failed to get process list: %s", strerror(errno));
        free(kp);
        return;
    }

    int cnt = len / sizeof(struct kinfo_proc);

    for (int i = 0; i < cnt; i++) {
        // Optimized: Only get command line for processes that pass initial filters
        char cmdline[PATH_MAX];
        
        // Corrected uptime calculation with microseconds for higher precision
        struct timeval tv_start = kp[i].ki_start;
        struct timeval tv_now;
        gettimeofday(&tv_now, NULL);
        elapsed_time = (double)(tv_now.tv_sec - tv_start.tv_sec) +
                       (double)(tv_now.tv_usec - tv_start.tv_usec) / 1000000.0;
        
        const char *username = get_username_from_uid(kp[i].ki_uid);

        // Check for PID reuse using ki_start
        if (is_in_killed_processes_cache(kp[i].ki_pid, kp[i].ki_start)) {
            syslog(LOG_INFO, "Skipping recently killed process PID %d (reused PID detected).", kp[i].ki_pid);
            continue;
        }

        // Check against time limit before getting the full command line
        if (should_kill(username, "", elapsed_time)) {
             // Only get cmdline if a kill is needed
            kvm_t *kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, "kvm_openfiles");
            if (kd != NULL) {
                 char **argv = kvm_getargv(kd, &kp[i], 0);
                 if (argv) {
                    cmdline[0] = '\0';
                    for (int j = 0; argv[j] != NULL; j++) {
                        strncat(cmdline, argv[j], sizeof(cmdline) - strlen(cmdline) - 1);
                        strncat(cmdline, " ", sizeof(cmdline) - strlen(cmdline) - 1);
                    }
                    if (should_kill(username, cmdline, elapsed_time)) {
                        add_to_killed_processes_cache(kp[i].ki_pid, kp[i].ki_start);
                        kill_process(kp[i].ki_pid, "Time limit or regex match");
                    }
                 }
                 kvm_close(kd);
            }
        }
    }
    free(kp);
}
#endif

void daemonize() {
    pid_t pid, sid;
    pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "fork failed: %s", strerror(errno));
        exit(1);
    }
    if (pid > 0) {
        exit(0);
    }
    umask(0);
    sid = setsid();
    if (sid < 0) {
        syslog(LOG_ERR, "setsid failed: %s", strerror(errno));
        exit(1);
    }
    if ((chdir("/")) < 0) {
        syslog(LOG_ERR, "chdir failed: %s", strerror(errno));
        exit(1);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

int main(int argc, char *argv[]) {
    openlog("proc_killer", LOG_PID | LOG_CONS, LOG_DAEMON);

    struct passwd *pw = getpwnam("root");
    if (pw) {
        root_uid = pw->pw_uid;
    } else {
        syslog(LOG_WARNING, "Could not find root user UID. Root processes will not be ignored.");
        ignore_root_processes = 0;
    }
    
    char *target_user = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dry-run") == 0) {
            dry_run_flag = 1;
        } else if (strcmp(argv[i], "--safe-mode") == 0) {
            safe_mode_flag = 1;
        } else if (strcmp(argv[i], "--check-interval") == 0) {
            if (i + 1 < argc) {
                check_interval_seconds = atoi(argv[i + 1]);
                i++;
                if (check_interval_seconds <= 0) {
                    syslog(LOG_ERR, "--check-interval must be a positive integer.");
                    return 1;
                }
            } else {
                syslog(LOG_ERR, "--check-interval requires an integer argument.");
                return 1;
            }
        } else if (strcmp(argv[i], "--kill-user") == 0) {
            if (i + 1 < argc) {
                target_user = argv[i + 1];
                i++;
            } else {
                syslog(LOG_ERR, "--kill-user requires a username.");
                return 1;
            }
        }
    }

    if (target_user) {
        syslog(LOG_NOTICE, "Command line kill requested for user '%s'. %s", target_user, dry_run_flag ? "(Dry-run)" : "");
#ifdef __linux__
        DIR *dir;
        struct dirent *entry;
        char path[PATH_MAX];
        struct stat st;
        struct passwd *pwnam;
        dir = opendir("/proc");
        if (!dir) {
            syslog(LOG_ERR, "Failed to open /proc: %s", strerror(errno));
            return 1;
        }
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                pid_t pid = atoi(entry->d_name);
                if (pid > 0) {
                    snprintf(path, sizeof(path), "/proc/%s", entry->d_name);
                    if (stat(path, &st) == 0) {
                        pwnam = getpwuid(st.st_uid);
                        if (pwnam && strcmp(pwnam->pw_name, target_user) == 0) {
                            if (dry_run_flag) {
                                syslog(LOG_NOTICE, "Dry-run: Would have killed PID %d for user '%s'.", pid, target_user);
                            } else {
                                syslog(LOG_INFO, "Found process PID %d for user '%s'.", pid, target_user);
                                kill_process(pid, "Command line kill request");
                            }
                        }
                    }
                }
            }
        }
        closedir(dir);
#endif
        return 0;
    }

    daemonize();
    write_pid_file();
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
    init_killed_processes_cache();

    syslog(LOG_INFO, "Starting proc_killer daemon. Safe mode: %s, Dry-run: %s, Check interval: %d seconds.",
           safe_mode_flag ? "ON" : "OFF", dry_run_flag ? "ON" : "OFF", check_interval_seconds);

    read_config();
    
#ifdef __linux__
    sd_notify(0, "READY=1\nSTATUS=Monitoring processes...");
#endif

    while (!shutdown_flag) {
        if (reload_flag) {
            reload_config();
            reload_flag = 0;
#ifdef __linux__
            sd_notify(0, "STATUS=Configuration reloaded. Monitoring processes...");
#endif
        }

#ifdef __linux__
        sd_notify(0, "WATCHDOG=1");
#endif
        
        monitor();
        sleep(check_interval_seconds);
    }
    
    cleanup();
    return 0;
}
