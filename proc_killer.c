/*
 * proc_killer_v4.c - Process killer daemon (Linux + FreeBSD)
 *
 * Features:
 * - Runs as root (necessary for killing other users' processes)
 * - Config via EnvironmentFile
 * - Allow list: no time limit
 * - Monitor users: user[,seconds] -> individual time limits
 * - Regex cmdline blacklist
 * - Execution time limit for non-allow processes
 * - Debug levels:
 * DEBUG_LEVEL=1 -> detect only (log only, no kill)
 * DEBUG_LEVEL=2 -> SIGTERM only
 * DEBUG_LEVEL=3 -> SIGTERM + SIGKILL
 * - PID file
 * - Logging via syslog (facility: DAEMON)
 * - Reloads config on SIGHUP
 * - Graceful shutdown on SIGINT/SIGTERM
 * - Uses Hash Tables for allow and user lists for performance
 * - Robust configuration reloading
 * - Security check for configuration file permissions (root:root, 0600)
 * - Uses a non-blocking 'kill list' to manage SIGTERM/SIGKILL grace period
 * - Uniquely identifies processes with PID + start time to prevent re-use errors
 * - systemd notify support using sd_notify() for Type=notify service
 *
 * Compilation:
 * Linux (with systemd):   gcc -O2 -Wall -o proc_killer_v4 proc_killer_v4.c -lregex -lsystemd
 * Linux (without systemd): gcc -O2 -Wall -o proc_killer_v4 proc_killer_v4.c -lregex
 * FreeBSD:                cc  -O2 -Wall -o proc_killer_v4 proc_killer_v4.c -lregex
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <regex.h>
#include <syslog.h>

#ifdef __linux__
// Required for systemd support on Linux
#include <systemd/sd-daemon.h>
#endif

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <sys/user.h>
#endif

// Defined structures for linked lists
typedef struct node {
    char *key;
    void *value;
    struct node *next;
} Node;

#define HASH_TABLE_SIZE 1024
typedef struct {
    Node *buckets[HASH_TABLE_SIZE];
} HashTable;

typedef struct user_limit {
    int limit;
} UserLimit;

typedef struct regex_node {
    regex_t regex;
    struct regex_node *next;
} RegexNode;

// Node for the non-blocking kill list
typedef struct kill_node {
    pid_t pid;
    long long start_time;
    time_t sigterm_time;
    struct kill_node *next;
} KillNode;

// Default configuration paths
#define DEFAULT_ALLOW_LIST          "/etc/proc_killer/proc_allow_list"
#define DEFAULT_USER_LIST           "/etc/proc_killer/monitor_users"
#define DEFAULT_PID_FILE            "/run/proc_killer.pid"
#define DEFAULT_CMDLINE_BLACKLIST   "/etc/proc_killer/cmdline_blacklist_regex"
#define DEFAULT_CHECK_INTERVAL      30
#define DEFAULT_MAX_SECONDS         300
#define DEFAULT_GRACE_PERIOD        5

// Global configuration pointers for easy cleanup and reloading
HashTable *allow_list_ht = NULL;
HashTable *user_limits_ht = NULL;
RegexNode *blacklist_head = NULL;
KillNode *kill_list_head = NULL;

int DEBUG_LEVEL = 3;
int CHECK_INTERVAL;
int MAX_SECONDS;
int GRACE_PERIOD;
const char *PID_FILE;

volatile sig_atomic_t reload_flag = 0;
volatile sig_atomic_t shutdown_flag = 0;

/* -------- Utility Functions -------- */

// Simple string hash function
unsigned int hash(const char *key) {
    unsigned long int value = 0;
    unsigned int i = 0;
    unsigned int key_len = strlen(key);
    for (; i < key_len; ++i) {
        value = value * 37 + key[i];
    }
    value = value % HASH_TABLE_SIZE;
    return value;
}

// Initializes a hash table
HashTable *create_hashtable() {
    HashTable *ht = calloc(1, sizeof(HashTable));
    if (!ht) {
        syslog(LOG_ERR, "Failed to allocate memory for hash table");
        return NULL;
    }
    return ht;
}

// Inserts a key-value pair into a hash table
int hashtable_insert(HashTable *ht, const char *key, void *value) {
    if (!ht || !key) return -1;
    unsigned int index = hash(key);
    Node *new_node = malloc(sizeof(Node));
    if (!new_node) {
        syslog(LOG_ERR, "Failed to allocate memory for hash node");
        return -1;
    }
    new_node->key = strdup(key);
    if (!new_node->key) {
        free(new_node);
        return -1;
    }
    new_node->value = value;
    new_node->next = ht->buckets[index];
    ht->buckets[index] = new_node;
    return 0;
}

// Looks up a value in a hash table
void *hashtable_lookup(HashTable *ht, const char *key) {
    if (!ht || !key) return NULL;
    unsigned int index = hash(key);
    for (Node *node = ht->buckets[index]; node; node = node->next) {
        if (strcmp(node->key, key) == 0) {
            return node->value;
        }
    }
    return NULL;
}

// Frees a hash table
void free_hashtable(HashTable *ht, void (*free_value_func)(void *)) {
    if (!ht) return;
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        Node *node = ht->buckets[i];
        while (node) {
            Node *tmp = node;
            node = node->next;
            free(tmp->key);
            if (free_value_func) {
                free_value_func(tmp->value);
            }
            free(tmp);
        }
    }
    free(ht);
}

// Frees the memory for a kill list
void free_kill_list(KillNode *head) {
    while (head) {
        KillNode *tmp = head;
        head = head->next;
        free(tmp);
    }
}

// Loads a list from a file into a hash table
HashTable *load_list_to_hashtable(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open config file: %s", path);
        return NULL;
    }
    HashTable *ht = create_hashtable();
    if (!ht) {
        fclose(fp);
        return NULL;
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, fp)) != -1) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0 || line[0] == '#') continue;
        if (hashtable_insert(ht, line, NULL) != 0) {
            free(line);
            fclose(fp);
            free_hashtable(ht, NULL);
            return NULL;
        }
    }
    free(line);
    fclose(fp);
    return ht;
}

// Loads user-specific time limits into a hash table
HashTable *load_user_limits_to_hashtable(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open user limits file: %s", path);
        return NULL;
    }
    HashTable *ht = create_hashtable();
    if (!ht) {
        fclose(fp);
        return NULL;
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, fp)) != -1) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || strlen(line) == 0) continue;

        char *tok_ctx = NULL;
        char *user_name = strtok_r(line, ",", &tok_ctx);
        if (!user_name) continue;

        UserLimit *u = calloc(1, sizeof(UserLimit));
        if (!u) {
            syslog(LOG_ERR, "Memory allocation failed for user limit node");
            free(line);
            fclose(fp);
            free_hashtable(ht, free);
            return NULL;
        }

        char *limit_str = strtok_r(NULL, ",", &tok_ctx);
        if (limit_str) {
            u->limit = atoi(limit_str);
            if (u->limit <= 0) u->limit = MAX_SECONDS;
        } else {
            u->limit = MAX_SECONDS;
        }

        if (hashtable_insert(ht, user_name, u) != 0) {
            free(u);
            free(line);
            fclose(fp);
            free_hashtable(ht, free);
            return NULL;
        }
    }
    free(line);
    fclose(fp);
    return ht;
}

// Safely get environment variable or return a fallback
const char *getenv_or(const char *key, const char *fallback) {
    const char *val = getenv(key);
    return val ? val : fallback;
}

// Frees the memory for a regex list
void free_regex_list(RegexNode *head) {
    while (head) {
        RegexNode *tmp = head;
        head = head->next;
        regfree(&tmp->regex);
        free(tmp);
    }
}

// Loads regex patterns from a file using getline
RegexNode *load_regex_list(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open regex list: %s", path);
        return NULL;
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    RegexNode *head = NULL, *tail = NULL;
    while ((read = getline(&line, &len, fp)) != -1) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || strlen(line) == 0) continue;

        RegexNode *node = calloc(1, sizeof(RegexNode));
        if (!node) {
            syslog(LOG_ERR, "Memory allocation failed for regex node");
            free_regex_list(head);
            free(line);
            fclose(fp);
            return NULL;
        }

        if (regcomp(&node->regex, line, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0) {
            syslog(LOG_WARNING, "Failed to compile regex: %s", line);
            free(node);
            continue;
        }
        node->next = NULL;
        if (!head) {
            head = node;
        } else {
            tail->next = node;
        }
        tail = node;
    }
    free(line);
    fclose(fp);
    return head;
}

// Checks if a string matches any regex in a list
int match_regex_list(RegexNode *head, const char *cmdline) {
    if (!cmdline) return 0;
    for (RegexNode *node = head; node; node = node->next) {
        if (regexec(&node->regex, cmdline, 0, NULL, 0) == 0)
            return 1;
    }
    return 0;
}

// Gets the time limit for a specific user
int get_user_limit(HashTable *ht, const char *uname) {
    UserLimit *limit = hashtable_lookup(ht, uname);
    if (limit) {
        return (limit->limit > 0) ? limit->limit : MAX_SECONDS;
    }
    return -1; // Not a monitored user
}

// Logs the action to syslog
void log_action(const char *user, pid_t pid,
                const char *exe, long long etime, const char *action) {
    syslog(LOG_NOTICE, "proc_killer %s USER=%s PID=%d EXE=%s ETIME=%llds",
           action, user, pid, exe, etime);
}

// Writes the PID to a file
void write_pid_file(const char *path) {
    FILE *fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    } else {
        syslog(LOG_ERR, "Failed to write PID file: %s, errno=%d", path, errno);
    }
}

// Daemonizes the process
void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    if (setsid() < 0) exit(EXIT_FAILURE);
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    umask(0);
    chdir("/");
}

// Check if a file has the correct permissions (root:root, 0600)
int check_config_permissions(const char *path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        if (errno == ENOENT) {
            syslog(LOG_WARNING, "Config file not found: %s. Assuming safe.", path);
            return 0; // File does not exist, safe to continue
        }
        syslog(LOG_ERR, "Failed to stat config file: %s, errno=%d", path, errno);
        return -1; // Critical error
    }

    if (st.st_uid != 0 || st.st_gid != 0) {
        syslog(LOG_ERR, "Config file %s must be owned by root:root. Aborting.", path);
        return -1;
    }

    if ((st.st_mode & 0777) != 0600) {
        syslog(LOG_ERR, "Config file %s must have 0600 permissions. Aborting.", path);
        return -1;
    }

    return 0;
}

// Adds a process to the kill list
void add_to_kill_list(pid_t pid, long long start_time) {
    // Check if the process is already in the list
    for (KillNode *node = kill_list_head; node; node = node->next) {
        if (node->pid == pid && node->start_time == start_time) {
            return;
        }
    }
    // Add new node to the head
    KillNode *new_node = calloc(1, sizeof(KillNode));
    if (!new_node) {
        syslog(LOG_ERR, "Failed to allocate memory for kill list node");
        return;
    }
    new_node->pid = pid;
    new_node->start_time = start_time;
    new_node->sigterm_time = time(NULL);
    new_node->next = kill_list_head;
    kill_list_head = new_node;
}

// Process the kill list
void process_kill_list() {
    KillNode *cur = kill_list_head;
    KillNode *prev = NULL;
    time_t now = time(NULL);

    while (cur) {
        // Check if the process is still running and the grace period has expired
        if ((now - cur->sigterm_time) > GRACE_PERIOD) {
            if (kill(cur->pid, 0) == 0) { // Check if process still exists
                if (kill(cur->pid, SIGKILL) == 0) {
                    syslog(LOG_NOTICE, "proc_killer SIGKILL PID=%d after grace period.", cur->pid);
                }
            }
            // Remove node from list
            if (prev) {
                prev->next = cur->next;
            } else {
                kill_list_head = cur->next;
            }
            KillNode *tmp = cur;
            cur = cur->next;
            free(tmp);
        } else {
            prev = cur;
            cur = cur->next;
        }
    }
}

/* -------- Platform-specific process scan -------- */

#ifdef __linux__

// Reads the command line from /proc/<pid>/cmdline using dynamic memory
char *read_cmdline(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;

    char *line = NULL;
    size_t len = 0;
    ssize_t read = getline(&line, &len, fp);
    fclose(fp);
    
    if (read == -1) {
        free(line);
        return NULL;
    }

    // Replace null terminators with spaces
    for (ssize_t i = 0; i < read; i++) {
        if (line[i] == '\0') {
            line[i] = ' ';
        }
    }
    return line;
}

// Gets process info from /proc
int get_process_info(pid_t pid, char *comm, size_t clen,
                      uid_t *uid, long long *etime, long long *start_ticks, char *exepath, size_t plen) {
    char path[256], buf[4096];
    FILE *fp;

    // Get UID from /proc/<pid> stat file
    snprintf(path, sizeof(path), "/proc/%d", pid);
    struct stat st;
    if (stat(path, &st) == -1) return -1;
    *uid = st.st_uid;

    // Get command name and start time from /proc/<pid>/stat
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    if (!fp) return -1;
    if (!fgets(buf, sizeof(buf), fp)) { fclose(fp); return -1; }
    fclose(fp);

    char comm_raw[256];
    char *paren_open = strchr(buf, '(');
    char *paren_close = strrchr(buf, ')');
    if (!paren_open || !paren_close) return -1;

    size_t comm_len = paren_close - paren_open - 1;
    if (comm_len >= clen) comm_len = clen - 1;
    strncpy(comm, paren_open + 1, comm_len);
    comm[comm_len] = '\0';
    
    char *stat_end = paren_close + 1;
    sscanf(stat_end, " %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %lld", start_ticks);

    // Get uptime to calculate elapsed time
    double uptime = 0.0;
    fp = fopen("/proc/uptime", "r");
    if (!fp) return -1;
    if (fscanf(fp, "%lf", &uptime) != 1) { fclose(fp); return -1; }
    fclose(fp);

    long hz = sysconf(_SC_CLK_TCK);
    *etime = (long long)(uptime - (double)*start_ticks / hz);
    if (*etime < 0) *etime = 0;

    // Get executable path
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len2 = readlink(path, exepath, plen - 1);
    if (len2 >= 0) {
        exepath[len2] = '\0';
    } else {
        strncpy(exepath, "(unknown)", plen);
    }
    return 0;
}

#endif /* __linux__ */

#ifdef __FreeBSD__
// Gets all processes using sysctl
int get_processes(struct kinfo_proc **procs) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t len;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) return -1;
    *procs = malloc(len);
    if (!*procs) return -1;
    if (sysctl(mib, 4, *procs, &len, NULL, 0) < 0) {
        free(*procs);
        return -1;
    }
    return len / sizeof(struct kinfo_proc);
}

// Helper to get full command line arguments on FreeBSD
char *get_freebsd_cmdline(pid_t pid, char *buf, size_t buflen) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ARGS, pid };
    size_t len = buflen;
    if (sysctl(mib, 4, buf, &len, NULL, 0) < 0) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
    return buf;
}

#endif /* __FreeBSD__ */

// Performs the kill action based on debug level
void perform_kill(pid_t pid, const char *uname, const char *exepath, long long etime, const char *type, long long start_time) {
    if (DEBUG_LEVEL <= 1) {
        log_action(uname, pid, exepath, etime, "DETECTED");
        return;
    }

    // Only send SIGTERM if not already in the kill list
    int found_in_list = 0;
    for (KillNode *node = kill_list_head; node; node = node->next) {
        if (node->pid == pid && node->start_time == start_time) {
            found_in_list = 1;
            break;
        }
    }

    if (!found_in_list) {
        if (DEBUG_LEVEL >= 2) {
            if (kill(pid, SIGTERM) == 0) {
                log_action(uname, pid, exepath, etime, "SIGTERM");
                if (DEBUG_LEVEL >= 3) {
                    add_to_kill_list(pid, start_time);
                }
            }
        }
    }
}

/* -------- Monitor -------- */

void monitor() {
    process_kill_list(); // Check for processes to SIGKILL
    
#ifdef __linux__
    DIR *dir = opendir("/proc");
    if (!dir) {
        syslog(LOG_ERR, "Failed to open /proc: %s", strerror(errno));
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(dir))) {
        if (!isdigit(ent->d_name[0])) continue;
        pid_t pid = atoi(ent->d_name);
        char comm[256], exepath[PATH_MAX];
        uid_t uid; long long etime, start_ticks;
        if (get_process_info(pid, comm, sizeof(comm), &uid, &etime, &start_ticks, exepath, sizeof(exepath)) != 0) continue;

        struct passwd *pw = getpwuid(uid);
        if (!pw) continue;
        const char *uname = pw->pw_name;

        int limit = get_user_limit(user_limits_ht, uname);
        if (limit < 0) continue;

        char *cmdline = read_cmdline(pid);
        if (!cmdline) continue;

        if (match_regex_list(blacklist_head, cmdline)) {
            perform_kill(pid, uname, exepath, etime, "BLACKLISTED", start_ticks);
            free(cmdline);
            continue;
        }

        if (hashtable_lookup(allow_list_ht, comm) || hashtable_lookup(allow_list_ht, exepath)) {
            free(cmdline);
            continue;
        }

        if (etime > limit) {
            perform_kill(pid, uname, exepath, etime, "TIMED_OUT", start_ticks);
        }
        free(cmdline);
    }
    closedir(dir);
#endif /* __linux__ */

#ifdef __FreeBSD__
    struct kinfo_proc *procs;
    int n = get_processes(&procs);
    if (n < 0) {
        syslog(LOG_ERR, "Failed to get process list: %s", strerror(errno));
        return;
    }
    time_t now = time(NULL);
    char cmdbuf[2048];
    for (int i = 0; i < n; i++) {
        struct kinfo_proc *kp = &procs[i];
        pid_t pid = kp->ki_pid;
        const char *comm = kp->ki_comm;
        uid_t uid = kp->ki_uid;

        struct passwd *pw = getpwuid(uid);
        if (!pw) continue;
        const char *uname = pw->pw_name;

        int limit = get_user_limit(user_limits_ht, uname);
        if (limit < 0) continue;

        long long etime = (long long)difftime(now, kp->ki_start.tv_sec);
        if (etime < 0) etime = 0;

        char exepath[PATH_MAX];
        strncpy(exepath, comm, sizeof(exepath) - 1);
        exepath[sizeof(exepath) - 1] = '\0';

        char *cmdline = get_freebsd_cmdline(pid, cmdbuf, sizeof(cmdbuf));
        if (!cmdline) {
            cmdline = (char *)comm;
        }

        if (match_regex_list(blacklist_head, cmdline)) {
            perform_kill(pid, uname, exepath, etime, "BLACKLISTED", kp->ki_start.tv_sec);
            continue;
        }

        if (hashtable_lookup(allow_list_ht, comm) || hashtable_lookup(allow_list_ht, exepath)) continue;

        if (etime > limit) {
            perform_kill(pid, uname, exepath, etime, "TIMED_OUT", kp->ki_start.tv_sec);
        }
    }
    free(procs);
#endif /* __FreeBSD__ */
}

// Cleans up resources
void cleanup() {
    #ifdef __linux__
    sd_notify(0, "STOPPING=1");
    #endif
    free_hashtable(allow_list_ht, NULL);
    free_hashtable(user_limits_ht, free);
    free_regex_list(blacklist_head);
    free_kill_list(kill_list_head);
    if (PID_FILE) {
        unlink(PID_FILE);
    }
    closelog();
}

// Atomically reloads the configuration
void reload_config() {
    syslog(LOG_INFO, "Reloading configuration...");

    HashTable *new_allow = load_list_to_hashtable(getenv_or("ALLOW_LIST_FILE", DEFAULT_ALLOW_LIST));
    if (new_allow) {
        free_hashtable(allow_list_ht, NULL);
        allow_list_ht = new_allow;
    }

    HashTable *new_users = load_user_limits_to_hashtable(getenv_or("USER_LIST_FILE", DEFAULT_USER_LIST));
    if (new_users) {
        free_hashtable(user_limits_ht, free);
        user_limits_ht = new_users;
    }

    RegexNode *new_blacklist = load_regex_list(getenv_or("CMDLINE_BLACKLIST_FILE", DEFAULT_CMDLINE_BLACKLIST));
    if (new_blacklist) {
        free_regex_list(blacklist_head);
        blacklist_head = new_blacklist;
    }

    syslog(LOG_INFO, "Configuration reload complete. Some files may have failed to load.");
}

// Signal handler using sigaction
void sig_handler(int signo) {
    switch (signo) {
        case SIGHUP:
            reload_flag = 1;
            break;
        case SIGINT:
        case SIGTERM:
            shutdown_flag = 1;
            break;
    }
}

/* -------- Main -------- */

int main() {
    if (geteuid() != 0) {
        fprintf(stderr, "Error: must be root to start.\n");
        return 1;
    }

    // Check config file permissions before daemonizing
    if (check_config_permissions(getenv_or("ALLOW_LIST_FILE", DEFAULT_ALLOW_LIST)) != 0 ||
        check_config_permissions(getenv_or("USER_LIST_FILE", DEFAULT_USER_LIST)) != 0 ||
        check_config_permissions(getenv_or("CMDLINE_BLACKLIST_FILE", DEFAULT_CMDLINE_BLACKLIST)) != 0) {
        fprintf(stderr, "Aborting due to insecure configuration file permissions.\n");
        return 1;
    }

    // Use sigaction for robust signal handling
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        perror("sigaction SIGHUP");
        return 1;
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction SIGTERM");
        return 1;
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction SIGINT");
        return 1;
    }

    // In systemd environments, the PID file is managed by systemd and is not needed
    if (getenv("NOTIFY_SOCKET") == NULL) {
        daemonize();
        openlog("proc_killer", LOG_PID | LOG_NDELAY, LOG_DAEMON);
        PID_FILE = getenv_or("PID_FILE", DEFAULT_PID_FILE);
        write_pid_file(PID_FILE);
    } else {
        openlog("proc_killer", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }

    // Now close all other file descriptors except for standard ones
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        if (x != STDIN_FILENO && x != STDOUT_FILENO && x != STDERR_FILENO) {
            close(x);
        }
    }
    // And finally redirect standard I/O to /dev/null
    stdin = fopen("/dev/null", "r");
    stdout = fopen("/dev/null", "w");
    stderr = fopen("/dev/null", "w");

    syslog(LOG_INFO, "proc_killer daemon starting.");

    // Read initial configuration from environment variables
    CHECK_INTERVAL = atoi(getenv_or("CHECK_INTERVAL", "30"));
    MAX_SECONDS    = atoi(getenv_or("MAX_SECONDS", "300"));
    GRACE_PERIOD   = atoi(getenv_or("GRACE_PERIOD", "5"));
    DEBUG_LEVEL    = atoi(getenv_or("DEBUG_LEVEL", "3"));
    
    // In non-systemd environments, the PID file is not managed by systemd, so it is created during daemonization
    if (getenv("NOTIFY_SOCKET") == NULL) {
        PID_FILE       = getenv_or("PID_FILE", DEFAULT_PID_FILE);
        write_pid_file(PID_FILE);
    }

    reload_config();

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
        monitor();
        sleep(CHECK_INTERVAL);
    }

    syslog(LOG_INFO, "proc_killer daemon shutting down.");
    cleanup();
    return 0;
}
