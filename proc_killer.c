/*
 * proc_killer.c - The ultimate process killer daemon for large-scale environments.
 *
 * This version incorporates the final set of enhancements for mission-critical reliability, including:
 * - A more robust, unique process identifier key to mitigate PID reuse risks.
 * - Improved log rate-limiting with summary timestamps.
 * - Native systemd watchdog support for enhanced service reliability.
 * - An explicit option to enforce mandatory configuration file existence.
 *
 * The core logic remains highly optimized for performance and scalability on both Linux and FreeBSD.
 *
 * Features:
 * - Runs as root (necessary for killing other users' processes)
 * - Config via EnvironmentFile
 * - Allow list: no time limit
 * - Monitor users: user[,seconds] -> individual time limits
 * - Regex cmdline blacklist
 * - Execution time limit for non-allow processes
 * - Debug levels:
 * DEBUG_LEVEL=0 -> Dry-run (detects and logs, but does not kill)
 * DEBUG_LEVEL=1 -> LOG_DEBUG (detect only, no kill, for SIGTERM and SIGKILL)
 * DEBUG_LEVEL=2 -> LOG_INFO (SIGTERM only)
 * DEBUG_LEVEL=3 -> LOG_NOTICE (SIGTERM + SIGKILL)
 * - PID file
 * - Logging via syslog (facility: DAEMON)
 * - Reloads config on SIGHUP
 * - Graceful shutdown on SIGINT/SIGTERM
 * - Uses Hash Tables for allow, user, and UID/username lists for performance
 * - Robust configuration reloading with mtime checks
 * - Security check for configuration file permissions (root:root, 0600)
 * - Uses a hash table-based 'kill list' for efficient grace period management, complemented by a min-heap for cleanup.
 * - Uniquely identifies processes with PID + start time to prevent re-use errors
 * - **NEW**: Enhanced unique process key: PID + UID + comm + start_time.
 * - **NEW**: Log rate-limiting summary includes start and end timestamps.
 * - **NEW**: systemd watchdog support.
 * - **NEW**: Configuration existence can be mandatory via CONFIG_REQUIRED=1.
 *
 * Compilation:
 * Linux (with systemd):   gcc -O2 -Wall -o proc_killer_v9 proc_killer_v9_ultimate.c -lregex -lsystemd
 * Linux (without systemd): gcc -O2 -Wall -o proc_killer_v9 proc_killer_v9_ultimate.c -lregex
 * FreeBSD:                cc  -O2 -Wall -o proc_killer_v9 proc_killer_v9_ultimate.c -lregex
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
#include <fcntl.h>

#ifdef __linux__
#include <systemd/sd-daemon.h>
#include <syscall.h>
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

#define HASH_TABLE_SIZE 4096 // Increased hash table size for large environments
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

// Node for the UID cache, now with TTL
typedef struct {
    char *username;
    time_t last_used;
} UidCache;
#define UID_CACHE_TTL_SECONDS 3600 // 1 hour

// Node for the kill list and min-heap, with added info for logging
typedef struct {
    time_t sigterm_time;
    char *username;
    char *exe_path;
    long long start_time;
} KillNode;

// A combined structure for the min-heap
typedef struct {
    time_t expire_time;
    char *hash_key; // Key to the hash table
} HeapNode;

typedef struct {
    HeapNode **data;
    size_t capacity;
    size_t size;
} MinHeap;

// New struct for log rate limiting, now with timestamps
typedef struct {
    time_t first_log_time;
    time_t last_log_time;
    int count;
} LogRate;

// Global configuration pointers for easy cleanup and reloading
HashTable *allow_list_ht = NULL;
HashTable *user_limits_ht = NULL;
HashTable *uid_cache_ht = NULL;
HashTable *kill_list_ht = NULL;
MinHeap *kill_heap = NULL;
RegexNode *blacklist_head = NULL;
HashTable *log_rate_ht = NULL;

int DEBUG_LEVEL = 3;
int CHECK_INTERVAL;
int MAX_SECONDS;
int GRACE_PERIOD;
int LOG_RATE_LIMIT_SECONDS;
int CONFIG_REQUIRED;
const char *PID_FILE;
int log_level;
int config_failed_flag = 0;

// Store mtime for each config file to detect changes
time_t allow_list_mtime = 0;
time_t user_list_mtime = 0;
time_t blacklist_mtime = 0;

volatile sig_atomic_t reload_flag = 0;
volatile sig_atomic_t shutdown_flag = 0;

/* -------- Min-Heap Functions -------- */
MinHeap *minheap_create(size_t capacity) {
    MinHeap *heap = malloc(sizeof(MinHeap));
    if (!heap) return NULL;
    heap->data = malloc(sizeof(HeapNode*) * capacity);
    if (!heap->data) {
        free(heap);
        return NULL;
    }
    heap->capacity = capacity;
    heap->size = 0;
    return heap;
}

void minheap_swap(MinHeap *heap, size_t i, size_t j) {
    HeapNode *temp = heap->data[i];
    heap->data[i] = heap->data[j];
    heap->data[j] = temp;
}

void minheap_heapify_down(MinHeap *heap, size_t index) {
    size_t smallest = index;
    size_t left = 2 * index + 1;
    size_t right = 2 * index + 2;

    if (left < heap->size && heap->data[left]->expire_time < heap->data[smallest]->expire_time) {
        smallest = left;
    }
    if (right < heap->size && heap->data[right]->expire_time < heap->data[smallest]->expire_time) {
        smallest = right;
    }

    if (smallest != index) {
        minheap_swap(heap, index, smallest);
        minheap_heapify_down(heap, smallest);
    }
}

void minheap_heapify_up(MinHeap *heap, size_t index) {
    while (index > 0 && heap->data[(index - 1) / 2]->expire_time > heap->data[index]->expire_time) {
        minheap_swap(heap, index, (index - 1) / 2);
        index = (index - 1) / 2;
    }
}

void minheap_insert(MinHeap *heap, HeapNode *node) {
    if (heap->size == heap->capacity) {
        size_t new_capacity = heap->capacity * 2;
        HeapNode **new_data = realloc(heap->data, sizeof(HeapNode*) * new_capacity);
        if (!new_data) {
            syslog(LOG_ERR, "Failed to reallocate min-heap. Cannot insert.");
            free(node->hash_key);
            free(node);
            return;
        }
        heap->data = new_data;
        heap->capacity = new_capacity;
    }
    
    size_t index = heap->size++;
    heap->data[index] = node;
    minheap_heapify_up(heap, index);
}

HeapNode *minheap_extract_min(MinHeap *heap) {
    if (heap->size == 0) return NULL;

    HeapNode *root = heap->data[0];
    heap->data[0] = heap->data[--heap->size];
    minheap_heapify_down(heap, 0);

    return root;
}

void minheap_free(MinHeap *heap) {
    if (!heap) return;
    for (size_t i = 0; i < heap->size; ++i) {
        free(heap->data[i]->hash_key);
        free(heap->data[i]);
    }
    free(heap->data);
    free(heap);
}

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

// Simple integer hash function for UID
unsigned int hash_int(int key) {
    return (unsigned int)key % HASH_TABLE_SIZE;
}

// Creates a unique, robust key for a process
char *create_kill_key(pid_t pid, long long start_time, const char *comm, uid_t uid) {
    char key[4096];
    snprintf(key, sizeof(key), "%d:%lld:%d:%s", pid, start_time, uid, comm);
    return strdup(key);
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
    if (!ht || !key) {
        syslog(LOG_WARNING, "hashtable_insert called with null ht or key");
        return -1;
    }
    unsigned int index = hash(key);
    Node *new_node = malloc(sizeof(Node));
    if (!new_node) {
        syslog(LOG_ERR, "Failed to allocate memory for hash node");
        return -1;
    }
    new_node->key = strdup(key);
    if (!new_node->key) {
        free(new_node);
        syslog(LOG_ERR, "Failed to allocate key string");
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

// Inserts an integer key-value pair into a hash table
int hashtable_insert_int(HashTable *ht, int key, void *value) {
    if (!ht) return -1;
    unsigned int index = hash_int(key);
    Node *new_node = malloc(sizeof(Node));
    if (!new_node) {
        syslog(LOG_ERR, "Failed to allocate memory for hash node");
        return -1;
    }
    char key_str[16];
    snprintf(key_str, sizeof(key_str), "%d", key);
    new_node->key = strdup(key_str);
    if (!new_node->key) {
        free(new_node);
        return -1;
    }
    new_node->value = value;
    new_node->next = ht->buckets[index];
    ht->buckets[index] = new_node;
    return 0;
}

// Looks up a value by integer key in a hash table
void *hashtable_lookup_int(HashTable *ht, int key) {
    if (!ht) return NULL;
    unsigned int index = hash_int(key);
    char key_str[16];
    snprintf(key_str, sizeof(key_str), "%d", key);
    for (Node *node = ht->buckets[index]; node; node = node->next) {
        if (strcmp(node->key, key_str) == 0) {
            return node->value;
        }
    }
    return NULL;
}

// Removes a key-value pair from a hash table
int hashtable_remove(HashTable *ht, const char *key, void (*free_value_func)(void *)) {
    if (!ht || !key) return -1;
    unsigned int index = hash(key);
    Node *cur = ht->buckets[index];
    Node *prev = NULL;

    while(cur) {
        if(strcmp(cur->key, key) == 0) {
            if(prev) {
                prev->next = cur->next;
            } else {
                ht->buckets[index] = cur->next;
            }
            free(cur->key);
            if(free_value_func) {
                free_value_func(cur->value);
            }
            free(cur);
            return 0;
        }
        prev = cur;
        cur = cur->next;
    }
    return -1;
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
            syslog(LOG_ERR, "Failed to insert into hash table for %s", path);
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
            syslog(LOG_ERR, "Failed to insert into hash table for %s", path);
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

// Logs the action to syslog with rate limiting
void log_action(const char *user, pid_t pid,
                const char *exe, long long etime, const char *action) {
    // Determine log level based on action
    int level = LOG_INFO;
    if (strstr(action, "SIGKILL")) {
        level = LOG_NOTICE;
    } else if (strstr(action, "SIGTERM")) {
        level = LOG_INFO;
    } else if (strstr(action, "DETECTED")) {
        level = LOG_DEBUG;
    } else if (strstr(action, "ZOMBIE")) {
        level = LOG_WARNING;
    }

    if (LOG_RATE_LIMIT_SECONDS > 0) {
        char key_buf[512];
        snprintf(key_buf, sizeof(key_buf), "%s:%s:%s", user, exe, action);

        LogRate *lr = hashtable_lookup(log_rate_ht, key_buf);
        time_t now = time(NULL);

        if (lr) {
            if ((now - lr->last_log_time) < LOG_RATE_LIMIT_SECONDS) {
                lr->count++;
                return; // Suppress log
            } else {
                if (lr->count > 1) {
                    char start_time_str[32], end_time_str[32];
                    strftime(start_time_str, sizeof(start_time_str), "%H:%M:%S", localtime(&lr->first_log_time));
                    strftime(end_time_str, sizeof(end_time_str), "%H:%M:%S", localtime(&lr->last_log_time));
                    syslog(level, "proc_killer [SUMMARY] %s count=%d (from %s to %s). USER=%s PID=%d EXE=%s ETIME=%llds",
                           action, lr->count, start_time_str, end_time_str, user, pid, exe, etime);
                }
                lr->first_log_time = now;
                lr->last_log_time = now;
                lr->count = 1;
            }
        } else {
            lr = calloc(1, sizeof(LogRate));
            if (!lr) {
                syslog(LOG_ERR, "Failed to allocate memory for log rate limiter.");
                syslog(level, "proc_killer %s USER=%s PID=%d EXE=%s ETIME=%llds",
                       action, user, pid, exe, etime);
                return;
            }
            lr->first_log_time = now;
            lr->last_log_time = now;
            lr->count = 1;
            hashtable_insert(log_rate_ht, key_buf, lr);
        }
    }
    
    syslog(level, "proc_killer %s USER=%s PID=%d EXE=%s ETIME=%llds",
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

void free_kill_node(void *value) {
    if (value) {
        KillNode *node = (KillNode *)value;
        free(node->username);
        free(node->exe_path);
        free(node);
    }
}

void free_lograte(void *value) {
    if (value) {
        free(value);
    }
}

// Adds a process to the kill list (using hash table and min-heap)
void add_to_kill_list(pid_t pid, long long start_time, const char *uname, const char *exepath, uid_t uid, const char *comm) {
    char *key = create_kill_key(pid, start_time, comm, uid);
    if (!key) return;

    if (hashtable_lookup(kill_list_ht, key)) {
        free(key);
        return; // Already in the list
    }

    // Allocate and initialize the kill node for the hash table
    KillNode *new_kill_node = calloc(1, sizeof(KillNode));
    if (!new_kill_node) {
        syslog(LOG_ERR, "Failed to allocate memory for kill list node");
        free(key);
        return;
    }
    new_kill_node->sigterm_time = time(NULL);
    new_kill_node->username = strdup(uname);
    new_kill_node->exe_path = strdup(exepath);
    new_kill_node->start_time = start_time;

    // Allocate and initialize the heap node
    HeapNode *new_heap_node = calloc(1, sizeof(HeapNode));
    if (!new_heap_node) {
        syslog(LOG_ERR, "Failed to allocate memory for heap node");
        free(new_kill_node->username);
        free(new_kill_node->exe_path);
        free(new_kill_node);
        free(key);
        return;
    }
    new_heap_node->expire_time = new_kill_node->sigterm_time + GRACE_PERIOD;
    new_heap_node->hash_key = key;

    // Insert into both data structures
    if (hashtable_insert(kill_list_ht, key, new_kill_node) != 0) {
        syslog(LOG_ERR, "Failed to insert into kill list hash table");
        free(new_kill_node->username);
        free(new_kill_node->exe_path);
        free(new_kill_node);
        free(new_heap_node->hash_key);
        free(new_heap_node);
    } else {
        minheap_insert(kill_heap, new_heap_node);
    }
}

// Process the kill list (using the min-heap)
void process_kill_list() {
    time_t now = time(NULL);

    while (kill_heap->size > 0 && kill_heap->data[0]->expire_time <= now) {
        // Extract the root (oldest expired process)
        HeapNode *expired_node = minheap_extract_min(kill_heap);
        if (!expired_node) continue;
        
        // Lookup the process info from the hash table
        KillNode *kill_node = hashtable_lookup(kill_list_ht, expired_node->hash_key);
        if (kill_node) {
            pid_t pid = 0;
            // The unique key is now more complex, need to extract PID
            sscanf(expired_node->hash_key, "%d:", &pid);
            
            #ifdef __linux__
            char path[256], buf[4096];
            snprintf(path, sizeof(path), "/proc/%d/stat", pid);
            FILE *fp = fopen(path, "r");
            char state = ' ';
            if (fp && fgets(buf, sizeof(buf), fp)) {
                sscanf(buf, "%*d %*s %c", &state);
            }
            if (state == 'Z') {
                log_action(kill_node->username, pid, kill_node->exe_path, now - kill_node->sigterm_time, "ZOMBIE DETECTED");
            }
            fclose(fp);
            #endif
            
            if (kill(pid, 0) == 0) { // Check if process still exists
                if (kill(pid, SIGKILL) == 0) {
                    log_action(kill_node->username, pid, kill_node->exe_path, now - kill_node->sigterm_time, "SIGKILL");
                }
            } else {
                syslog(LOG_DEBUG, "PID %d not found. Old process terminated.", pid);
            }
        }
        
        hashtable_remove(kill_list_ht, expired_node->hash_key, free_kill_node);
        free(expired_node->hash_key);
        free(expired_node);
    }
}

// UID-to-username caching function
const char *getpwuid_cached(uid_t uid) {
    UidCache *cached_user = hashtable_lookup_int(uid_cache_ht, uid);
    if (cached_user) {
        cached_user->last_used = time(NULL);
        return cached_user->username;
    }

    struct passwd *pw = getpwuid(uid);
    if (!pw) {
        return NULL;
    }

    UidCache *new_cache = calloc(1, sizeof(UidCache));
    if (!new_cache) {
        syslog(LOG_ERR, "Failed to allocate memory for UID cache node. Not caching.");
        return pw->pw_name;
    }

    new_cache->username = strdup(pw->pw_name);
    if (!new_cache->username) {
        free(new_cache);
        syslog(LOG_ERR, "Failed to allocate username string for UID cache. Not caching.");
        return pw->pw_name;
    }
    new_cache->last_used = time(NULL);

    if (hashtable_insert_int(uid_cache_ht, uid, new_cache) != 0) {
        syslog(LOG_ERR, "Failed to insert into UID cache hash table. Not caching.");
        free(new_cache->username);
        free(new_cache);
    }
    return new_cache->username;
}

// Cleans up old UID cache entries based on TTL
void cleanup_uid_cache() {
    time_t now = time(NULL);
    for (int i = 0; i < HASH_TABLE_SIZE; ++i) {
        Node *cur = uid_cache_ht->buckets[i];
        Node *prev = NULL;

        while (cur) {
            UidCache *cache = (UidCache *)cur->value;
            if ((now - cache->last_used) > UID_CACHE_TTL_SECONDS) {
                // Time to expire this entry
                Node *to_remove = cur;
                if (prev) {
                    prev->next = cur->next;
                } else {
                    uid_cache_ht->buckets[i] = cur->next;
                }
                cur = cur->next;

                syslog(LOG_DEBUG, "Removing expired UID cache entry for user: %s", cache->username);
                free(cache->username);
                free(cache);
                free(to_remove->key);
                free(to_remove);
                continue;
            }
            prev = cur;
            cur = cur->next;
        }
    }
}

/* -------- Platform-specific process scan -------- */

#ifdef __linux__
char *read_cmdline_light(pid_t pid, char *buf, size_t buf_len) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    
    int fd = open(path, O_RDONLY);
    if (fd == -1) return NULL;

    ssize_t read_bytes = pread(fd, buf, buf_len - 1, 0);
    close(fd);

    if (read_bytes <= 0) {
        buf[0] = '\0';
        return NULL;
    }
    buf[read_bytes] = '\0';

    for (ssize_t i = 0; i < read_bytes; i++) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
    return buf;
}

int get_process_info(pid_t pid, char *comm, size_t clen,
                      long long *etime, long long *start_ticks, char *exepath, size_t plen) {
    char path[256], buf[4096];
    FILE *fp;
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

    double uptime = 0.0;
    fp = fopen("/proc/uptime", "r");
    if (!fp) return -1;
    if (fscanf(fp, "%lf", &uptime) != 1) { fclose(fp); return -1; }
    fclose(fp);

    long hz = sysconf(_SC_CLK_TCK);
    *etime = (long long)(uptime - (double)*start_ticks / hz);
    if (*etime < 0) *etime = 0;

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

// Dynamically allocates memory for the full command line on FreeBSD
char *get_freebsd_cmdline(pid_t pid) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ARGS, pid };
    size_t len;

    // First call to get the required size
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) {
        return NULL;
    }
    
    if (len == 0) return NULL;
    
    char *buf = malloc(len);
    if (!buf) {
        syslog(LOG_ERR, "Failed to allocate memory for FreeBSD cmdline.");
        return NULL;
    }

    // Second call to get the data
    if (sysctl(mib, 4, buf, &len, NULL, 0) < 0) {
        free(buf);
        return NULL;
    }
    
    // Replace null terminators with spaces
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
    // Ensure the string is null-terminated
    if (len > 0) buf[len-1] = '\0';
    
    return buf;
}
#endif /* __FreeBSD__ */

void perform_kill(pid_t pid, const char *uname, const char *exepath, long long etime, const char *type, long long start_time, uid_t uid, const char *comm) {
    if (DEBUG_LEVEL == 0) { // dry-run mode
        log_action(uname, pid, exepath, etime, "DETECTED (DRY-RUN)");
        return;
    }

    if (DEBUG_LEVEL <= 1) { // detect-only mode
        log_action(uname, pid, exepath, etime, "DETECTED");
        return;
    }
    
    char *key = create_kill_key(pid, start_time, comm, uid);
    if (!key) return;

    if (hashtable_lookup(kill_list_ht, key)) {
        free(key);
        return; // Already in the kill list
    }
    free(key);

    if (DEBUG_LEVEL >= 2) {
        if (kill(pid, SIGTERM) == 0) {
            log_action(uname, pid, exepath, etime, "SIGTERM");
            if (DEBUG_LEVEL >= 3) {
                add_to_kill_list(pid, start_time, uname, exepath, uid, comm);
            }
        }
    }
}

/* -------- Monitor -------- */

void monitor() {
    process_kill_list(); // Check for processes to SIGKILL
    cleanup_uid_cache(); // Clean up expired UID cache entries
    
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
        
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d", pid);
        struct stat st;
        if (stat(path, &st) == -1) continue;
        uid_t uid = st.st_uid;

        const char *uname = getpwuid_cached(uid);
        if (!uname) continue;

        int limit = get_user_limit(user_limits_ht, uname);
        if (limit < 0) continue;

        char comm[256], exepath[PATH_MAX];
        long long etime, start_ticks;
        
        if (get_process_info(pid, comm, sizeof(comm), &etime, &start_ticks, exepath, sizeof(exepath)) != 0) continue;

        char cmdline_buf[4096];
        char *cmdline = read_cmdline_light(pid, cmdline_buf, sizeof(cmdline_buf));
        if (!cmdline) cmdline = comm;

        if (match_regex_list(blacklist_head, cmdline)) {
            perform_kill(pid, uname, exepath, etime, "BLACKLISTED", start_ticks, uid, comm);
            continue;
        }

        if (hashtable_lookup(allow_list_ht, comm) || hashtable_lookup(allow_list_ht, exepath)) {
            continue;
        }

        if (etime > limit) {
            perform_kill(pid, uname, exepath, etime, "TIMED_OUT", start_ticks, uid, comm);
        }
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
    for (int i = 0; i < n; i++) {
        struct kinfo_proc *kp = &procs[i];
        pid_t pid = kp->ki_pid;
        const char *comm = kp->ki_comm;
        uid_t uid = kp->ki_uid;
        long long start_time = kp->ki_start.tv_sec;

        const char *uname = getpwuid_cached(uid);
        if (!uname) continue;

        int limit = get_user_limit(user_limits_ht, uname);
        if (limit < 0) continue;

        long long etime = (long long)difftime(now, start_time);
        if (etime < 0) etime = 0;

        char exepath[PATH_MAX];
        strncpy(exepath, comm, sizeof(exepath) - 1);
        exepath[sizeof(exepath) - 1] = '\0';

        char *cmdline = get_freebsd_cmdline(pid);
        if (!cmdline) {
            cmdline = (char *)comm;
        }

        if (match_regex_list(blacklist_head, cmdline)) {
            perform_kill(pid, uname, exepath, etime, "BLACKLISTED", start_time, uid, comm);
            if (cmdline != comm) free(cmdline);
            continue;
        }

        if (hashtable_lookup(allow_list_ht, comm) || hashtable_lookup(allow_list_ht, exepath)) {
             if (cmdline != comm) free(cmdline);
             continue;
        }

        if (etime > limit) {
            perform_kill(pid, uname, exepath, etime, "TIMED_OUT", start_time, uid, comm);
        }
        if (cmdline != comm) free(cmdline);
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
    free_hashtable(uid_cache_ht, free);
    free_hashtable(kill_list_ht, free_kill_node);
    free_hashtable(log_rate_ht, free_lograte);
    minheap_free(kill_heap);
    free_regex_list(blacklist_head);
    if (PID_FILE) {
        unlink(PID_FILE);
    }
    closelog();
}

// Atomically reloads the configuration
void reload_config() {
    syslog(LOG_INFO, "Reloading configuration...");
    
    int success = 1;
    HashTable *new_allow = NULL;
    HashTable *new_users = NULL;
    RegexNode *new_blacklist = NULL;
    
    const char *allow_path = getenv_or("ALLOW_LIST_FILE", "/etc/proc_killer/proc_allow_list");
    struct stat st_allow;
    int allow_changed = (stat(allow_path, &st_allow) == 0 && st_allow.st_mtime > allow_list_mtime);
    if (allow_changed) {
        syslog(LOG_INFO, "Loading new allow list: %s", allow_path);
        new_allow = load_list_to_hashtable(allow_path);
        if (!new_allow) {
            syslog(LOG_ERR, "Failed to load new allow list.");
            success = 0;
        }
    }

    const char *users_path = getenv_or("USER_LIST_FILE", "/etc/proc_killer/monitor_users");
    struct stat st_users;
    int users_changed = (stat(users_path, &st_users) == 0 && st_users.st_mtime > user_list_mtime);
    if (users_changed) {
        syslog(LOG_INFO, "Loading new user limits: %s", users_path);
        new_users = load_user_limits_to_hashtable(users_path);
        if (!new_users) {
            syslog(LOG_ERR, "Failed to load new user limits.");
            success = 0;
        }
    }

    const char *blacklist_path = getenv_or("CMDLINE_BLACKLIST_FILE", "/etc/proc_killer/cmdline_blacklist_regex");
    struct stat st_blacklist;
    int blacklist_changed = (stat(blacklist_path, &st_blacklist) == 0 && st_blacklist.st_mtime > blacklist_mtime);
    if (blacklist_changed) {
        syslog(LOG_INFO, "Loading new blacklist: %s", blacklist_path);
        new_blacklist = load_regex_list(blacklist_path);
        if (!new_blacklist) {
            syslog(LOG_ERR, "Failed to load new blacklist.");
            success = 0;
        }
    }
    
    // Check if any file exists at all
    if (CONFIG_REQUIRED && (!new_allow || !new_users || !new_blacklist)) {
        syslog(LOG_ERR, "CONFIG_REQUIRED is set and one or more configuration files failed to load. Aborting.");
        config_failed_flag = 1;
        // Free temp pointers before exit
        if (new_allow) free_hashtable(new_allow, NULL);
        if (new_users) free_hashtable(new_users, free);
        if (new_blacklist) free_regex_list(new_blacklist);
        return;
    }

    if (success) {
        if (new_allow) {
            free_hashtable(allow_list_ht, NULL);
            allow_list_ht = new_allow;
            allow_list_mtime = st_allow.st_mtime;
        }
        if (new_users) {
            free_hashtable(user_limits_ht, free);
            user_limits_ht = new_users;
            user_list_mtime = st_users.st_mtime;
        }
        if (new_blacklist) {
            free_regex_list(blacklist_head);
            blacklist_head = new_blacklist;
            blacklist_mtime = st_blacklist.st_mtime;
        }
        syslog(LOG_INFO, "Configuration reload complete.");
        config_failed_flag = 0;
    } else {
        syslog(LOG_WARNING, "Configuration reload failed. Continuing with previous settings.");
        // Free temporarily allocated memory if a failure occurred
        if (new_allow) free_hashtable(new_allow, NULL);
        if (new_users) free_hashtable(new_users, free);
        if (new_blacklist) free_regex_list(new_blacklist);
    }
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

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "Error: must be root to start.\n");
        return 1;
    }

    if (check_config_permissions(getenv_or("ALLOW_LIST_FILE", "/etc/proc_killer/proc_allow_list")) != 0 ||
        check_config_permissions(getenv_or("USER_LIST_FILE", "/etc/proc_killer/monitor_users")) != 0 ||
        check_config_permissions(getenv_or("CMDLINE_BLACKLIST_FILE", "/etc/proc_killer/cmdline_blacklist_regex")) != 0) {
        fprintf(stderr, "Aborting due to insecure configuration file permissions.\n");
        return 1;
    }

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

    if (getenv("NOTIFY_SOCKET") == NULL) {
        daemonize();
        openlog("proc_killer", LOG_PID | LOG_NDELAY, LOG_DAEMON);
        PID_FILE = getenv_or("PID_FILE", "/run/proc_killer.pid");
        write_pid_file(PID_FILE);
    } else {
        openlog("proc_killer", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    }
    
#ifdef __linux__
    if (syscall(SYS_close_range, 3, ~0U, 0) == -1 && errno == ENOSYS) {
        for (int x = sysconf(_SC_OPEN_MAX); x >= 3; x--) {
            close(x);
        }
    }
#elif defined(__FreeBSD__)
    closefrom(3);
#else
    for (int x = sysconf(_SC_OPEN_MAX); x >= 3; x--) {
        close(x);
    }
#endif
    
    stdin = fopen("/dev/null", "r");
    stdout = fopen("/dev/null", "w");
    stderr = fopen("/dev/null", "w");

    syslog(LOG_INFO, "proc_killer daemon starting.");

    CHECK_INTERVAL = atoi(getenv_or("CHECK_INTERVAL", "30"));
    MAX_SECONDS    = atoi(getenv_or("MAX_SECONDS", "300"));
    GRACE_PERIOD   = atoi(getenv_or("GRACE_PERIOD", "5"));
    LOG_RATE_LIMIT_SECONDS = atoi(getenv_or("LOG_RATE_LIMIT_SECONDS", "30"));
    DEBUG_LEVEL    = atoi(getenv_or("DEBUG_LEVEL", "3"));
    CONFIG_REQUIRED = atoi(getenv_or("CONFIG_REQUIRED", "0"));

    // Check for --safe-mode argument
    if (argc > 1 && strcmp(argv[1], "--safe-mode") == 0) {
        DEBUG_LEVEL = 0;
    }
    
    switch (DEBUG_LEVEL) {
        case 0: log_level = LOG_INFO; break;
        case 1: log_level = LOG_DEBUG; break;
        case 2: log_level = LOG_INFO; break;
        case 3:
        default: log_level = LOG_NOTICE; break;
    }
    setlogmask(LOG_UPTO(log_level));
    
    allow_list_ht = create_hashtable();
    user_limits_ht = create_hashtable();
    uid_cache_ht = create_hashtable();
    kill_list_ht = create_hashtable();
    log_rate_ht = create_hashtable();
    
    // Initial heap capacity is 1024, now dynamically extended
    kill_heap = minheap_create(1024);
    
    if (!allow_list_ht || !user_limits_ht || !uid_cache_ht || !kill_list_ht || !log_rate_ht || !kill_heap) {
        syslog(LOG_ERR, "Failed to initialize data structures. Aborting.");
        cleanup();
        return 1;
    }

    reload_config();
    if (config_failed_flag) {
        if (CONFIG_REQUIRED) {
            syslog(LOG_ERR, "Initial configuration load failed and CONFIG_REQUIRED is set. Aborting.");
            cleanup();
            return 1;
        } else {
            DEBUG_LEVEL = 0;
            syslog(LOG_WARNING, "Initial configuration load failed. Starting in SAFE MODE (DEBUG_LEVEL=0). No processes will be killed until a successful reload.");
        }
    }
    
    #ifdef __linux__
    sd_notify(0, "READY=1\nSTATUS=Monitoring processes...");
    #endif

    while (!shutdown_flag) {
        if (reload_flag) {
            reload_config();
            reload_flag = 0;
            if (config_failed_flag) {
                if (CONFIG_REQUIRED) {
                    syslog(LOG_ERR, "Configuration reload failed and CONFIG_REQUIRED is set. Shutting down.");
                    shutdown_flag = 1;
                    continue;
                } else {
                    DEBUG_LEVEL = 0;
                    syslog(LOG_WARNING, "Configuration reload failed again. Remaining in SAFE MODE.");
                }
            }
            #ifdef __linux__
            sd_notify(0, "STATUS=Configuration reloaded. Monitoring processes...");
            #endif
        }

        #ifdef __linux__
        sd_notify(0, "WATCHDOG=1");
        #endif
        
        monitor();
        sleep(CHECK_INTERVAL);
    }

    syslog(LOG_INFO, "proc_killer daemon shutting down.");
    cleanup();
    return 0;
}
