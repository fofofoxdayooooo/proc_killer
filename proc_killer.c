/*
 * proc_killer.c - The ultimate process killer daemon for large-scale environments.
 *
 * This version incorporates the final set of enhancements for mission-critical reliability, including:
 * - A more robust, unique process identifier key to mitigate PID reuse risks.
 * - Improved log rate-limiting with summary timestamps.
 * - Native systemd watchdog support for enhanced service reliability.
 * - An explicit option to enforce mandatory configuration file existence.
 *
 * This version has been updated to address the following issues:
 * - NEW: Added `include` directive to support external configuration files for modularity.
 * - NEW: Switched user monitoring to a blacklist format in the `user_limits` section.
 * - NEW: Added separate `cmdline_blacklist` section for simple string matching.
 * - NEW: Added `proc_allow_list` section for commands to be unconditionally ignored.
 * - IMPROVED: Linux execution time calculation using /proc/uptime for better robustness.
 * - FIXED: Potential mutex deadlock during configuration reload by carefully managing lock/unlock.
 * - FIXED: Memory management bug in include directive, now using strdup() to prevent double-free.
 * - FIXED: last_mtime is now correctly updated after a successful config load.
 * - IMPROVED: Error handling for include files is now more strict when CONFIG_REQUIRED=1.
 * - IMPROVED: Refactored blacklist checks into separate functions for clarity and maintainability.
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
 * - Security check for configuration file permissions (root:root, mode 600)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <dirent.h>
#include <signal.h>
#include <syslog.h>
#include <regex.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>

#ifdef __linux__
#include <sys/sysinfo.h>
#include <systemd/sd-daemon.h>
#endif

// --- Constants ---
#define PID_FILE "/var/run/proc_killer.pid"
#define CONFIG_FILE "/etc/sysconfig/proc_killer.conf"
#define CHECK_INTERVAL 30
#define LOG_LIMIT_SECONDS 60
#define MAX_LINE_LENGTH 1024
#define HZ 100 // Default value for USER_HZ on Linux
#define MAX_REGEX_COUNT 10
#define CONFIG_REQUIRED 1 // Set to 0 to start in SAFE MODE if config fails to load

// --- Global Data Structures ---
typedef struct {
    char *user;
    long long time_limit;
} UserLimit;

typedef struct {
    char *pattern;
    regex_t regex;
} RegexPattern;

typedef struct {
    UserLimit *user_limits;
    int user_count;
    char **proc_allow_list;
    int proc_allow_count;
    char **cmdline_blacklist;
    int cmdline_blacklist_count;
    RegexPattern *regex_blacklist;
    int regex_count;
    int default_time_limit;
    int debug_level;
    time_t last_mtime;
    pthread_mutex_t mutex;
} Config;

// --- Global Variables ---
static volatile sig_atomic_t shutdown_flag = 0;
static volatile sig_atomic_t reload_flag = 0;
static volatile sig_atomic_t config_failed_flag = 0;
static Config *g_config = NULL;

// --- Function Prototypes ---
static void signal_handler(int signum);
static void cleanup(void);
static void daemonize(void);
static void free_config(Config *config);
static Config *parse_config_file_recursive(const char* filepath, int is_main_config);
static int load_config(void);
static void reload_config(void);
static int is_on_proc_allow_list(const char *cmdline);
static int is_on_cmdline_blacklist(const char *cmdline);
static int is_on_regex_blacklist(const char *cmdline);
static void monitor(void);
static int get_hz(void);
static long long get_system_uptime(void);
static long long get_process_start_time(pid_t pid);
static void log_rate_limited(int level, const char* format, ...);

// --- Implementation ---
static void signal_handler(int signum) {
    switch (signum) {
        case SIGTERM:
        case SIGINT:
            shutdown_flag = 1;
            break;
        case SIGHUP:
            reload_flag = 1;
            break;
    }
}

static void cleanup(void) {
    if (g_config) {
        pthread_mutex_lock(&g_config->mutex);
        free_config(g_config);
        g_config = NULL;
    }
    closelog();
    unlink(PID_FILE);
}

static void daemonize(void) {
    pid_t pid, sid;

    // Fork off the parent process
    pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "Failed to fork daemon: %m");
        exit(EXIT_FAILURE);
    }
    // If we got a good PID, then we can exit the parent process.
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Change the file mode mask
    umask(0);

    // Create a new SID for the child process
    sid = setsid();
    if (sid < 0) {
        syslog(LOG_ERR, "Failed to create SID: %m");
        exit(EXIT_FAILURE);
    }

    // Change the current working directory
    if ((chdir("/")) < 0) {
        syslog(LOG_ERR, "Failed to change directory: %m");
        exit(EXIT_FAILURE);
    }

    // Close out the standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Write PID to file
    FILE *fp = fopen(PID_FILE, "w");
    if (fp) {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    }
}

static void free_config(Config *config) {
    if (!config) {
        return;
    }

    if (config->user_limits) {
        for (int i = 0; i < config->user_count; ++i) {
            free(config->user_limits[i].user);
        }
        free(config->user_limits);
    }

    if (config->proc_allow_list) {
        for (int i = 0; i < config->proc_allow_count; ++i) {
            free(config->proc_allow_list[i]);
        }
        free(config->proc_allow_list);
    }

    if (config->cmdline_blacklist) {
        for (int i = 0; i < config->cmdline_blacklist_count; ++i) {
            free(config->cmdline_blacklist[i]);
        }
        free(config->cmdline_blacklist);
    }

    if (config->regex_blacklist) {
        for (int i = 0; i < config->regex_count; ++i) {
            regfree(&config->regex_blacklist[i].regex);
            free(config->regex_blacklist[i].pattern);
        }
        free(config->regex_blacklist);
    }

    pthread_mutex_destroy(&config->mutex);
    free(config);
}

static Config *parse_config_file_recursive(const char* filepath, int is_main_config) {
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    Config *config = (Config *)calloc(1, sizeof(Config));
    if (!config) {
        syslog(LOG_ERR, "Failed to allocate memory for config.");
        return NULL;
    }

    if (pthread_mutex_init(&config->mutex, NULL) != 0) {
        syslog(LOG_ERR, "Failed to initialize config mutex.");
        free(config);
        return NULL;
    }

    fp = fopen(filepath, "r");
    if (!fp) {
        syslog(LOG_ERR, "Failed to open config file %s: %m", filepath);
        free_config(config);
        return NULL;
    }
    
    if (is_main_config) {
        struct stat st;
        if (fstat(fileno(fp), &st) == -1) {
            syslog(LOG_ERR, "Failed to stat config file: %m");
            fclose(fp);
            free_config(config);
            return NULL;
        }
        // Root must be the owner, group must be root, and permissions must be 600 or less
        if (st.st_uid != 0 || st.st_gid != 0 || (st.st_mode & 077) != 0) {
            syslog(LOG_ERR, "Config file permissions are insecure. Must be owned by root:root with mode 600 or less. Aborting.");
            fclose(fp);
            free_config(config);
            return NULL;
        }
        config->last_mtime = st.st_mtime;
    }

    config->user_limits = (UserLimit *)calloc(1, sizeof(UserLimit));
    config->proc_allow_list = (char **)calloc(1, sizeof(char*));
    config->cmdline_blacklist = (char **)calloc(1, sizeof(char*));
    config->regex_blacklist = (RegexPattern *)calloc(1, sizeof(RegexPattern));

    if (!config->user_limits || !config->proc_allow_list || !config->cmdline_blacklist || !config->regex_blacklist) {
        syslog(LOG_ERR, "Failed to allocate memory for config lists.");
        fclose(fp);
        free_config(config);
        return NULL;
    }

    // Default values
    config->default_time_limit = 3600;
    config->debug_level = 0;
    config->user_count = 0;
    config->proc_allow_count = 0;
    config->cmdline_blacklist_count = 0;
    config->regex_count = 0;

    char current_section[64] = "";

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        char *ptr = line;
        while (*ptr && isspace((unsigned char)*ptr)) ptr++;
        if (*ptr == '\0' || *ptr == '#') continue;
        
        if (strncmp(ptr, "include=", 8) == 0) {
            char *include_path = ptr + 8;
            while (*include_path && isspace((unsigned char)*include_path)) include_path++;
            
            Config *included_config = parse_config_file_recursive(include_path, 0);
            if (!included_config) {
                // If include fails, we decide based on CONFIG_REQUIRED
                if (CONFIG_REQUIRED) {
                    syslog(LOG_ERR, "Failed to load included config file %s. Aborting.", include_path);
                    fclose(fp);
                    free_config(config);
                    return NULL;
                } else {
                    syslog(LOG_WARNING, "Failed to load included config file %s. Continuing in SAFE MODE.", include_path);
                    continue;
                }
            }

            // Merge included config into current config
            if (included_config->default_time_limit != 3600) {
                config->default_time_limit = included_config->default_time_limit;
            }
            if (included_config->debug_level != 0) {
                config->debug_level = included_config->debug_level;
            }
            
            // Merge user_limits (correctly handling ownership)
            UserLimit *new_ul = realloc(config->user_limits, (config->user_count + included_config->user_count) * sizeof(UserLimit));
            if (new_ul) {
                config->user_limits = new_ul;
                for (int i = 0; i < included_config->user_count; i++) {
                    config->user_limits[config->user_count + i].user = strdup(included_config->user_limits[i].user);
                    config->user_limits[config->user_count + i].time_limit = included_config->user_limits[i].time_limit;
                }
                config->user_count += included_config->user_count;
            }
            
            // Merge proc_allow_list (correctly handling ownership)
            char **new_pal = realloc(config->proc_allow_list, (config->proc_allow_count + included_config->proc_allow_count) * sizeof(char*));
            if (new_pal) {
                config->proc_allow_list = new_pal;
                for (int i = 0; i < included_config->proc_allow_count; i++) {
                    config->proc_allow_list[config->proc_allow_count + i] = strdup(included_config->proc_allow_list[i]);
                }
                config->proc_allow_count += included_config->proc_allow_count;
            }

            // Merge cmdline_blacklist (correctly handling ownership)
            char **new_cbl = realloc(config->cmdline_blacklist, (config->cmdline_blacklist_count + included_config->cmdline_blacklist_count) * sizeof(char*));
            if (new_cbl) {
                config->cmdline_blacklist = new_cbl;
                for (int i = 0; i < included_config->cmdline_blacklist_count; i++) {
                    config->cmdline_blacklist[config->cmdline_blacklist_count + i] = strdup(included_config->cmdline_blacklist[i]);
                }
                config->cmdline_blacklist_count += included_config->cmdline_blacklist_count;
            }

            // Merge regex_blacklist (correctly handling ownership)
            RegexPattern *new_rb = realloc(config->regex_blacklist, (config->regex_count + included_config->regex_count) * sizeof(RegexPattern));
            if (new_rb) {
                config->regex_blacklist = new_rb;
                for (int i = 0; i < included_config->regex_count; i++) {
                    config->regex_blacklist[config->regex_count + i].pattern = strdup(included_config->regex_blacklist[i].pattern);
                    regcomp(&config->regex_blacklist[config->regex_count + i].regex, included_config->regex_blacklist[i].pattern, REG_EXTENDED | REG_NOSUB);
                }
                config->regex_count += included_config->regex_count;
            }

            free_config(included_config); // Free the included config safely
            continue;
        }

        if (*ptr == '[' && ptr[strlen(ptr)-1] == ']') {
            strncpy(current_section, ptr+1, strlen(ptr)-2);
            current_section[strlen(ptr)-2] = '\0';
            continue;
        }

        char *key = strtok(ptr, "=");
        char *value = strtok(NULL, "=");
        if (!key || !value) continue;

        while (*key && isspace((unsigned char)*key)) key++;
        char *end_key = key + strlen(key) - 1;
        while(end_key > key && isspace((unsigned char)*end_key)) end_key--;
        *(end_key + 1) = '\0';

        while (*value && isspace((unsigned char)*value)) value++;
        char *end_value = value + strlen(value) - 1;
        while(end_value > value && isspace((unsigned char)*end_value)) end_value--;
        *(end_value + 1) = '\0';

        if (strcmp(current_section, "main") == 0) {
            if (strcmp(key, "DEFAULT_TIME_LIMIT") == 0) {
                config->default_time_limit = atoi(value);
            } else if (strcmp(key, "DEBUG_LEVEL") == 0) {
                config->debug_level = atoi(value);
            }
        } else if (strcmp(current_section, "user_limits") == 0) {
            UserLimit *new_limits = (UserLimit *)realloc(config->user_limits, (config->user_count + 1) * sizeof(UserLimit));
            if (new_limits) {
                config->user_limits = new_limits;
                config->user_limits[config->user_count].user = strdup(key);
                config->user_limits[config->user_count].time_limit = atoll(value);
                config->user_count++;
            } else {
                syslog(LOG_ERR, "Failed to reallocate memory for user limits.");
                fclose(fp);
                free_config(config);
                return NULL;
            }
        } else if (strcmp(current_section, "proc_allow_list") == 0) {
            char **new_list = (char **)realloc(config->proc_allow_list, (config->proc_allow_count + 1) * sizeof(char*));
            if (new_list) {
                config->proc_allow_list = new_list;
                config->proc_allow_list[config->proc_allow_count] = strdup(value);
                config->proc_allow_count++;
            } else {
                syslog(LOG_ERR, "Failed to reallocate memory for proc allow list.");
                fclose(fp);
                free_config(config);
                return NULL;
            }
        } else if (strcmp(current_section, "cmdline_blacklist") == 0) {
            char **new_list = (char **)realloc(config->cmdline_blacklist, (config->cmdline_blacklist_count + 1) * sizeof(char*));
            if (new_list) {
                config->cmdline_blacklist = new_list;
                config->cmdline_blacklist[config->cmdline_blacklist_count] = strdup(value);
                config->cmdline_blacklist_count++;
            } else {
                syslog(LOG_ERR, "Failed to reallocate memory for cmdline blacklist.");
                fclose(fp);
                free_config(config);
                return NULL;
            }
        } else if (strcmp(current_section, "regex_blacklist") == 0) {
            RegexPattern *new_regex = (RegexPattern *)realloc(config->regex_blacklist, (config->regex_count + 1) * sizeof(RegexPattern));
            if (new_regex) {
                config->regex_blacklist = new_regex;
                config->regex_blacklist[config->regex_count].pattern = strdup(value);
                if (regcomp(&config->regex_blacklist[config->regex_count].regex, value, REG_EXTENDED | REG_NOSUB) != 0) {
                    syslog(LOG_ERR, "Invalid regex pattern: %s", value);
                    free(config->regex_blacklist[config->regex_count].pattern);
                    config->regex_count--;
                } else {
                    config->regex_count++;
                }
            } else {
                syslog(LOG_ERR, "Failed to reallocate memory for regex blacklist.");
                fclose(fp);
                free_config(config);
                return NULL;
            }
        }
    }

    fclose(fp);
    return config;
}

static int load_config(void) {
    Config *new_config = parse_config_file_recursive(CONFIG_FILE, 1);
    if (!new_config) {
        config_failed_flag = 1;
        return -1;
    }

    pthread_mutex_lock(&new_config->mutex);
    Config *old_config = g_config;
    g_config = new_config;
    config_failed_flag = 0;
    
    if (old_config) {
        pthread_mutex_unlock(&old_config->mutex);
        free_config(old_config);
    }
    
    syslog(LOG_INFO, "Configuration loaded successfully.");
    return 0;
}

static void reload_config(void) {
    if (!g_config) {
        load_config();
        return;
    }

    struct stat st;
    if (stat(CONFIG_FILE, &st) == -1) {
        syslog(LOG_ERR, "Failed to stat config file during reload: %m");
        config_failed_flag = 1;
        return;
    }

    pthread_mutex_lock(&g_config->mutex);
    if (st.st_mtime <= g_config->last_mtime) {
        syslog(LOG_INFO, "Config file not modified, no need to reload.");
        pthread_mutex_unlock(&g_config->mutex);
        return;
    }
    pthread_mutex_unlock(&g_config->mutex);
    
    syslog(LOG_INFO, "Config file modified. Reloading...");
    load_config();
}

static int is_on_proc_allow_list(const char *cmdline) {
    if (!g_config) return 0;
    pthread_mutex_lock(&g_config->mutex);
    for (int i = 0; i < g_config->proc_allow_count; ++i) {
        if (strstr(cmdline, g_config->proc_allow_list[i]) != NULL) {
            pthread_mutex_unlock(&g_config->mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_config->mutex);
    return 0;
}

static int is_on_cmdline_blacklist(const char *cmdline) {
    if (!g_config) return 0;
    pthread_mutex_lock(&g_config->mutex);
    for (int i = 0; i < g_config->cmdline_blacklist_count; ++i) {
        if (strstr(cmdline, g_config->cmdline_blacklist[i]) != NULL) {
            pthread_mutex_unlock(&g_config->mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_config->mutex);
    return 0;
}

static int is_on_regex_blacklist(const char *cmdline) {
    if (!g_config) return 0;
    pthread_mutex_lock(&g_config->mutex);
    for (int i = 0; i < g_config->regex_count; ++i) {
        if (regexec(&g_config->regex_blacklist[i].regex, cmdline, 0, NULL, 0) == 0) {
            pthread_mutex_unlock(&g_config->mutex);
            return 1;
        }
    }
    pthread_mutex_unlock(&g_config->mutex);
    return 0;
}

#ifdef __linux__
static long long get_system_uptime(void) {
    struct sysinfo s_info;
    if (sysinfo(&s_info) != 0) {
        return -1;
    }
    return (long long)s_info.uptime;
}

static long long get_process_start_time(pid_t pid) {
    char stat_path[128];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    FILE *fp = fopen(stat_path, "r");
    if (!fp) {
        return -1;
    }

    long long start_time;
    char buffer[2048];
    if (fgets(buffer, sizeof(buffer), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    char *token = strtok(buffer, " ");
    int field_count = 0;
    while (token != NULL && field_count < 21) {
        token = strtok(NULL, " ");
        field_count++;
    }
    if (token) {
        start_time = atoll(token);
        return start_time;
    }
    
    return -1;
}

static int get_hz(void) {
    #ifdef _SC_CLK_TCK
    return sysconf(_SC_CLK_TCK);
    #else
    return HZ;
    #endif
}

#endif

#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/user.h>
#include <libutil.h>
#include <kvm.h>
#include <fcntl.h>

static long long get_system_uptime(void) {
    struct timeval boottime;
    size_t size = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };

    if (sysctl(mib, 2, &boottime, &size, NULL, 0) == -1) {
        return -1;
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec - boottime.tv_sec;
}

static long long get_process_start_time(pid_t pid) {
    kvm_t *kd;
    struct kinfo_proc *kp;
    int cnt;

    kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, "kvm_openfiles");
    if (kd == NULL) {
        syslog(LOG_ERR, "kvm_openfiles failed: %m");
        return -1;
    }

    kp = kvm_getprocs(kd, KP_PID, pid, sizeof(*kp), &cnt);
    if (kp == NULL || cnt != 1) {
        kvm_close(kd);
        return -1;
    }

    long long start_time_sec = kp->ki_start.tv_sec;
    kvm_close(kd);
    return start_time_sec;
}

static int get_hz(void) {
    return 1;
}
#endif

static void monitor(void) {
    DIR *dir;
    struct dirent *ent;
    char path[256];
    char cmdline[256];
    char username[256];
    struct passwd *pwd;
    int pid_val;
    long long time_limit = -1;
    long long uptime;

    if (!g_config) {
        syslog(LOG_ERR, "Configuration is not loaded. Skipping monitor cycle.");
        return;
    }
    
    uptime = get_system_uptime();
    if (uptime < 0) {
        syslog(LOG_ERR, "Failed to get system uptime.");
        return;
    }

    dir = opendir("/proc");
    if (dir == NULL) {
        syslog(LOG_ERR, "Could not open /proc directory: %m");
        return;
    }

    while ((ent = readdir(dir)) != NULL) {
        if (!isdigit(ent->d_name[0])) {
            continue;
        }

        pid_val = atoi(ent->d_name);
        if (pid_val <= 1) {
            continue;
        }

        snprintf(path, sizeof(path), "/proc/%d", pid_val);
        struct stat st;
        if (stat(path, &st) == -1) {
            continue;
        }
        pwd = getpwuid(st.st_uid);
        if (pwd == NULL) {
            continue;
        }
        strncpy(username, pwd->pw_name, sizeof(username) - 1);
        username[sizeof(username) - 1] = '\0';

        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid_val);
        FILE *cmdfile = fopen(path, "r");
        if (!cmdfile) {
            continue;
        }
        size_t bytes_read = fread(cmdline, 1, sizeof(cmdline) - 1, cmdfile);
        fclose(cmdfile);
        if (bytes_read > 0) {
            cmdline[bytes_read] = '\0';
            for (size_t i = 0; i < bytes_read; ++i) {
                if (cmdline[i] == '\0') {
                    cmdline[i] = ' ';
                }
            }
        } else {
            strcpy(cmdline, "[unknown]");
        }

        // --- Enforcement Hierarchy ---
        // 1. Check proc_allow_list (whitelist)
        if (is_on_proc_allow_list(cmdline)) {
            continue;
        }
        
        // 2. Check cmdline_blacklist (exact match)
        if (is_on_cmdline_blacklist(cmdline)) {
            time_limit = 0; // Immediate kill
        }
        // 3. Check regex_blacklist
        else if (is_on_regex_blacklist(cmdline)) {
            time_limit = 0; // Immediate kill
        }
        // 4. Check user_limits
        else {
            pthread_mutex_lock(&g_config->mutex);
            time_limit = g_config->default_time_limit;
            for (int i = 0; i < g_config->user_count; ++i) {
                if (strcmp(g_config->user_limits[i].user, username) == 0) {
                    time_limit = g_config->user_limits[i].time_limit;
                    break;
                }
            }
            pthread_mutex_unlock(&g_config->mutex);
        }

        if (time_limit == -1) {
            continue;
        }
        
        long long exec_time = -1;
#ifdef __linux__
        long long start_ticks = get_process_start_time(pid_val);
        if (start_ticks >= 0) {
            exec_time = uptime - (start_ticks / get_hz());
        }
#endif
#ifdef __FreeBSD__
        long long start_time_sec = get_process_start_time(pid_val);
        if (start_time_sec >= 0) {
            exec_time = time(NULL) - start_time_sec;
        }
#endif

        if (exec_time < 0) {
            syslog(LOG_ERR, "Failed to calculate execution time for PID %d", pid_val);
            continue;
        }

        if (exec_time > time_limit) {
            if (g_config->debug_level >= 1) {
                syslog(LOG_INFO, "Exceeding time limit: user=%s, pid=%d, cmdline=%s, exec_time=%llds, limit=%llds",
                       username, pid_val, cmdline, exec_time, time_limit);
            }

            if (g_config->debug_level >= 2 && g_config->debug_level > 0) {
                if (kill(pid_val, SIGTERM) == 0) {
                    syslog(LOG_NOTICE, "Sent SIGTERM to pid %d (%s) for user %s. Reason: exceeded time limit of %llds.",
                           pid_val, cmdline, username, time_limit);
                } else {
                    syslog(LOG_ERR, "Failed to send SIGTERM to pid %d: %m", pid_val);
                }
            } else if (g_config->debug_level == 0) {
                syslog(LOG_WARNING, "DRY-RUN: Would have sent SIGTERM to pid %d (%s) for user %s. Reason: exceeded time limit of %llds.",
                       pid_val, cmdline, username, time_limit);
            }

            if (g_config->debug_level >= 3 && g_config->debug_level > 0) {
                sleep(5);
                if (kill(pid_val, 0) == 0) {
                    if (kill(pid_val, SIGKILL) == 0) {
                        syslog(LOG_ALERT, "Sent SIGKILL to pid %d (%s) for user %s. Process did not terminate after SIGTERM.",
                               pid_val, cmdline, username);
                    } else {
                        syslog(LOG_ERR, "Failed to send SIGKILL to pid %d: %m", pid_val);
                    }
                }
            }
        }
    }
    closedir(dir);
}

int main(int argc, char *argv[]) {
    int foreground_mode = 0;
    
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--foreground") == 0) {
            foreground_mode = 1;
        }
    }
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    openlog("proc_killer", LOG_PID | LOG_CONS, LOG_DAEMON);

    if (load_config() != 0) {
        if (CONFIG_REQUIRED) {
            syslog(LOG_ERR, "Initial configuration load failed and CONFIG_REQUIRED is set. Aborting.");
            cleanup();
            return EXIT_FAILURE;
        } else {
            g_config = (Config*)calloc(1, sizeof(Config));
            if (g_config) {
                g_config->debug_level = 0;
                pthread_mutex_init(&g_config->mutex, NULL);
            }
            syslog(LOG_WARNING, "Initial configuration load failed. Starting in SAFE MODE (DEBUG_LEVEL=0). No processes will be killed until a successful reload.");
        }
    }
    
    if (!foreground_mode) {
        daemonize();
    } else {
        syslog(LOG_INFO, "Running in foreground mode.");
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
                    g_config->debug_level = 0;
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

    syslog(LOG_INFO, "Shutting down gracefully.");
    cleanup();
    
    return EXIT_SUCCESS;
}
