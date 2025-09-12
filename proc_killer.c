/*
 * proc_killer.c - Process killer daemon (Linux + FreeBSD)
 *
 * Features:
 * - Runs as root only
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
 *
 * Compilation:
 * Linux:   gcc -O2 -Wall -o proc_killer proc_killer.c -lregex
 * FreeBSD: cc  -O2 -Wall -o proc_killer proc_killer.c -lregex
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

#ifdef __FreeBSD__
#include <sys/sysctl.h>
#include <sys/user.h>
#endif

#define DEFAULT_ALLOW_LIST          "/etc/poc_check/proc_allow_list"
#define DEFAULT_USER_LIST           "/etc/poc_check/monitor_users"
#define DEFAULT_PID_FILE            "/run/proc_killer.pid"
#define DEFAULT_CMDLINE_BLACKLIST   "/etc/poc_check/cmdline_blacklist_regex"
#define DEFAULT_CHECK_INTERVAL      30
#define DEFAULT_MAX_SECONDS         300
#define DEFAULT_GRACE_PERIOD        5

// Global configuration pointers for easy cleanup and reloading
Node *allow = NULL;
UserLimit *users = NULL;
RegexNode *blacklist = NULL;

int DEBUG_LEVEL = 3;
int CHECK_INTERVAL;
int MAX_SECONDS;
int GRACE_PERIOD;
const char *PID_FILE;

volatile sig_atomic_t reload_flag = 0;
volatile sig_atomic_t shutdown_flag = 0;

/* -------- Utility -------- */

const char *getenv_or(const char *key, const char *fallback) {
    const char *val = getenv(key);
    return val ? val : fallback;
}

Node *load_list(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    Node *head = NULL, *cur = NULL;
    char buf[512];
    while (fgets(buf, sizeof(buf), fp)) {
        buf[strcspn(buf, "\r\n")] = 0;
        if (strlen(buf) == 0 || buf[0] == '#') continue;
        Node *n = malloc(sizeof(Node));
        if (!n) { /* Handle malloc failure */ continue; }
        n->value = strdup(buf);
        if (!n->value) { free(n); continue; }
        n->next = NULL;
        if (!head) head = n;
        else cur->next = n;
        cur = n;
    }
    fclose(fp);
    return head;
}

int in_list(Node *head, const char *val) {
    for (Node *n = head; n; n = n->next) {
        if (strcmp(n->value, val) == 0) return 1;
    }
    return 0;
}

void free_list(Node *head) {
    while (head) {
        Node *tmp = head;
        head = head->next;
        free(tmp->value);
        free(tmp);
    }
}

RegexNode *load_regex_list(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    char line[1024];
    RegexNode *head = NULL, *tail = NULL;
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || strlen(line) == 0) continue;
        RegexNode *node = calloc(1, sizeof(RegexNode));
        if (!node) { /* Handle calloc failure */ continue; }
        if (regcomp(&node->regex, line, REG_EXTENDED | REG_NOSUB) != 0) {
            syslog(LOG_WARNING, "Failed to compile regex: %s", line);
            free(node);
            continue;
        }
        node->next = NULL;
        if (!head) head = node;
        else tail->next = node;
        tail = node;
    }
    fclose(fp);
    return head;
}

int match_regex_list(RegexNode *head, const char *cmdline) {
    if (!cmdline) return 0;
    for (RegexNode *node = head; node; node = node->next) {
        if (regexec(&node->regex, cmdline, 0, NULL, 0) == 0)
            return 1;
    }
    return 0;
}

void free_regex_list(RegexNode *head) {
    while (head) {
        RegexNode *tmp = head;
        head = head->next;
        regfree(&tmp->regex);
        free(tmp);
    }
}

UserLimit *load_user_limits(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    char line[256];
    UserLimit *head=NULL, *tail=NULL;
    while (fgets(line,sizeof(line),fp)) {
        line[strcspn(line,"\r\n")] = 0;
        if (line[0]=='#' || strlen(line)==0) continue;
        char *tok = strtok(line,",");
        if (!tok) continue;
        UserLimit *u = calloc(1,sizeof(UserLimit));
        if (!u) { continue; }
        u->user = strdup(tok);
        if (!u->user) { free(u); continue; }
        char *limit_str = strtok(NULL,",");
        if (limit_str) u->limit = atoi(limit_str);
        else u->limit = 0; // default
        u->next = NULL;
        if (!head) head=u; else tail->next=u;
        tail=u;
    }
    fclose(fp);
    return head;
}

int get_user_limit(UserLimit *list, const char *uname, int default_limit) {
    if (!list || !uname) return -1;
    for (UserLimit *u=list; u; u=u->next) {
        if (strcmp(u->user, uname)==0) {
            return (u->limit>0)? u->limit : default_limit;
        }
    }
    return -1; // not monitored
}

void free_user_limits(UserLimit *list) {
    while (list) {
        UserLimit *tmp=list;
        list=list->next;
        free(tmp->user);
        free(tmp);
    }
}

void log_action(const char *user, pid_t pid,
                const char *exe, int etime, const char *action) {
    syslog(LOG_NOTICE, "proc_killer %s USER=%s PID=%d EXE=%s ETIME=%ds",
           action, user, pid, exe, etime);
}

void write_pid_file(const char *path) {
    FILE *fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "%d\n", getpid());
        fclose(fp);
    } else {
        syslog(LOG_ERR, "Failed to write PID file: %s", path);
    }
}

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
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) close(x);
}

/* -------- Platform-specific process scan -------- */

#ifdef __linux__

char *read_cmdline(pid_t pid, char *buf, size_t buflen) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    size_t len = fread(buf, 1, buflen - 1, fp);
    fclose(fp);
    if (len == 0) return NULL;
    for (size_t i = 0; i < len - 1; i++) {
        if (buf[i] == '\0') buf[i] = ' ';
    }
    buf[len] = '\0';
    return buf;
}

int get_process_info(pid_t pid, char *comm, size_t clen,
                     uid_t *uid, int *etime, char *exepath, size_t plen) {
    char path[256], buf[1024];
    FILE *fp;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    if (!fp) return -1;
    if (!fgets(buf, sizeof(buf), fp)) { fclose(fp); return -1; }
    fclose(fp);

    char comm_raw[256];
    long long start_ticks;
    sscanf(buf, "%*d (%255[^)]) %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %lld",
           comm_raw, &start_ticks);
    strncpy(comm, comm_raw, clen);
    comm[clen-1] = '\0';

    struct stat st;
    snprintf(path, sizeof(path), "/proc/%d", pid);
    if (stat(path, &st) == -1) return -1;
    *uid = st.st_uid;

    double uptime = 0.0;
    fp = fopen("/proc/uptime", "r");
    if (!fp) return -1;
    if (fscanf(fp, "%lf", &uptime) != 1) { fclose(fp); return -1; }
    fclose(fp);

    long hz = sysconf(_SC_CLK_TCK);
    *etime = (int)(uptime - (start_ticks / hz));
    if (*etime < 0) *etime = 0;

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len2 = readlink(path, exepath, plen-1);
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

void perform_kill(pid_t pid, const char *uname, const char *exepath, int etime, const char *type) {
    if (DEBUG_LEVEL == 1) {
        log_action(uname, pid, exepath, etime, "DETECTED");
        return;
    }
    if (DEBUG_LEVEL >= 2) {
        if (kill(pid, SIGTERM) == 0) {
            log_action(uname, pid, exepath, etime, "SIGTERM");
            if (DEBUG_LEVEL >= 3) {
                sleep(GRACE_PERIOD);
                if (kill(pid, 0) == 0) { // Check if process is still alive
                    if (kill(pid, SIGKILL) == 0) {
                        log_action(uname, pid, exepath, etime, "SIGKILL");
                    }
                }
            }
        }
    }
}

/* -------- Monitor -------- */

void monitor() {
#ifdef __linux__
    DIR *dir = opendir("/proc");
    if (!dir) return;
    struct dirent *ent;
    char cmdbuf[2048];
    while ((ent = readdir(dir))) {
        if (!isdigit(ent->d_name[0])) continue;
        pid_t pid = atoi(ent->d_name);
        char comm[256], exepath[PATH_MAX];
        uid_t uid; int etime;
        if (get_process_info(pid, comm, sizeof(comm), &uid, &etime, exepath, sizeof(exepath)) != 0) continue;
        struct passwd *pw = getpwuid(uid);
        if (!pw) continue;
        const char *uname = pw->pw_name;
        int limit = get_user_limit(users, uname, MAX_SECONDS);
        if (limit < 0) continue;
        char *cmdline = read_cmdline(pid, cmdbuf, sizeof(cmdbuf));
        if (!cmdline) continue;

        if (match_regex_list(blacklist, cmdline)) {
            perform_kill(pid, uname, exepath, etime, "BLACKLISTED");
            continue;
        }

        if (allow && (in_list(allow, comm) || in_list(allow, exepath))) continue;

        if (etime > limit) {
            perform_kill(pid, uname, exepath, etime, "TIMED_OUT");
        }
    }
    closedir(dir);
#endif /* __linux__ */

#ifdef __FreeBSD__
    struct kinfo_proc *procs;
    int n = get_processes(&procs);
    if (n < 0) return;
    time_t now = time(NULL);
    char cmdbuf[2048];
    for (int i=0; i<n; i++) {
        struct kinfo_proc *kp = &procs[i];
        pid_t pid = kp->ki_pid;
        const char *comm = kp->ki_comm;
        uid_t uid = kp->ki_uid;
        struct passwd *pw = getpwuid(uid);
        if (!pw) continue;
        const char *uname = pw->pw_name;
        int limit = get_user_limit(users, uname, MAX_SECONDS);
        if (limit < 0) continue;
        
        // Calculate etime based on start time
        int etime = (int)difftime(now, kp->ki_start.tv_sec);

        char exepath[PATH_MAX]; strncpy(exepath, comm, sizeof(exepath));
        exepath[sizeof(exepath) - 1] = '\0';
        
        char *cmdline = get_freebsd_cmdline(pid, cmdbuf, sizeof(cmdbuf));
        if (!cmdline) {
            // Fallback to comm if cmdline cannot be retrieved
            cmdline = (char *)comm;
        }

        if (match_regex_list(blacklist, cmdline)) {
            perform_kill(pid, uname, exepath, etime, "BLACKLISTED");
            continue;
        }

        if (allow && (in_list(allow, comm) || in_list(allow, exepath))) continue;

        if (etime > limit) {
            perform_kill(pid, uname, exepath, etime, "TIMED_OUT");
        }
    }
    free(procs);
#endif /* __FreeBSD__ */
}

void cleanup() {
    free_list(allow);
    free_user_limits(users);
    free_regex_list(blacklist);
    unlink(PID_FILE);
    closelog();
}

void reload_config() {
    syslog(LOG_INFO, "Reloading configuration...");
    Node *new_allow = load_list(getenv_or("ALLOW_LIST_FILE", DEFAULT_ALLOW_LIST));
    UserLimit *new_users = load_user_limits(getenv_or("USER_LIST_FILE", DEFAULT_USER_LIST));
    RegexNode *new_blacklist = load_regex_list(getenv_or("CMDLINE_BLACKLIST_FILE", DEFAULT_CMDLINE_BLACKLIST));
    
    // Atomically swap and free old configuration
    free_list(allow);
    free_user_limits(users);
    free_regex_list(blacklist);
    
    allow = new_allow;
    users = new_users;
    blacklist = new_blacklist;

    syslog(LOG_INFO, "Configuration reloaded successfully.");
}

void sig_handler(int signo) {
    if (signo == SIGHUP) {
        reload_flag = 1;
    } else if (signo == SIGINT || signo == SIGTERM) {
        shutdown_flag = 1;
    }
}

/* -------- Main -------- */

int main() {
    if (geteuid() != 0) {
        fprintf(stderr, "Error: must be root.\n");
        return 1;
    }

    // Set up signal handlers for graceful management
    if (signal(SIGHUP, sig_handler) == SIG_ERR) {
        perror("signal SIGHUP");
        return 1;
    }
    if (signal(SIGTERM, sig_handler) == SIG_ERR) {
        perror("signal SIGTERM");
        return 1;
    }
    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        perror("signal SIGINT");
        return 1;
    }

    daemonize();

    // Read initial configuration from environment variables
    CHECK_INTERVAL = atoi(getenv_or("CHECK_INTERVAL", "30"));
    MAX_SECONDS    = atoi(getenv_or("MAX_SECONDS", "300"));
    GRACE_PERIOD   = atoi(getenv_or("GRACE_PERIOD", "5"));
    DEBUG_LEVEL    = atoi(getenv_or("DEBUG_LEVEL", "3"));
    PID_FILE       = getenv_or("PID_FILE", DEFAULT_PID_FILE);

    write_pid_file(PID_FILE);

    openlog("proc_killer", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    syslog(LOG_INFO, "proc_killer daemon started.");

    reload_config();

    while (!shutdown_flag) {
        if (reload_flag) {
            reload_config();
            reload_flag = 0;
        }

        monitor();
        sleep(CHECK_INTERVAL);
    }

    syslog(LOG_INFO, "proc_killer daemon shutting down.");
    cleanup();
    return 0;
}
