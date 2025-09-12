# proc-killer-v9

**proc-killer-v9** is a mission-critical daemon for automatically monitoring and terminating long-running processes in shared server environments.  
It is optimized for both **Linux** and **FreeBSD**, with optional **systemd** integration.

---

## Features

- **Cross-Platform Support**  
  Works on both Linux and FreeBSD.

- **Flexible Configuration**  
  Managed via environment file (`/etc/sysconfig/proc_killer.conf`) and configuration lists (`/etc/poc_check/*`).

- **Per-User Time Limits**  
  Define custom execution time limits for specific users.  
  Format: `user[,seconds]`

- **Command Blacklist**  
  Regex-based filtering for dangerous or unwanted command lines.

- **Whitelisting**  
  Processes in the allow list are exempt from time limits.

- **Graceful Termination**  
  Sends `SIGTERM` first, followed by `SIGKILL` after a grace period.

- **Robust Logging**  
  Uses syslog with rate limiting, log levels adjustable by `DEBUG_LEVEL`.

- **Systemd Integration**  
  Supports watchdog and `sd_notify` for `Type=notify` units.

- **Security Hardened**  
  All config files must be `root:root` with `0600` permissions.  
  `CONFIG_REQUIRED=1` enforces mandatory existence of config files.

---

## Compilation

**Linux (with systemd support):**
```bash
gcc -O2 -Wall -o /usr/local/sbin/proc_killer_v9 proc_killer.c -lregex -lsystemd
```

**Linux (without systemd support):**
```bash
gcc -O2 -Wall -o /usr/local/sbin/proc_killer_v9 proc_killer.c -lregex
```

**FreeBSD:**
```bash
cc -O2 -Wall -o /usr/local/sbin/proc_killer_v9 proc_killer.c -lregex
```
---

## Installation

```bash
# Create directories
mkdir -p /etc/sysconfig
mkdir -p /etc/poc_check
mkdir -p /run

# Create config files
touch /etc/sysconfig/proc_killer.conf
touch /etc/poc_check/proc_allow_list
touch /etc/poc_check/monitor_users
touch /etc/poc_check/cmdline_blacklist
touch /etc/poc_check/cmdline_blacklist_regex

# Secure permissions
chown root:root /etc/sysconfig/proc_killer.conf /etc/poc_check/*
chmod 600 /etc/sysconfig/proc_killer.conf /etc/poc_check/*
```

### Example Configuration
/etc/sysconfig/proc_killer.conf
```bash
CHECK_INTERVAL=30
MAX_SECONDS=300
GRACE_PERIOD=5
DEBUG_LEVEL=3
LOG_RATE_LIMIT_SECONDS=30
CONFIG_REQUIRED=1
ALLOW_LIST_FILE=/etc/poc_check/proc_allow_list
USER_LIST_FILE=/etc/poc_check/monitor_users
CMDLINE_BLACKLIST_FILE=/etc/poc_check/cmdline_blacklist_regex
```

/etc/poc_check/proc_allow_list
```bash
bash
sh
zsh
csh
tcsh
httpd
apache2
php-cgi
php-fpm
perl
python
python3
ruby
proftpd
vsftpd
pure-ftpd
postfix
sendmail
exim
dovecot
courier
imapd
pop3d
sshd
cron
crond
atd
syslogd
rsyslogd
systemd
init
ls
cat
less
more
tail
head
grep
awk
sed
vim
vi
nano
scp
sftp
rsync
wget
curl
tar
gzip
bzip2
xz
zip
unzip
gcc
g++
make
perl
python3
man
```

/etc/poc_check/monitor_users
```bash
# Monitored users and their individual max runtime (seconds).
# Format: username[,seconds]
# If seconds is omitted, fallback to MAX_SECONDS from proc_killer.conf.

user1
user2,40
user3,120
user4
user5,600
```

/etc/poc_check/cmdline_blacklist_regex
```bash
# Regular expressions matched against process command line.
# Any match → highest priority kill (ignores allow list & user limits).

# Perl sleep bombs
^perl .*sleep

# Fork bombs
.*fork.*

# Netcat misuse
(^| )nc( |$)

# Long-running wget or curl
(^| )wget( |$)
(^| )curl( |$)

# Dangerous shell loops
:(){ :|:& };:
```
### Example systemd unit
/etc/systemd/system/proc_killer.service
```bash
[Unit]
Description=Process Killer Daemon
After=network.target

[Service]
Type=notify
ExecStart=/usr/local/sbin/proc_killer_v9
EnvironmentFile=-/etc/sysconfig/proc_killer.conf
Restart=always
WatchdogSec=60s

[Install]
WantedBy=multi-user.target

```

### Usage
Start and enable via systemd:
```bash
systemctl daemon-reload
systemctl enable proc_killer.service
systemctl start proc_killer.service

```
Reload configuration at runtime:
```bash
kill -HUP $(cat /run/proc_killer.pid)
```
