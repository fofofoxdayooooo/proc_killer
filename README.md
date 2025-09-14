# proc-killer

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
gcc -O2 -Wall -o /usr/local/sbin/proc_killer.c -lregex -lsystemd
```

**Linux (without systemd support):**
```bash
gcc -O2 -Wall -o /usr/local/sbin/proc_killer.c -lregex
```

**FreeBSD:**
```bash
cc -O2 -Wall -o /usr/local/sbin/proc_killer.c -lregex
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
[main]
# デフォルトの制限時間（秒）
DEFAULT_TIME_LIMIT=3600

# ログ出力レベル / kill 動作レベル
# 0 = Dry-run（検知のみ）
# 1 = LOG_DEBUG（検知のみ、killなし）
# 2 = LOG_INFO（SIGTERMのみ）
# 3 = LOG_NOTICE（SIGTERM + SIGKILL）
DEBUG_LEVEL=3

# 外部設定ファイルを include して管理
include=/etc/proc_killer/proc_allow_list.conf
include=/etc/proc_killer/monitor_users.conf
include=/etc/proc_killer/cmdline_blacklist.conf
include=/etc/proc_killer/cmdline_blacklist_regex.conf
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
[user_limits]
attacker=0         # 即 kill
noisyuser=300      # 5分超過で kill
tester=600         # 10分超過で kill
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
systemctl daemon-reexec
systemctl enable proc_killer
systemctl start proc_killer
systemctl status proc_killer

```
Reload configuration at runtime:
```bash
kill -HUP $(cat /run/proc_killer.pid)
```
