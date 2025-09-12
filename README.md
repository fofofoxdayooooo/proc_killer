# proc-killer

**proc-killer** is a daemon designed to automatically monitor and terminate long-running processes that match specified users or command-line regular expressions. It is optimized for resource management and ensuring stability in shared server environments.

---

## Features

- **Cross-Platform Support**  
  Works on both Linux and FreeBSD.

- **Flexible Configuration**  
  Managed via environment variables and configuration files (`EnvironmentFile`).

- **Per-User Time Limits**  
  Define custom execution time limits for specific users.

- **Blacklisting**  
  Kill processes automatically if their command line matches regex patterns.

- **Whitelisting**  
  Processes in the allow list are exempt from time limits.

- **Graceful Termination**  
  Sends `SIGTERM` first, followed by `SIGKILL` after a grace period if necessary.

- **Real-time Config Reload**  
  Reload configuration on the fly by sending `SIGHUP`.

- **Detailed Logging**  
  All actions are logged via `syslog` (facility: `DAEMON`).

---

## Compilation

`proc-killer` requires the regex library.

**Linux:**
```bash
gcc -O2 -Wall -o proc_killer proc_killer.c -lregex

***FreeBSD:***
cc -O2 -Wall -o proc_killer proc_killer.c -lregex
