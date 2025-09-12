#!/bin/sh
# Standalone launcher for proc_killer_v9

CONFIG_FILE="/etc/sysconfig/proc_killer.conf"
PID_FILE="/run/proc_killer.pid"
DAEMON="/usr/local/sbin/proc_killer_v9"

# Ensure PID dir exists
mkdir -p /run

# Start in background
$DAEMON >> /var/log/proc_killer.log 2>&1 &

# Write PID manually
echo $! > $PID_FILE

echo "proc_killer started with PID $(cat $PID_FILE)"
