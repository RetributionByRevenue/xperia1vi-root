#!/data/data/com.termux/files/usr/bin/sh
# root.sh — on-device re-root via loopback adb (run by Termux:Boot at boot)
export MINIADB_KEY=/data/data/com.termux/files/home/autoroot/adbkey
export MINIADB_PORT=5555
MB=/data/data/com.termux/files/home/autoroot/miniboot
LOG=/data/data/com.termux/files/home/autoroot/autoroot.log
termux-wake-lock 2>/dev/null
echo "[*] autoroot start $(date)" >> "$LOG"
if $MB "su -c id" 2>&1 | grep -q "uid=0"; then
  echo "[=] already rooted, skipping" >> "$LOG"
  termux-wake-unlock 2>/dev/null
  exit 0
fi
# launch detached: survives adb-client disconnect and Termux process death
$MB "setsid nohup /data/local/tmp/ghostlock_native --load-prebuilt-profile /data/local/tmp/xperia_profile_v4.bin --force-attack > /data/local/tmp/autorun.log 2>&1 < /dev/null &" >/dev/null 2>&1
sleep 2
# poll for root: 15 W2 attempts can take ~2-3 minutes (and a panic = reboot = next boot retries)
i=0
while [ $i -lt 36 ]; do
  sleep 5
  if $MB "su -c id" 2>&1 | grep -q "uid=0"; then
    echo "[+] ROOT OK $(date)" >> "$LOG"
    termux-wake-unlock 2>/dev/null
    exit 0
  fi
  i=$((i+1))
done
echo "[-] no root after attempt $(date)" >> "$LOG"
termux-wake-unlock 2>/dev/null
