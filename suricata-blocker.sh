#!/bin/bash

LOG_FILE="/var/log/suricata/eve.json"
STATE="/tmp/suricata_blocked_ips.txt"
SUPERBAN_FILE="/etc/suricata/superbanned_ips.txt"

: > "$STATE"

echo "[*] Suricata IPS started"

touch "$STATE"
touch "$SUPERBAN_FILE"

# -------------------------
# CLEAN DROP ZONE
# -------------------------
echo "[*] Cleaning DROP ZONE..."

# runtime
for ip in $(firewall-cmd --zone=drop --list-sources 2>/dev/null); do
    firewall-cmd --zone=drop --remove-source="$ip" >/dev/null 2>&1
done

# permanent
for ip in $(firewall-cmd --permanent --zone=drop --list-sources 2>/dev/null); do
    firewall-cmd --permanent --zone=drop --remove-source="$ip" >/dev/null 2>&1
done

firewall-cmd --reload
sleep 1

# -------------------------
# SUPERBAN SYNC (FIXED)
# -------------------------
sync_superban() {
    echo "[*] Syncing SUPERBAN..."

    [[ ! -f "$SUPERBAN_FILE" ]] && return

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        # 🔥 FIX: eliminar timestamp si existe
        ip="${line%%|*}"

        # limpieza adicional por seguridad
        ip="$(echo "$ip" | tr -d '"'"'")"

        [[ -z "$ip" ]] && continue

        echo "[SUPERBAN SYNC] $ip"

        # INPUT DROP (zone)
        firewall-cmd --zone=drop --add-source="$ip" >/dev/null 2>&1
        firewall-cmd --zone=drop --add-source="$ip" --permanent >/dev/null 2>&1

        # OUTPUT DROP (rich rules)
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip drop" >/dev/null 2>&1
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 destination address=$ip drop" >/dev/null 2>&1

    done < "$SUPERBAN_FILE"

    firewall-cmd --reload
}

# -------------------------
# SUPERBAN FUNCTION (USED)
# -------------------------
superban_ip() {
    local ip="$1"

    grep -qx "$ip" "$SUPERBAN_FILE" 2>/dev/null && return

    echo "[SUPERBAN] $ip"

    # INPUT
    firewall-cmd --zone=drop --add-source="$ip" >/dev/null 2>&1
    firewall-cmd --zone=drop --add-source="$ip" --permanent >/dev/null 2>&1

    # OUTPUT
    firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$ip drop" >/dev/null 2>&1
    firewall-cmd --permanent --add-rich-rule="rule family=ipv4 destination address=$ip drop" >/dev/null 2>&1

    echo "$ip" >> "$SUPERBAN_FILE"

    firewall-cmd --reload
}

# -------------------------
# FILTERS
# -------------------------
is_safe_ip() {
    local ip="$1"
    [[ -z "$ip" ]] && return 0
    [[ "$ip" == 192.168.* ]] && return 0
    [[ "$ip" == 10.* ]] && return 0
    [[ "$ip" == 172.16.* ]] && return 0
    [[ "$ip" == 127.* ]] && return 0
    return 1
}

is_whitelisted() {
    echo "$1" | grep -qi "ET CINS" && return 0
    echo "$1" | grep -qi "Generic Protocol Command Decode" && return 0
    return 1
}

is_bad_alert() {
    echo "$1" | grep -Eqi "ET DROP|ET TOR|ET MALWARE|SCAN|EXPLOIT"
}

already_blocked() {
    grep -qx "$1" "$STATE"
}

block_ip() {
    local ip="$1"
    local sig="$2"

    already_blocked "$ip" && return

    echo "[BLOCK] $ip -> $sig"

    firewall-cmd --zone=drop --add-source="$ip" >/dev/null 2>&1
    firewall-cmd --zone=drop --add-source="$ip" --permanent >/dev/null 2>&1

    echo "$ip" >> "$STATE"
}

# -------------------------
# INIT SYNC
# -------------------------
sync_superban

# -------------------------
# HISTORICAL
# -------------------------
SNAPSHOT="/tmp/eve_snapshot.json"
cp "$LOG_FILE" "$SNAPSHOT" 2>/dev/null

TMP="/tmp/suricata_alerts.txt"

jq -r '
    select(.event_type=="alert") |
    "\(.src_ip)|\(.alert.signature)"
' "$SNAPSHOT" > "$TMP"

TOTAL=$(wc -l < "$TMP")
COUNT=0

exec 3> >(yad --progress --title="Suricata IPS" --auto-close --width=400)

while IFS='|' read -r IP SIG; do

    COUNT=$((COUNT + 1))
    PERCENT=$((COUNT * 100 / TOTAL))

    echo $PERCENT >&3
    echo "# Processing $COUNT / $TOTAL" >&3

    [[ -z "$IP" ]] && continue

    is_safe_ip "$IP" && continue
    is_whitelisted "$SIG" && continue
    is_bad_alert "$SIG" || continue

    # IMPORTANTE: si es grave → SUPERBAN automático opcional
    block_ip "$IP" "$SIG"

done < "$TMP"

exec 3>&-

# -------------------------
# REAL TIME
# -------------------------
echo "[*] Realtime monitor..."

tail -n0 -F "$LOG_FILE" | while IFS= read -r line; do

    IP=$(echo "$line" | jq -r 'select(.event_type=="alert") | .src_ip' 2>/dev/null)
    SIG=$(echo "$line" | jq -r 'select(.event_type=="alert") | .alert.signature' 2>/dev/null)

    [[ -z "$IP" ]] && continue

    is_safe_ip "$IP" && continue
    is_whitelisted "$SIG" && continue
    is_bad_alert "$SIG" || continue

    block_ip "$IP" "$SIG"

done
