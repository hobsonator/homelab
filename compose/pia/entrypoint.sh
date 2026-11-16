#!/bin/bash
# Entrypoint for the PIA VPN container: starts the daemon, logs in, connects,
# applies a leak-safe firewall, and keeps the tunnel alive.

# Exit on any error (-e) and on use of unset variables (-u)
set -eu

# Make piactl / pia-daemon available without full paths
export PATH="$PATH:/opt/piavpn/bin"

# PIA settings file, Docker secret path for credentials, and monitor tuning
SETTINGS=/opt/piavpn/etc/settings.json
CRED_SECRET=/run/secrets/pia_credentials
# Seconds between state checks in the monitor loop
CHECK_INTERVAL=30
# Consecutive Interrupted/Unknown checks tolerated before forcing a reconnect
INTERRUPTED_STRIKES_MAX=3

# Seed a default settings file with the PIA kill switch on, if none exists
mkdir -p "$(dirname "$SETTINGS")"
[ -f "$SETTINGS" ] || echo '{"killswitch":"on"}' > "$SETTINGS"

# --- optional pre-daemon firewall (default DROP until PIA takes over) ------
prefirewall() {
    local ipt
    # Apply the same baseline to IPv4 and IPv6
    for ipt in iptables ip6tables; do
        # Skip tools that aren't installed
        command -v "$ipt" >/dev/null 2>&1 || continue
        # Default-drop inbound; abort on iptables failure, tolerate ip6tables failure
        "$ipt" -P INPUT DROP    2>/dev/null || { [ "$ipt" = ip6tables ] && continue; echo "prefirewall: $ipt failed"; exit 1; }
        "$ipt" -P OUTPUT DROP   2>/dev/null || true
        "$ipt" -P FORWARD DROP  2>/dev/null || true
        # Always allow loopback
        "$ipt" -A INPUT  -i lo -j ACCEPT 2>/dev/null || true
        "$ipt" -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
        # Allow replies to connections that are already allowed
        "$ipt" -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
        "$ipt" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    done

    # keep the Docker network reachable (published ports, sibling containers)
    local lan
    # Find the first link-scope (LAN) subnet, ignoring tunnel interfaces
    lan=$(ip -4 route show scope link | awk '!/tun|wg/ {print $1; exit}')
    if [ -n "$lan" ]; then
        iptables -A INPUT  -s "$lan" -j ACCEPT
        iptables -A OUTPUT -d "$lan" -j ACCEPT
    fi

    # Temporary bootstrap allow-list so the daemon can log in and connect.
    # Removed by prefirewall_tighten once the tunnel is up.
    # Create the BOOT chain, or flush it if it already exists
    iptables -N BOOT 2>/dev/null || iptables -F BOOT
    # Hook BOOT into OUTPUT only once
    iptables -C OUTPUT -j BOOT 2>/dev/null || iptables -A OUTPUT -j BOOT
    # DNS
    iptables -A BOOT -p udp --dport 53 -j ACCEPT
    iptables -A BOOT -p tcp --dport 53 -j ACCEPT
    # HTTPS (login / server list API)
    iptables -A BOOT -p tcp --dport 443 -j ACCEPT
    # UDP ports used to establish the VPN connection
    iptables -A BOOT -p udp -m multiport --dports 443,853,1197,1198,1337,8080 -j ACCEPT
    # TCP ports used as connection fallbacks
    iptables -A BOOT -p tcp -m multiport --dports 80,110,501,853,8080 -j ACCEPT
    echo "prefirewall: default DROP active (LAN: ${lan:-none}), bootstrap rules open"
}

# Remove the bootstrap allow-list once connected, leaving only the PIA kill switch
prefirewall_tighten() {
    # No-op unless the pre-firewall is enabled
    [ "${PIA_PREFIREWALL:-false}" = "true" ] || return 0
    # Unhook, empty, then delete the BOOT chain
    iptables -D OUTPUT -j BOOT 2>/dev/null || true
    iptables -F BOOT 2>/dev/null || true
    iptables -X BOOT 2>/dev/null || true
    echo "prefirewall: bootstrap rules removed (PIA kill switch only)"
}

# Hard lockdown: used when the daemon dies or the script exits.
# Re-asserts DROP and leaves only loopback + LAN, whatever PIA left behind.
lockdown() {
    # No-op unless the pre-firewall is enabled
    [ "${PIA_PREFIREWALL:-false}" = "true" ] || return 0
    local ipt lan
    # Re-detect the LAN subnet (excluding tunnel interfaces)
    lan=$(ip -4 route show scope link | awk '!/tun|wg/ {print $1; exit}')
    for ipt in iptables ip6tables; do
        command -v "$ipt" >/dev/null 2>&1 || continue
        "$ipt" -P OUTPUT DROP  2>/dev/null || true
        "$ipt" -P FORWARD DROP 2>/dev/null || true
        # Wipe all OUTPUT rules (including any PIA left open), then re-allow loopback
        "$ipt" -F OUTPUT       2>/dev/null || true
        "$ipt" -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
    done
    # Allow the LAN only if one was detected
    [ -n "$lan" ] && iptables -A OUTPUT -d "$lan" -j ACCEPT || true
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    echo "lockdown: OUTPUT locked to loopback/LAN"
}

# Apply the pre-firewall before the daemon starts, if enabled
if [ "${PIA_PREFIREWALL:-false}" = "true" ]; then
    prefirewall
fi
# Lock down on any script exit
trap lockdown EXIT

# Start the PIA daemon in the background and remember its PID
pia-daemon &
DAEMON=$!

# --- shutdown -------------------------------------------------------------
# Graceful stop: kill monitor, disconnect VPN, stop daemon, exit cleanly
cleanup() {
    [ -n "${MON:-}" ] && kill "$MON" 2>/dev/null || true
    piactl disconnect 2>/dev/null || true
    kill "$DAEMON" 2>/dev/null || true
    wait "$DAEMON" 2>/dev/null || true
    exit 0
}
# Run cleanup on docker stop (TERM) or Ctrl-C (INT)
trap cleanup TERM INT

# --- helpers --------------------------------------------------------------
# Print the current VPN connection state, or "Unknown" if piactl fails
get_state() { piactl get connectionstate 2>/dev/null || echo Unknown; }

# Poll up to $1 seconds for Connected (1s steps)
wait_connected() {
    local i
    for i in $(seq 1 "${1:-30}"); do
        [ "$(get_state)" = "Connected" ] && return 0
        sleep 1
    done
    return 1
}

# Wait (up to 20s) for PIA to assign a forwarded port; skipped if not requested
wait_for_port_forward() {
    [ "${PIA_REQUESTPORTFORWARD:-false}" = "true" ] || return 0
    local i pf
    for i in $(seq 1 20); do
        pf=$(piactl get portforward 2>/dev/null || echo N/A)
        case "$pf" in
            ''|*[!0-9]*) sleep 1 ;;   # not numeric yet
            *) return 0 ;;
        esac
    done
}

# Print a status banner (state, IPs, region, port) and optionally run a speedtest
print_banner() {
    echo
    echo "========================================"
    echo "  $1"
    echo "========================================"
    printf "%-20s %s\n" "State:"        "$(get_state)"
    printf "%-20s %s\n" "VPN IP:"       "$(piactl get vpnip 2>/dev/null || echo N/A)"
    # Public IP as seen from outside, to confirm traffic exits via the VPN
    printf "%-20s %s\n" "Public IP:"    "$(curl -s --max-time 10 https://ifconfig.me 2>/dev/null || echo N/A)"
    printf "%-20s %s\n" "Region:"       "$(piactl get region 2>/dev/null || echo N/A)"
    printf "%-20s %s\n" "Port Forward:" "$(piactl get portforward 2>/dev/null || echo N/A)"
    echo "========================================"
    # Speedtest is on by default; failures are non-fatal
    if [ "${PIA_SPEEDTEST:-true}" = "true" ]; then
        speedtest || echo "speedtest failed (ignored)"
        echo "========================================"
    fi
    echo
}

# --- wait for daemon ------------------------------------------------------
# Wait up to 30s for the daemon to respond to piactl
for i in $(seq 1 30); do
    piactl get connectionstate >/dev/null 2>&1 && break
    sleep 1
done

# Give up if the daemon never came up
if ! piactl get connectionstate >/dev/null 2>&1; then
    echo "pia-daemon failed to start"
    exit 1
fi

# --- login (secret file preferred, env vars as fallback) ------------------
CREDS=""
if [ -r "$CRED_SECRET" ]; then
    # Use the Docker secret file directly
    CREDS="$CRED_SECRET"
elif [ -n "${PIA_USERNAME:-}" ] && [ -n "${PIA_PASSWORD:-}" ]; then
    # Fallback: build a private temp credentials file from env vars
    CREDS=$(mktemp)
    chmod 600 "$CREDS"
    printf '%s\n%s\n' "$PIA_USERNAME" "$PIA_PASSWORD" > "$CREDS"
fi

if [ -n "$CREDS" ]; then
    # Login failure is non-fatal (may already be logged in)
    if ! piactl login "$CREDS"; then
        echo "PIA login failed or already logged in"
    fi
    # Securely delete the temp file; never touch the real secret
    [ "$CREDS" = "$CRED_SECRET" ] || { shred -u "$CREDS" 2>/dev/null || rm -f "$CREDS"; }
fi
# Scrub credentials from the environment
unset PIA_USERNAME PIA_PASSWORD CREDS

# --- configure & connect --------------------------------------------------
# Keep the daemon running without the GUI client
piactl background enable
# Allow LAN traffic (needed for Docker network / sibling containers)
piactl set allowlan true
piactl set protocol "${PIA_PROTOCOL:-wireguard}"
piactl set region "${PIA_REGION:-auto}"
piactl set requestportforward "${PIA_REQUESTPORTFORWARD:-false}"

echo "Connecting to PIA..."
piactl connect

# Wait up to 30s for the tunnel to come up
for i in $(seq 1 30); do
    [ "$(get_state)" = "Connected" ] && break
    sleep 1
done

if [ "$(get_state)" = "Connected" ]; then
    # Tunnel is up: drop the bootstrap rules, then report status
    prefirewall_tighten
    wait_for_port_forward
    print_banner "PIA CONNECTION ESTABLISHED"
else
    echo "WARNING: not connected after 30s (state: $(get_state)); monitor loop will keep retrying"
fi

# --- monitor loop (background) --------------------------------------------
# Watches the connection and reconnects if it drops; exits when the daemon dies
monitor() {
    local RECONNECTING=0 STRIKES=0 state
    while kill -0 "$DAEMON" 2>/dev/null; do
        state="$(get_state)"

        case "$state" in
            Connected)
                STRIKES=0
                # Announce recovery once after a drop
                if [ "$RECONNECTING" -eq 1 ]; then
                    wait_for_port_forward
                    print_banner "PIA RECONNECTED"
                    RECONNECTING=0
                fi
                ;;

            # Daemon is already working on it; just reset the strike counter
            Connecting|StillConnecting|Reconnecting)
                STRIKES=0
                ;;

            # Tunnel is down: reconnect immediately
            Disconnected)
                if [ "$RECONNECTING" -eq 0 ]; then
                    echo; echo "==== TUNNEL DROPPED - RECONNECTING ===="; echo
                    RECONNECTING=1
                fi
                piactl connect >/dev/null 2>&1 || true
                wait_connected 5 || true
                continue   # re-check now instead of sleeping, so the banner prints promptly
                ;;

            Interrupted|Unknown)
                # daemon retries Interrupted on its own; only step in if it persists
                STRIKES=$((STRIKES + 1))
                if [ "$STRIKES" -ge "$INTERRUPTED_STRIKES_MAX" ]; then
                    if [ "$RECONNECTING" -eq 0 ]; then
                        echo; echo "==== TUNNEL DOWN ($state) - FORCING RECONNECT ===="; echo
                        RECONNECTING=1
                    fi
                    piactl connect >/dev/null 2>&1 || true
                    STRIKES=0
                    wait_connected 5 || true
                    continue
                fi
                ;;
        esac

        # Pause between checks (|| true so an interrupted sleep doesn't abort under set -e)
        sleep "$CHECK_INTERVAL" || true
    done
}

# Run the monitor in the background and remember its PID for cleanup
monitor &
MON=$!

# Block on the daemon itself: reacts the instant it dies (no polling gap).
RC=0
wait "$DAEMON" || RC=$?
# Daemon died: lock the firewall down, stop the monitor, and propagate the exit code
lockdown
kill "$MON" 2>/dev/null || true
echo "pia-daemon exited with code $RC"
exit "$RC"