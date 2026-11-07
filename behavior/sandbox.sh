#!/usr/bin/env bash
# Isolate a target app in its own network namespace so every packet it sends
# crosses veth-host, where we capture it. Record only: nothing is blocked.
#
#   sudo behavior/sandbox.sh up
#   sudo behavior/sandbox.sh run "<cmd>"     # runs <cmd> as $SUDO_USER inside the netns
#   sudo behavior/sandbox.sh down            # safe to run any number of times
#   sudo behavior/sandbox.sh status
set -euo pipefail

NS=noalibi
VH=veth-host
VN=veth-ns
HOST_IP=10.200.0.1
NS_IP=10.200.0.2
SUBNET=10.200.0.0/24

die() { echo "sandbox: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

nat_rule=(POSTROUTING -s "$SUBNET" ! -o "$VH" -j MASQUERADE)
fwd_out=(FORWARD -i "$VH" -j ACCEPT)
fwd_in=(FORWARD -o "$VH" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT)

add_rule() { # table, rule...
  local table=$1; shift
  iptables -t "$table" -C "$@" 2>/dev/null || iptables -t "$table" -I "$@"
}
del_rule() { # table, rule...  (delete every copy)
  local table=$1; shift
  while iptables -t "$table" -C "$@" 2>/dev/null; do iptables -t "$table" -D "$@"; done
}

pick_resolv_conf() {
  # Ubuntu's /etc/resolv.conf points at systemd-resolved's stub (127.0.0.53),
  # which is unreachable from inside the netns. Use the real upstream list.
  if grep -qE '^nameserver 127\.' /etc/resolv.conf 2>/dev/null; then
    if [[ -s /run/systemd/resolve/resolv.conf ]]; then
      echo /run/systemd/resolve/resolv.conf
      return
    fi
    echo "sandbox: warning: only a loopback resolver found; using 1.1.1.1 in netns" >&2
    echo ""
    return
  fi
  echo /etc/resolv.conf
}

up() {
  if ip netns list | grep -qw "$NS"; then
    echo "sandbox: $NS already up"; return 0
  fi
  ip netns add "$NS"
  ip link add "$VH" type veth peer name "$VN"
  ip link set "$VN" netns "$NS"
  ip addr add "$HOST_IP/24" dev "$VH"
  ip link set "$VH" up
  ip netns exec "$NS" ip addr add "$NS_IP/24" dev "$VN"
  ip netns exec "$NS" ip link set "$VN" up
  ip netns exec "$NS" ip link set lo up
  ip netns exec "$NS" ip route add default via "$HOST_IP"
  # IPv4 only inside the sandbox: avoids slow v6 fallbacks and v6 traffic we would not NAT.
  ip netns exec "$NS" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 || true

  sysctl -qw net.ipv4.ip_forward=1
  add_rule nat "${nat_rule[@]}"
  # Docker/ufw often set FORWARD policy to DROP; allow our subnet explicitly.
  add_rule filter "${fwd_out[@]}"
  add_rule filter "${fwd_in[@]}"

  mkdir -p "/etc/netns/$NS"
  local src; src=$(pick_resolv_conf)
  if [[ -n "$src" ]]; then
    cp "$src" "/etc/netns/$NS/resolv.conf"
  else
    echo "nameserver 1.1.1.1" > "/etc/netns/$NS/resolv.conf"
  fi
  echo "sandbox: up ($NS_IP via $HOST_IP, capture on $VH)"
}

run() {
  [[ $# -ge 1 ]] || die "usage: sandbox.sh run \"<cmd>\""
  ip netns list | grep -qw "$NS" || die "$NS is not up; run: sandbox.sh up"
  local user=${SUDO_USER:-}
  [[ -n "$user" && "$user" != root ]] || user=${NOALIBI_RUN_AS:-root}
  # sudo strips the GUI session variables, so pass through whatever we were given.
  local uid; uid=$(id -u "$user")
  exec ip netns exec "$NS" sudo -u "$user" env \
    DISPLAY="${DISPLAY:-:0}" \
    XAUTHORITY="${XAUTHORITY:-/home/$user/.Xauthority}" \
    WAYLAND_DISPLAY="${WAYLAND_DISPLAY:-}" \
    XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$uid}" \
    DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$uid/bus}" \
    HOME="$(getent passwd "$user" | cut -d: -f6)" \
    bash -c "$1"
}

down() {
  # Stop anything still running inside the sandbox first (apps that daemonize
  # would otherwise keep running with a dead network).
  local pids; pids=$(ip netns pids "$NS" 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    kill $pids 2>/dev/null || true
    sleep 1
    pids=$(ip netns pids "$NS" 2>/dev/null || true)
    [[ -z "$pids" ]] || kill -9 $pids 2>/dev/null || true
  fi
  ip netns del "$NS" 2>/dev/null || true      # also removes veth-ns and its peer
  ip link del "$VH" 2>/dev/null || true
  del_rule nat "${nat_rule[@]}"
  del_rule filter "${fwd_out[@]}"
  del_rule filter "${fwd_in[@]}"
  rm -rf "/etc/netns/$NS"
  # ip_forward is left as is: other software (Docker) may depend on it.
  echo "sandbox: down"
}

status() {
  if ip netns list | grep -qw "$NS"; then
    echo "up"; ip -br addr show "$VH" 2>/dev/null || true
  else
    echo "down"
  fi
}

case "${1:-}" in
  up) up ;;
  run) shift; run "$@" ;;
  down) down ;;
  status) status ;;
  *) die "usage: sandbox.sh up|run \"<cmd>\"|down|status" ;;
esac
