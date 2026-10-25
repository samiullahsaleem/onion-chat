#!/bin/sh
# Run onion-chat as a Tor onion service from this folder, sandboxed on macOS.
#
#   ./onion.sh start     build, then start the app and tor
#   ./onion.sh stop      stop both
#   ./onion.sh status    show what is running and the .onion address
#
# Everything Tor keeps (keys, cache, log) lives in ./.tor, which git ignores.
# .tor/hidden_service holds the private key that IS your address: back it up,
# and delete it if you ever want a fresh address.
set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
STATE="$DIR/.tor"
PORT=${PORT:-8080}
TOR=${TOR:-$(command -v tor || echo "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor")}

running() { [ -f "$STATE/$1.pid" ] && kill -0 "$(cat "$STATE/$1.pid")" 2>/dev/null; }

# On macOS, confine both processes with deploy/macos-sandbox.sb.
sandboxed() {
	role=$1
	shift
	if [ "$(uname)" = Darwin ]; then
		exec sandbox-exec -f "$DIR/deploy/macos-sandbox.sb" \
			-D HOME="$HOME" -D PROJECT="$DIR" -D STATE="$STATE" -D ROLE="$role" "$@"
	fi
	exec "$@"
}

start() {
	if running app || running tor; then
		echo "Already running. Use ./onion.sh stop first."
		exit 1
	fi
	[ -x "$TOR" ] || { echo "tor not found. Install Tor Browser or 'brew install tor', or set TOR=/path/to/tor."; exit 1; }

	echo "Building…"
	(cd "$DIR" && go build -trimpath -ldflags="-s -w" -o onion-chat .)

	mkdir -p "$STATE/data" "$STATE/hidden_service"
	chmod 700 "$STATE" "$STATE/data" "$STATE/hidden_service"
	cat >"$STATE/torrc" <<EOF
DataDirectory $STATE/data
HiddenServiceDir $STATE/hidden_service
HiddenServicePort 80 127.0.0.1:$PORT
HiddenServiceEnableIntroDoSDefense 1
HiddenServicePoWDefensesEnabled 1
HiddenServiceMaxStreams 200
HiddenServiceMaxStreamsCloseCircuit 1
SocksPort 0
AvoidDiskWrites 1
Log notice file $STATE/tor.log
EOF
	: >"$STATE/tor.log"

	(sandboxed app "$DIR/onion-chat" -addr "127.0.0.1:$PORT") >/dev/null 2>&1 &
	echo $! >"$STATE/app.pid"
	(sandboxed tor "$TOR" -f "$STATE/torrc") >/dev/null 2>&1 &
	echo $! >"$STATE/tor.pid"

	printf "Starting Tor"
	i=0
	until grep -q "Bootstrapped 100" "$STATE/tor.log" 2>/dev/null; do
		i=$((i + 1))
		if [ $i -gt 240 ] || ! running tor; then
			echo
			echo "Tor didn't start. Last log lines:"
			tail -5 "$STATE/tor.log"
			stop
			exit 1
		fi
		printf .
		sleep 2
	done
	echo
	running app || { echo "The app didn't start (is port $PORT free?)."; stop; exit 1; }
	echo "Online at: http://$(cat "$STATE/hidden_service/hostname")"
	echo "Open it in Tor Browser. A brand-new address can take a minute to become reachable."
}

stop() {
	for p in tor app; do
		if running $p; then kill "$(cat "$STATE/$p.pid")"; fi
		rm -f "$STATE/$p.pid"
	done
	echo "Stopped."
}

status() {
	for p in app tor; do
		if running $p; then echo "$p: running (pid $(cat "$STATE/$p.pid"))"; else echo "$p: stopped"; fi
	done
	[ -f "$STATE/hidden_service/hostname" ] && echo "address: http://$(cat "$STATE/hidden_service/hostname")"
	true
}

case ${1:-} in
start) start ;;
stop) stop ;;
status) status ;;
*) echo "usage: $0 start|stop|status"; exit 2 ;;
esac
