#!/usr/bin/env bash
# wdttpanel installer: C panel + WDTT data plane.
# Asks: TLS mode (http/selfsigned/domain), nginx usage, external port.
set -euo pipefail
umask 077

[[ $(id -u) == 0 ]] || { echo 'Запустите установщик от root.' >&2; exit 1; }
# systemd/nohup-запуски не имеют HOME — Go и cargo его требуют
export HOME="${HOME:-/root}"
export GOMODCACHE="${GOMODCACHE:-$HOME/go/pkg/mod}"
export GOPATH="${GOPATH:-$HOME/go}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
. /etc/os-release
case "$ID" in debian|ubuntu) ;; *) echo 'Поддерживаются Debian и Ubuntu.' >&2; exit 1;; esac

REPO_URL="${WDTT_REPO_URL:-https://github.com/ttrroyy/wdtt-panel.git}"
C_PANEL_SRC="${WDTT_PANEL_SRC:-}"   # path to wdttpanel-c sources (rsynced by deploy)
CONFIG_DIR=/etc/wdtt

prompt() { read -r -p "$1" "$2" </dev/tty; }

# ---------- interactive (or env-driven) choices ----------
echo "=== wdttpanel installer ==="
echo
if [[ "${WDTT_NONINTERACTIVE:-}" == 1 ]]; then
    TLS_MODE="${WDTT_TLS_MODE:-selfsigned}"
    PANEL_HOST="${WDTT_PANEL_HOST:-$(curl -4fsS --max-time 10 https://api.ipify.org 2>/dev/null || echo 127.0.0.1)}"
    USE_NGINX="${WDTT_USE_NGINX:-no}"
    EXTERNAL_PORT="${WDTT_EXTERNAL_PORT:-8443}"
    CERT="${WDTT_CERT_FILE:-}"; KEY="${WDTT_KEY_FILE:-}"
    BACKEND_PORT="$EXTERNAL_PORT"
    if [[ "$TLS_MODE" != http && -z "$PANEL_HOST" ]]; then
        echo 'WDTT_PANEL_HOST обязателен в неинтерактивном режиме'; exit 1
    fi
else
echo "Сертификат/HTTPS панели:"
echo "  1) HTTP без TLS"
echo "  2) Самоподписанный сертификат на IP"
echo "  3) Домен с существующим сертификатом"
echo "  4) LE-серт на IP (shortlived, автопродление acme.sh)"
echo "  5) Домен + certbot"
prompt 'Вариант [2]: ' tls_choice
case "${tls_choice:-2}" in
    1) TLS_MODE=http;;
    2) TLS_MODE=selfsigned;;
    3) TLS_MODE=existing;;
    4) TLS_MODE=ip-cert;;   # LE-серт прямо на IP (shortlived, автопродление)
    5) TLS_MODE=certbot;;
    *) echo 'Неизвестный вариант'; exit 1;;
esac

PANEL_HOST=""
CERT=""; KEY=""
if [[ "$TLS_MODE" != http ]]; then
    if [[ "$TLS_MODE" == selfsigned ]]; then
        prompt "Хост для сертификата (IP или домен) [$(curl -4fsS --max-time 10 https://api.ipify.org 2>/dev/null || echo 127.0.0.1)]: " PANEL_HOST
        PANEL_HOST=${PANEL_HOST:-$(curl -4fsS --max-time 10 https://api.ipify.org 2>/dev/null || echo 127.0.0.1)}
    else
        prompt 'Домен панели: ' PANEL_HOST
        [[ -n "$PANEL_HOST" ]] || { echo 'Нужен домен'; exit 1; }
        if [[ "$TLS_MODE" == existing ]]; then
            prompt 'Путь к fullchain.pem: ' CERT
            prompt 'Путь к privkey.pem: ' KEY
            [[ -f "$CERT" && -f "$KEY" ]] || { echo 'Сертификат/ключ не найдены'; exit 1; }
        fi
    fi
fi

echo
echo "Nginx как фронтенд?"
echo "  1) Да — nginx на 443 (или общем порту), панель за ним"
echo "  2) Нет — панель слушает свой порт напрямую"
prompt 'Вариант [2]: ' nginx_choice
case "${nginx_choice:-2}" in
    1) USE_NGINX=yes;;
    2) USE_NGINX=no;;
    *) echo 'Неизвестный вариант'; exit 1;;
esac

EXTERNAL_PORT=""
if [[ "$USE_NGINX" == yes ]]; then
    if ss -H -ltn 2>/dev/null | grep -q ':443 '; then
        echo 'Порт 443 занят другим процессом (не nginx).'
        prompt 'Внешний порт для nginx [8443]: ' EXTERNAL_PORT
        EXTERNAL_PORT=${EXTERNAL_PORT:-8443}
    else
        EXTERNAL_PORT=443
    fi
    BACKEND_PORT=$(python3 -c 'import socket
s=socket.socket()
for p in range(2860,2960):
    try: s.bind(("127.0.0.1",p)); print(p); break
    except OSError: pass' 2>/dev/null || true)
    if [[ -z "$BACKEND_PORT" ]]; then
        # shell fallback (python may not be installed yet at this point)
        BACKEND_PORT=2860
        while ss -H -ltn 2>/dev/null | grep -q ":$BACKEND_PORT "; do
            BACKEND_PORT=$((BACKEND_PORT + 1))
        done
    fi
else
    prompt 'Порт панели и подписок [8443]: ' EXTERNAL_PORT
    EXTERNAL_PORT=${EXTERNAL_PORT:-8443}
    while ss -H -ltn 2>/dev/null | grep -q ":$EXTERNAL_PORT "; do
        prompt "Порт $EXTERNAL_PORT занят. Другой порт: " EXTERNAL_PORT
    done
    BACKEND_PORT=$EXTERNAL_PORT
fi
fi  # end interactive else

SCHEME=https; [[ "$TLS_MODE" != http ]] || SCHEME=http
[[ -n "$PANEL_HOST" ]] || PANEL_HOST="127.0.0.1" # http + non-interactive default
PUBLIC_URL="$SCHEME://$PANEL_HOST:$EXTERNAL_PORT"

echo
echo "План: TLS=$TLS_MODE nginx=$USE_NGINX порт=$EXTERNAL_PORT"
echo "Хост: $PANEL_HOST"
echo "Публичный URL: $PUBLIC_URL"
echo

# ---------- swap bump (Rust builds need up to ~2 GB) ----------
SWAP_TOTAL=$(free -m | awk '/^Swap:/{print $2}')
if [[ "$SWAP_TOTAL" -lt 2048 ]] && [[ -w / ]]; then
    if [[ -f /swapfile ]]; then
        swapoff /swapfile 2>/dev/null || true
        dd if=/dev/zero of=/swapfile bs=1M count=3072 status=none
    else
        dd if=/dev/zero of=/swapfile bs=1M count=3072 status=none
    fi
    chmod 600 /swapfile
    mkswap -q /swapfile && swapon /swapfile
    grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
    echo "Свап расширен до 3G для сборки"
fi

# ---------- system deps ----------
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
PKGS=(ca-certificates curl git python3 sqlite3 openssl unzip build-essential pkg-config libsqlite3-dev libssl-dev iproute2 iptables nftables wireguard-tools)
[[ "$USE_NGINX" == yes ]] && PKGS+=(nginx)
[[ "$TLS_MODE" == certbot ]] && PKGS+=(certbot)
apt-get install -y -qq "${PKGS[@]}"

# ---------- clone data plane sources ----------
if [[ -z "$C_PANEL_SRC" ]]; then
    echo 'ОШИБКА: исходники wdttpanel-c не найдены (WDTT_PANEL_SRC не задан).' >&2
    exit 1
fi
SRC_DIR=$(mktemp -d /opt/wdttpanel-build.XXXXXX)
git clone --depth 1 "$REPO_URL" "$SRC_DIR/wdtt-panel"

# ---------- toolchain: Go + Rust (для внешних протоколов), Xray ----------
GO_VER=$(curl -4fsS --max-time 15 "https://go.dev/dl/?mode=json" 2>/dev/null | grep -o '"version": *"go[0-9.]*"' | head -1 | grep -o '[0-9][0-9.]*')
[[ -n "$GO_VER" ]] || GO_VER=1.27.4
if [[ ! -x /usr/local/go/bin/go ]] || [[ $(/usr/local/go/bin/go version 2>/dev/null) != *go$GO_VER* ]]; then
    GO_ARCHIVE=$(mktemp /tmp/wdtt-go.XXXXXX.tar.gz)
    curl -fsSL "https://dl.google.com/go/go$GO_VER.linux-amd64.tar.gz" -o "$GO_ARCHIVE"
    GO_CHECKSUM=$(curl -fsSL "https://dl.google.com/go/go$GO_VER.linux-amd64.tar.gz.sha256")
    [[ "$GO_CHECKSUM" =~ ^[0-9a-f]{64}$ ]] || { echo "Некорректная контрольная сумма Go ($GO_CHECKSUM)"; exit 1; }
    printf '%s  %s\n' "$GO_CHECKSUM" "$GO_ARCHIVE" | sha256sum -c -
    rm -rf /usr/local/go
    tar -xzf "$GO_ARCHIVE" -C /usr/local
    rm -f -- "$GO_ARCHIVE"
fi
export PATH="/usr/local/go/bin:/root/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null; then
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.97.1
fi

# ---------- build data plane + external protocols ----------
install -d -m 700 "$CONFIG_DIR" "$CONFIG_DIR/protocols"
install -d /usr/local/lib/wdtt /usr/local/lib/wdtt/protocols
install -m 755 "$SRC_DIR/wdtt-panel/scripts/protocols.py" /usr/local/lib/wdtt/protocols.py
install -m 755 "$SRC_DIR/wdtt-panel/scripts/wdtt-mtu-rules.sh" /usr/local/bin/wdtt-mtu-rules.sh
python3 "$SRC_DIR/wdtt-panel/scripts/build-protocols.py"
(cd "$SRC_DIR/wdtt-panel" && CGO_ENABLED=0 go build -trimpath -o /usr/local/bin/wdtt-app ./cmd/wdtt)

if [[ ! -x /usr/local/wdtt-xray/bin/xray-linux-amd64 ]]; then
    XRAY_TEMP=$(mktemp -d /tmp/wdtt-xray.XXXXXX)
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v26.6.1/Xray-linux-64.zip" -o "$XRAY_TEMP/xray.zip"
    unzip -q "$XRAY_TEMP/xray.zip" -d "$XRAY_TEMP/files"
    install -d /usr/local/wdtt-xray/bin
    install -m 755 "$XRAY_TEMP/files/xray" /usr/local/wdtt-xray/bin/xray-linux-amd64
    for f in geoip.dat geosite.dat; do
        [[ ! -f "$XRAY_TEMP/files/$f" ]] || install -m 644 "$XRAY_TEMP/files/$f" /usr/local/wdtt-xray/bin/
    done
    rm -rf "$XRAY_TEMP"
fi

# ---------- build C panel ----------
PANEL_BIN=/usr/local/bin/wdttpanel
echo "Сборка C-панели из $C_PANEL_SRC ..."
make -C "$C_PANEL_SRC" clean >/dev/null 2>&1 || true
make -C "$C_PANEL_SRC" wdttpanel
install -m 755 "$C_PANEL_SRC/wdttpanel" "$PANEL_BIN"

# ---------- init panel db ----------
systemctl stop wdttpanel wdtt 2>/dev/null || true
if [[ ! -f "$CONFIG_DIR/panel.db" ]]; then
    INITIAL_PASSWORD=$(openssl rand -hex 12)
    "$PANEL_BIN" -config-dir "$CONFIG_DIR" -init-panel \
        -set-password "$INITIAL_PASSWORD" -public-url "$PUBLIC_URL"
    MAIN_PASSWORD=$(sqlite3 "$CONFIG_DIR/panel.db" "SELECT main_password FROM wdtt_global WHERE id=1")
    {
        echo "admin"
        echo "$INITIAL_PASSWORD"
        echo "main-vpn-password: $MAIN_PASSWORD"
    } > "$CONFIG_DIR/install-credentials"
    chmod 600 "$CONFIG_DIR/install-credentials"
fi
# server_host для ссылок (если пуст)
PUBLIC_IP=$(curl -4fsS --max-time 10 https://api.ipify.org 2>/dev/null || echo "")
if [[ -n "$PUBLIC_IP" ]]; then
    HAS_HOST=$(sqlite3 "$CONFIG_DIR/panel.db" "SELECT server_host FROM wdtt_inbound WHERE id=1")
    [[ -n "$HAS_HOST" ]] || sqlite3 "$CONFIG_DIR/panel.db" "UPDATE wdtt_inbound SET server_host='$PUBLIC_IP' WHERE id=1"
fi

# ---------- certificates ----------
if [[ "$TLS_MODE" == selfsigned ]]; then
    CERT="$CONFIG_DIR/panel-cert.pem"; KEY="$CONFIG_DIR/panel-key.pem"
    if [[ "$PANEL_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SAN="subjectAltName=IP:$PANEL_HOST"
    else
        SAN="subjectAltName=DNS:$PANEL_HOST"
    fi
    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout "$KEY" -out "$CERT" \
        -subj "/CN=$PANEL_HOST" -addext "$SAN"
elif [[ "$TLS_MODE" == ip-cert ]]; then
    # настоящий LE-серт на IP: acme.sh + shortlived profile (6-дневный, автопродление)
    if [[ ! -x "$HOME/.acme.sh/acme.sh" ]]; then
        curl -fsSL https://get.acme.sh | sh -s -- --accountemail "${WDTT_ACME_EMAIL:-admin@local.host}" >/dev/null 2>&1
    fi
    "$HOME/.acme.sh/acme.sh" --issue -d "$PANEL_HOST" --webroot /var/www/html \
        --server letsencrypt --keylength ec-256 --cert-profile shortlived
    mkdir -p /var/www/html/.well-known/acme-challenge
    "$HOME/.acme.sh/acme.sh" --install-cert -d "$PANEL_HOST" --ecc \
        --fullchain-file "$CONFIG_DIR/panel-cert.pem" \
        --key-file "$CONFIG_DIR/panel-key.pem" \
        --reloadcmd 'systemctl try-restart wdttpanel'
    CERT="$CONFIG_DIR/panel-cert.pem"; KEY="$CONFIG_DIR/panel-key.pem"
    # systemd-таймер продления (cron может отсутствовать)
    cat >/etc/systemd/system/acme-renew.service <<'RENEW'
[Unit]
Description=acme.sh renewal pass (shortlived certs)
[Service]
Type=oneshot
ExecStart=/root/.acme.sh/acme.sh --cron --home /root/.acme.sh
RENEW
    cat >/etc/systemd/system/acme-renew.timer <<'RENEWT'
[Unit]
Description=Run acme.sh renewals twice a day
[Timer]
OnCalendar=*-*-* 06/12:10:00
Persistent=true
[Install]
WantedBy=timers.target
RENEWT
    systemctl daemon-reload && systemctl enable --now acme-renew.timer
elif [[ "$TLS_MODE" == certbot ]]; then
    certbot certonly --nginx --non-interactive --agree-tos -d "$PANEL_HOST" \
        --register-unsafely-without-email || certbot certonly --standalone --non-interactive --agree-tos -d "$PANEL_HOST"
    CERT="/etc/letsencrypt/live/$PANEL_HOST/fullchain.pem"
    KEY="/etc/letsencrypt/live/$PANEL_HOST/privkey.pem"
fi

# ---------- systemd units ----------
cat >/etc/systemd/system/wdtt.service <<'UNIT'
[Unit]
Description=WDTT data plane (protocol server, no panel)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/wdtt-app -config-dir /etc/wdtt -no-panel
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/wdttpanel.service <<UNIT
[Unit]
Description=wdttpanel web panel (C edition)
After=network-online.target wdtt.service
Wants=network-online.target
[Service]
ExecStart=$PANEL_BIN -config-dir $CONFIG_DIR -port $BACKEND_PORT $( [[ "$USE_NGINX" == no && "$TLS_MODE" != http ]] && printf -- '-cert %s -key %s' "$CERT" "$KEY" )
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/wdtt-protocol@.service <<'UNIT'
[Unit]
Description=WDTT protocol %i
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/python3 /usr/local/lib/wdtt/protocols.py run %i
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
KillMode=mixed
LimitNOFILE=1048576
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/wdtt-protocol-watch.service <<'UNIT'
[Unit]
Description=WDTT protocol routing and limits
After=wdtt.service wdtt-xray.service
[Service]
ExecStart=/usr/bin/python3 /usr/local/lib/wdtt/protocols.py watch
Restart=on-failure
RestartSec=3
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT

cat >/etc/systemd/system/wdtt-xray.service <<'UNIT'
[Unit]
Description=WDTT Xray routing
After=network-online.target
[Service]
ExecStart=/usr/local/wdtt-xray/bin/xray-linux-amd64 run -c /etc/wdtt-xray/config.json
Environment=XRAY_LOCATION_ASSET=/usr/local/wdtt-xray/bin
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
UNIT

printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\n' >/etc/sysctl.d/90-wdttpanel.conf
sysctl -p /etc/sysctl.d/90-wdttpanel.conf

# ---------- xray base config ----------
if [[ ! -f /etc/wdtt-xray/config.json ]]; then
    install -d /etc/wdtt-xray
    cat >/etc/wdtt-xray/config.json <<'XCFG'
{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}},{"tag":"blocked","protocol":"blackhole","settings":{}}],"routing":{"rules":[]}}
XCFG
fi

systemctl daemon-reload
systemctl enable --now wdtt wdtt-xray wdttpanel
systemctl restart wdtt wdttpanel

# ---------- protocols ----------
for protocol in qwdtt wdtt-plus csqtt-2.1.9 csqtt-2.5.0 freeturn; do
    status=$(python3 -c 'import json,sys
s=json.load(open("/etc/wdtt/protocols/state.json"))
n=sys.argv[1]
print("enabled" if s["profiles"].get(n) and not s.get("disabled",{}).get(n) else "disabled" if n in s["profiles"] else "new")' "$protocol" 2>/dev/null || echo new)
    case "$status" in
        enabled) systemctl restart "wdtt-protocol@$protocol";;
        disabled) continue;;
        new) PUBLIC_IP=$(curl -4fsS --max-time 10 https://api.ipify.org 2>/dev/null || echo "")
             printf '{"op":"create","protocol":"%s","host":"%s"}\n' "$protocol" "$PUBLIC_IP" | python3 /usr/local/lib/wdtt/protocols.py;;
    esac
done
systemctl enable --now wdtt-protocol-watch
systemctl restart wdtt-protocol-watch
seeded=0
for attempt in $(seq 1 20); do
    if printf '{"op":"seed-default"}\n' | python3 /usr/local/lib/wdtt/protocols.py; then seeded=1; break; fi
    sleep 1
done
[[ "$seeded" == 1 ]] || echo 'ВНИМАНИЕ: seed-default не прошёл; проверьте журналы.'

# ---------- nginx ----------
if [[ "$USE_NGINX" == yes ]]; then
    TLS_BLOCK=""
    [[ "$TLS_MODE" == http ]] || TLS_BLOCK="ssl_certificate $CERT;
    ssl_certificate_key $KEY;
    ssl_protocols TLSv1.2 TLSv1.3;"
    cat >/etc/nginx/conf.d/wdttpanel.conf <<NGINX
server {
    listen $EXTERNAL_PORT;
    listen [::]:$EXTERNAL_PORT;
    server_name $PANEL_HOST;
    $TLS_BLOCK

    location ^~ /wdtt/ {
        proxy_pass http://127.0.0.1:$BACKEND_PORT/wdtt/;
        proxy_http_version 1.1;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_buffering off;
    }
    location = /wdtt { return 302 /wdtt/; }
}
NGINX
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
fi

# ---------- firewall ----------
if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
    ufw allow "$EXTERNAL_PORT/tcp" >/dev/null || true
    for p in 56000 56100 56200 56300 56400 56500; do
        ufw allow "$p/udp" >/dev/null || true
        ufw allow "$((p+1))/udp" >/dev/null || true
    done
fi

echo
echo '=== Установка завершена ==='
echo "Панель: $PUBLIC_URL/wdtt/"
echo "Креды: $CONFIG_DIR/install-credentials"
[[ -f "$CONFIG_DIR/protocols/default-subscription-id" ]] && \
    echo "Подписка: $PUBLIC_URL/wdtt/sub/$(cat "$CONFIG_DIR/protocols/default-subscription-id")"
exit 0
