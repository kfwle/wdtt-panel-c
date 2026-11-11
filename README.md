# wdttpanel-c

Легковесная C-версия веб-панели для [wdtt-panel](https://github.com/ttrroyy/wdtt-panel)
(форк ildarmaga/wdtt). Панель заменяет Go-часть `panel.Run()`; дата-плейн остаётся
`wdtt-app -no-panel` (Go) + 5 внешних протоколов из protocols.py + Xray.

## Вес
- бинарь ~135 KB, RSS ~8 MB (Go-панель: RSS 40-70 MB)

## Совместимость
- та же БД `/etc/wdtt/panel.db` (схема v15), те же `wdtt://` подписки,
  заголовки Subscription-Userinfo/Profile-Title, admin API сервера
  (`POST /admin/users/update|delete` c `X-WDTT-Admin-Token: session_key`)
- пароль панели: PBKDF2-HMAC-SHA256 (формат `$wdttpanel$1$...`); хэши bcrypt от
  Go-панели не читаются — смена через `wdttpanel -set-password PW`

## Сборка
    make            # требуется libsqlite3-dev, libssl-dev
    make test-json

## Установка
    WDTT_NONINTERACTIVE=1 \
    WDTT_TLS_MODE=selfsigned WDTT_PANEL_HOST=<IP> \
    WDTT_USE_NGINX=no WDTT_EXTERNAL_PORT=8443 \
    WDTT_PANEL_SRC=/path/to/wdttpanel-c \
    bash install-wdttpanel.sh

Выбор: TLS (http / самоподписанный на IP / домен с готовым сертом / certbot),
nginx как фронтенд (да/нет), внешний порт. Без nginx панель сама держит TLS
на выбранном порту. panel-firewall.py специально не ставится (не трогает
существующие цепочки iptables).

## API (base /wdtt/)
- POST api/login {username,password}; POST api/logout
- GET api/me → {username, csrf} (CSRF в заголовке X-CSRF-Token на мутациях)
- GET api/users; POST api/users/{add,update,delete,reset-traffic}
- POST api/password/{main,panel}; GET/POST api/protocols
- GET api/status; GET/POST api/inbound[/save]
- GET sub/<subID> — подписка клиента (?format=raw — без base64)

## Известные проблемы оригинала (аудит)
Панель: XFF-спуфинг в rate-limit, безлимитные тела, неснимаемые сессии,
дедлоки cfg/panelDB при импорте — в C-версии исправлено.
Дата-плейн (Go, не переписывался): WRAP-ключ из пароля без stretching,
редирект-дедлоки botLoop, утечка rawDirectChallenges и пр. — см. аудит.
