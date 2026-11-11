# Происхождение и благодарности

**wdttpanel-c** — независимая C-реализация веб-панели для экосистемы
[WDTT](https://github.com/ildarmaga/wdtt) / [wdtt-panel](https://github.com/ttrroyy/wdtt-panel)
(«Independent development of WDTT VPN server and web panel», форк ildarmaga/wdtt).

- Совместимость с оригиналом: та же БД `panel.db` (схема v15), форматы подписок
  `wdtt://`, admin API дата-плейна, протоколы запускаются тем же `protocols.py`.
- Дата-плейн (Go-сервер WDTT, Xray, внешние протоколы) берётся из оригинального
  репозитория — здесь только заменяющая его Go-панель часть, написанная на C.
- Лицензия: GNU GPL v3 (как у оригинала).
