# Совместимость PHANTOM с клиентскими приложениями (INCY, Happ) и собственный клиент

**Статус:** черновик исследования, поток A1. **Дата проверки источников:** 2026-11-14.
**Метки:** [Факт], [Вывод], [Предположение], [Не проверено] — по `BRIEF_FOR_CONTRIBUTORS.md`.

Ограничения: `docs.incy.cc`, `www.happ.su`, `apps.apple.com` из среды недоступны; INCY —
по исходникам документации в GitHub, Happ — по репозиториям GitHub и выдаче поиска; Xray-core
и sing-box — по локальным клонам от 2026-11-14.

## 0. Краткий вывод

1. **INCY и Happ — закрытые клиенты на Xray-core** без плагинов и подключаемых движков
   **[Факт]**. Поддержки PHANTOM (ALPN `phantom/1`, T1/T2, свои управляющие сообщения) нет
   и без их разработчиков не будет **[Вывод]**.
2. **Главная находка:** Xray-core (теги с v26.10.21) и sing-box (1.15.0, только alpha)
   реализуют **MASQUE CONNECT-IP (RFC 9484)** **[Факт: исходники]** — тот же стандарт, что
   запланированный T3 (`ARCHITECTURE.md` §5.5). Это теоретический путь к INCY/Happ через
   полную JSON-конфигурацию Xray без изменения их кода; есть ли `masque` в их сборках —
   **[Не проверено]**.
3. Цена — более слабый профиль: пароль (HTTP Basic) вместо Ed25519 mTLS, нет RFC 9729 и
   `Activate`, в Xray закрепляется хэш сертификата, а не SPKI (§4.4).
4. **Рекомендация:** основной путь — собственный клиент на едином Rust-ядре; совместимость с
   Xray-клиентами — только через T3 после MVP и эксперимента; outbound PHANTOM на Go — нет.

## 1. INCY

### 1.1. Идентификация и неоднозначность

- Под названием INCY найден один подходящий продукт: кроссплатформенный прокси-клиент,
  организация `INCY-DEV` в GitHub, сайт `incy.cc`, документация `docs.incy.cc`
  **[Факт: README `INCY-DEV/incy-platforms`]**.
- Идентификатор Android-пакета `llc.itdev.incy`, App Group на iOS `group.llc.itdev.incy`
  **[Факт]**. Из этого следует, что издатель — юридическое лицо с названием вида
  «ITDev LLC» **[Предположение]**: имя продавца в App Store не прочитано (сайт недоступен).
- Одноимённые, но не относящиеся к задаче: `incy-io-kiosk-frontend`, Incydr **[Факт]** (§9).

### 1.2. Платформы и распространение [Факт]

| Платформа | Канал | Статус |
|---|---|---|
| iOS, Apple TV, macOS | App Store (id6756943388, ссылка на витрину `ru`) | Релиз |
| Android, Android TV | Google Play `llc.itdev.incy`, APK в GitHub Releases, Obtainium | Релиз (Android 3.9.x по `RELEASE.json`) |
| Windows x64/ARM64, macOS (Apple Silicon, Intel), Linux x64/ARM64 | GitHub Releases (exe, dmg, deb, rpm, pkg, zip) | **pre-alpha** (desktop 3.9.0) |

### 1.3. Ядро и устройство

- «Cross-platform proxy client built on Xray-core» **[Факт: README]**.
- Для AmneziaWG используется отдельный движок `amneziawg-go` v3.1, только iOS и Android;
  desktop-клиент AmneziaWG не поддерживает и разбирает `.conf` как обычный WireGuard
  **[Факт: `subscription-format.en.md`]**. То есть разработчик уже встраивал второй
  движок помимо Xray — но сам, в закрытом коде.
- Перехват трафика на мобильных платформах — через `hev-socks5-tunnel` (TUN → локальный
  SOCKS-inbound Xray); на iOS упоминается «HEV mode» и Network Extension; на Android —
  `VpnService` с per-app режимом **[Факт: `premium-api.en.md`, `routing.en.md`,
  `app-management.en.md`]**.
- Разработчик сам указывает лимит памяти Network Extension на iOS «50 MB cap» и держит
  отдельный «memory-tight» режим, чтобы транспорт xhttp не убивался системой **[Факт:
  `app-management.en.md`]** — практическое подтверждение ограничения из §7.3.
- Открытость кода: **закрыт** **[Факт: в репозиториях нет исходников приложения]**;
  лицензия приложения не указана **[Факт]**.

### 1.4. Протоколы и форматы [Факт: `subscription-format.en.md`, `share-links.en.md`]

- Ссылки: `vless://` (основной), `vmess://`, `trojan://`, `ss://` (SIP002 и «modern»),
  `hysteria2://`/`hy2://`, `socks://`/`socks5://`, `http://user:pass@host:port`,
  `wireguard://`/`wg://`, `amneziawg://`/`awg://` (url-safe base64 от `.conf`).
- `ssr://`, `tuic://`, `hysteria://` распознаются, но **не разбираются** — серверы пропускаются.
- Тела подписок: base64 со ссылками; ссылки открытым текстом; сырой `.conf`
  WireGuard/AmneziaWG; JSON-контейнер `{"type":"amneziawg",...}`; **полная JSON-конфигурация
  Xray** (объект или массив объектов), которая «передаётся в xray-core почти без изменений».
- Патчи полной конфигурации: SOCKS/mixed/HTTP-inbound принудительно слушают `127.0.0.1`
  (порты 10808/10809 — точки входа клиента), добавляется `mixed`-inbound, если его нет,
  подменяются пути логов, добавляется DNS-правило `direct` **[Факт: `full-xray-config.en.md`]**.
  Ограничений на тип outbound в документации **не описано** **[Факт]** — значит, любой
  протокол, собранный в их Xray, теоретически проходит **[Вывод]**; какой версии Xray
  и с какими модулями собран INCY — **[Не проверено]**.
- Метаданные подписки — HTTP-заголовки `profile-title`, `profile-update-interval`,
  `support-email`, `autorouting` и др.; запросы клиента несут `x-hwid`. Deep links:
  `incy://add/<ссылка>`, `incy://import/<url или base64 .conf>`, `incy://crypt1/<payload>`
  (обфусцированная ссылка, есть npm-пакет `incy-link-encoder`), `incy://connect`
  **[Факт: `deep-links.en.md`, поиск GitHub]**.
- API для провайдеров: «Premium API» (зашифрованная конфигурация провайдера, лимиты
  устройств, резервные домены) — это API подписок, а не расширения сетевого стека
  **[Факт: оглавление документации]**.

## 2. Happ (Happ Proxy Utility)

### 2.1. Идентификация, платформы [Факт: README `Happ-proxy/happ-desktop`, `happ-ios`, `happ-android`]

| Платформа | Канал | Версия на 2026-11-14 |
|---|---|---|
| iOS (+ tvOS — отдельное приложение «Happ for TV» по выдаче поиска) | App Store id6504287215 (глобально); отдельное «Happ lite» id6799917773 «Only RU»; TestFlight | **[Не проверено]**: витрина недоступна |
| Android | Google Play `com.happproxy`, APK в GitHub | stable 4.10.1, beta 4.11.1 (Xray 26.10.31) |
| Windows x64/ARM64, macOS universal, Linux deb/rpm/pkg | GitHub Releases | 4.7.2 (Xray 26.10.29) |

Разработчик: в APKMirror фигурирует как `happdev` **[по выдаче поиска]**; юридическое лицо
не установлено **[Не проверено]**.

### 2.2. Ядро и открытость

- «Powered by the robust Xray core» **[Факт: README]**. Версии Xray указаны в манифестах
  релизов (`release`) **[Факт]**.
- Код **закрыт**: репозитории `happ-android`, `happ-ios`, `happ-desktop` содержат только
  README и JSON-манифест обновлений (в манифесте есть список заблокированных версий —
  механизм принудительного обновления) **[Факт]**.
- Android: в журнале изменений — «Migration to hev-socks5-tunnel», «Add Xray Tun»,
  «Added support for inbound authorization between tunnel and xray core» **[Факт: история
  файла `release`]**. Схема та же, что у INCY: TUN → tun2socks → локальный inbound Xray,
  либо встроенный TUN-inbound Xray.

### 2.3. Протоколы и форматы

- Протоколы из README: VLESS (Reality), VMess, Trojan, Shadowsocks, Socks **[Факт]**;
  Hysteria2 — в журнале изменений («Fixed hysteria sni and udpHop params») и по выдаче
  поиска **[Факт для упоминания; полнота — Не проверено]**. WireGuard/AmneziaWG —
  **[Не проверено]**.
- JSON-конфигурации Xray: журнал упоминает «custom (json) servers input», «JSON inbound mode»,
  импорт «json and .happ files» **[Факт]**. Какие outbound допускаются — **[Не проверено]**.
- Зашифрованные ссылки `happ://crypt…` (несколько версий), «hidden» и «encrypted
  subscriptions», HWID-ссылки, Provider ID с ежедневной проверкой на
  `check.happ-proxy.com/provider` **[по выдаче поиска; документация `happ.su/main/dev-docs`
  недоступна]**.
- API, плагины, внешние движки — **не найдено**. «Android TV API» в оглавлении документации
  относится к передаче конфигурации на ТВ **[по выдаче поиска]**.

## 3. Расширяемость сетевых ядер (Xray-core, sing-box)

### 3.1. Xray-core [Факт: клон `XTLS/Xray-core`, HEAD 2026-11-11]

- Лицензия **MPL-2.0** (файловый copyleft: изменённые файлы Xray должны оставаться открытыми,
  новые файлы могут иметь иную лицензию при соблюдении условий MPL) **[Факт для лицензии;
  юридическое толкование — Вывод]**.
- Протоколы (`proxy/`): blackhole, dns, dokodemo, freedom, http, hysteria, loopback,
  **masque**, shadowsocks, shadowsocks_2022, socks, trojan, tun, vless, vmess, wireguard.
- Протокол добавляется только компиляцией в бинарник (Go-пакет в `proxy/`, protobuf-конфиг,
  разбор JSON в `infra/conf/`). Динамических плагинов нет **[Вывод из структуры]**.
- SIP003-плагинов в Go-коде Xray не найдено (поиск по `sip003`) **[Факт]**.
- `masque`: клиент и сервер CONNECT-IP поверх HTTP/3 (`EnableDatagrams`, ALPN `h3`) и
  HTTP/2 (extended CONNECT); аутентификация — пользователь/пароль (`Authorization: Basic`);
  QUIC — форк `apernet/quic-go`; есть режим WARP (`cloudflareaccess.com`) **[Факт]**.
  Присутствует в тегах v26.10.21, v26.10.31, v26.11.9 **[Факт]**.
- TLS: `pinnedPeerCertSha256` — хэш **всего сертификата** (не SPKI), `curvePreferences`
  принимает `x25519mlkem768`, есть `certificates` с полем `usage` **[Факт]**. Работает ли
  клиентский сертификат в outbound — **[Не проверено]**.

### 3.2. sing-box [Факт: клон `SagerNet/sing-box`, HEAD 2026-11-10]

- Лицензия **GPL-3.0-or-later** с дополнением: «no derivative work may use the name or imply
  association with this application without prior consent» **[Факт]**. Встраивание в
  закрытый клиент несовместимо с GPL **[Вывод]**; INCY и Happ sing-box не используют
  **[Факт: оба заявляют Xray]**.
- Протоколы (`protocol/`): anytls, block, bridge, cloudflare, direct, dns, group, http,
  hysteria, hysteria2, masque, mixed, naive, openconnect, openvpn, redirect, shadowsocks,
  shadowtls, snell, socks, ssh, tailscale, tor, trojan, tuic, tun, vless, vmess, wireguard.
- L3-протоколы оформлены как **endpoint** (wireguard, tailscale, openvpn, openconnect,
  masque) — естественное место для L3-туннеля вроде PHANTOM **[Вывод]**.
- SIP003: «implemented in internal. Only `obfs-local` and `v2ray-plugin` are supported» —
  внешние плагины не запускаются **[Факт: `outbound/shadowsocks.md`]**.
- `masque-client` (RFC 9484), «Since sing-box 1.15.0»: HTTP/3 по умолчанию с откатом на
  HTTP/2/1, Basic-авторизация, `advertise_routes`, MTU 1280 по умолчанию **[Факт]**.
  Последний стабильный тег — v1.14.4; 1.15.0 существует только как alpha (до alpha.13)
  **[Факт]**.
- TLS outbound: `certificate_public_key_sha256` (закрепление **SPKI**, с 1.13.0),
  `client_certificate`/`client_key` (mTLS), `curve_preferences` с `X25519MLKEM768`
  **[Факт: `shared/tls.md`]**.
- Политика приёма новых протоколов в upstream не опубликована: нет `CONTRIBUTING.md`,
  шаблоны issue — только bug report **[Факт]**. Принимают ли автора сторонний протокол —
  **[Не проверено]**.
- Мобильная библиотека `experimental/libbox` — основа официальных клиентов sing-box
  **[Факт: каталог есть; что именно её используют SFA/SFI — Предположение]**.

## 4. Способы интеграции

### 4.1. (а) Новый outbound PHANTOM в Xray-core или sing-box

- Технически: Go-реализация протокола PHANTOM (TLS 1.3, `X25519MLKEM768`, Ed25519
  mTLS, закрепление SPKI, QUIC DATAGRAM, кадры T2, `Hello/Config/Activate/...`) как
  `proxy/phantom` в Xray или endpoint в sing-box. Примитивы в Go есть (quic-go с DATAGRAM,
  `crypto/tls` с `X25519MLKEM768`) **[Вывод из §3]**.
- Возражения:
  1. **Вторая реализация протокола** на другом языке и другой TLS-библиотеке — вдвое больше
     поверхности для ошибок, нарушает решение «TLS из одной библиотеки, сборка конфигурации
     в одном месте» (`ARCHITECTURE.md` §3.1, провайдер `aws-lc-rs`) **[Вывод]**.
  2. Даже принятый в upstream outbound не попадёт в INCY/Happ, пока их разработчики не
     обновят ядро **и** не добавят разбор конфигурации/ссылок **[Вывод]**.
  3. Приём в upstream не гарантирован (§3.2); форк Xray — бремя сопровождения.
  4. Привязка Rust-ядра к Go через FFI в чужом клиенте невозможна без кода клиента.
- Оценка: нереалистично для MVP; возможно как отдельный поздний проект.

### 4.2. (б) Локальный мост: процесс PHANTOM + локальный SOCKS5/HTTP или TUN

- Схема: `phantom-client` поднимает туннель и локальный SOCKS5; клиент на Xray ходит в
  него outbound'ом `socks` на `127.0.0.1`.
- Desktop (Linux, Windows, macOS вне песочницы): возможно, но бессмысленно — если работает
  `phantom-client` с TUN, сторонний клиент не нужен; SOCKS-мост ломает kill switch и DNS
  PHANTOM (`ARCHITECTURE.md` §6.2) **[Вывод]**.
- Android: одновременно активен **только один VpnService** на пользователя/профиль; запуск
  нового останавливает предыдущий **[Факт: developer.android.com, по выдаче поиска]**.
  Мост-процесс без VpnService должен был бы сам уметь ходить в сеть как обычное приложение
  (SOCKS-клиент поверх QUIC в фоне) — без TUN это уже не L3-туннель; ограничения фоновой
  работы Android делают его ненадёжным **[Вывод]**.
- iOS/macOS из App Store: туннель живёт в Network Extension конкретного приложения; одно
  VPN-подключение активно одновременно, отдельный долгоживущий фоновый процесс-мост
  приложению недоступен **[Вывод из модели платформы; первоисточник Apple не прочитан —
  Не проверено]**.
- Оценка: только desktop и только как отладочный режим.

### 4.3. (в) Плагины и подключаемые транспорты (SIP003)

- sing-box: SIP003 только встроенные `obfs-local` и `v2ray-plugin` **[Факт]**. Xray: SIP003
  нет **[Факт: поиск по коду]**. INCY поддерживает `ss://` SIP002 без описания `plugin=`
  **[Факт]**; Happ — **[Не проверено]**.
- SIP003 — это обёртка TCP-потока Shadowsocks, а не L3; на мобильных внешний бинарник-плагин
  не запустить **[Вывод]**.
- Оценка: неприменимо.

### 4.4. (г) Совместимость через стандартный протокол

Что уже умеют ядра из протоколов туннелирования уровня L3/стандартов IETF **[Факт: §3]**:

| Протокол | Xray-core | sing-box | INCY | Happ |
|---|---|---|---|---|
| WireGuard | да | да (endpoint) | да (+AmneziaWG на моб.) | [Не проверено] |
| MASQUE CONNECT-IP (RFC 9484) | да, с v26.10.21 | да, 1.15.0-alpha | [Не проверено] | [Не проверено] |
| OpenVPN, OpenConnect | нет | да | нет | нет |
| SOCKS5, HTTP CONNECT | да | да | да | да (Socks) |

- **Совпадение с T3 PHANTOM.** T3 = HTTP/3 + CONNECT-IP по RFC 9484 (`ARCHITECTURE.md` §5.5).
  Если сервер PHANTOM реализует T3 строго по RFC 9484/9297/9298, то outbound `masque`
  Xray формально является совместимым клиентом **[Вывод; интероперабельность не
  испытана]**.
- Расхождения с моделью PHANTOM, которые придётся принять или закрыть **[Вывод]**:
  1. Аутентификация: Basic-пароль в Xray/sing-box против Ed25519 mTLS и RFC 9729 в PHANTOM.
     RFC 9729 ни в одном ядре не найден **[Факт]**. Серверу T3 понадобится режим
     «пароль поверх TLS» или mTLS (в sing-box есть `client_certificate`; в Xray — не проверено).
  2. Нет `Activate{seq}`/`Superseded` (§4 архитектуры): переключение маршрута между
     соединениями сервер должен делать по-другому — например, «последнее аутентифицированное
     соединение побеждает», с известными рисками.
  3. Нет гарантированного `X25519MLKEM768` и закрепления SPKI в Xray-ссылке; в полной JSON-
     конфигурации `curvePreferences` и `pinnedPeerCertSha256` задаются, но последний —
     хэш сертификата, а не SPKI.
  4. Kill switch, DNS, MTU — на совести стороннего клиента.
  5. WebPKI-сертификат и собственный домен для T3 уже заложены в архитектуру (§5.5).
- WireGuard не предлагается: совместимость с ним отклонена по умолчанию (`PROJECT_STATUS.md`).
- Оценка: **единственный реалистичный путь к INCY/Happ без участия их разработчиков**,
  но после MVP и после эксперимента.

### 4.5. (д) Импорт конфигурации

- Отдельная схема `phantom://` в INCY/Happ не появится без их разработчиков **[Вывод]**.
- Для пути (г) достаточно **полной JSON-конфигурации Xray** с outbound `masque`: INCY
  документирует импорт по подписке и через `incy://import/<url>` **[Факт]**; Happ —
  импорт JSON-серверов **[Факт: журнал изменений]**. Секреты (пароль) окажутся в теле
  подписки — требуется HTTPS и короткоживущие URL; заголовок `x-hwid` от INCY — данные
  об устройстве, которые сервер подписок PHANTOM не должен хранить без нужды **[Вывод]**.
- Для собственного клиента — подписанный конфигурационный файл (`phantom-config`, подпись
  Ed25519) и, при необходимости, QR с тем же содержимым; ссылочный формат — этап 6.

## 5. Ограничения существующих клиентов и платформ

- Оба клиента закрыты, без плагинов; новые протоколы — только через их разработчиков;
  оба — L4-прокси с TUN через tun2socks, L3 — только встроенными протоколами **[Вывод]**.
- iOS: лимит памяти Packet Tunnel Provider Apple не документирует; на форуме Apple — 50 MiB
  для iOS 15–16 и сообщения о ~15 MiB на iOS 17, DTS предупреждает об изменениях **[по
  выдаче поиска]**; INCY называет «50 MB cap» **[Факт]**.
- Android: один активный VpnService на пользователя/профиль **[по выдаче поиска]**.
- Магазины: у Happ отдельное приложение «Only RU» для российской витрины **[Факт]** —
  косвенный признак рисков витрин **[Предположение]**; правила App Review — **[Не проверено]**.

## 6. Необходимые изменения в PHANTOM

Для пути (г), если владелец его выберет **[Вывод]**:

1. Реализовать T3 строго по RFC 9484 (и 9297/9298 для datagrams), без собственных
   расширений, которые чужой клиент не понимает.
2. Режим аутентификации T3 для сторонних клиентов (Basic поверх TLS или mTLS) — отдельный
   ADR с оценкой рисков; учёт таких клиентов отдельно от Ed25519-ключей.
3. Правило выбора активного соединения без `Activate` для таких клиентов.
4. Генератор JSON-конфигурации Xray (`masque` outbound + `tls` с `curvePreferences`,
   `pinnedPeerCertSha256`) и отдельный сервер подписок либо одноразовые ссылки.
5. Стенд интероперабельности: Xray `masque` (Go) ↔ сервер PHANTOM T3 (Rust), затем INCY и
   Happ на реальных устройствах (выполняет владелец).

## 7. Собственный клиент на едином Rust-ядре

### 7.1. Общая схема [Вывод]

`phantom-core` + `phantom-transport` + `phantom-crypto` компилируются в библиотеку; слой
платформы даёт файловый дескриптор TUN (или поток пакетов) и применяет маршруты/DNS.
`phantom-network` (`ARCHITECTURE.md` §2) на мобильных платформах вырождается: маршруты и
DNS задаёт ОС по описанию туннеля. Привязки — UniFFI (Kotlin, Swift) или JNI.

### 7.2. Android

- `VpnService.Builder` → fd TUN передаётся в Rust; сокеты транспорта нужно исключать из
  туннеля (`protect()`) **[Вывод; API — по выдаче поиска]**.
- Kill switch — системный «Always-on VPN» + «Block connections without VPN» (настройка
  пользователя) **[Предположение: первоисточник не прочитан]**.
- Распространение: Google Play, APK, F-Droid; трудоёмкость средняя.

### 7.3. iOS и macOS

- `NEPacketTunnelProvider` в расширении; нужна платная учётная запись Apple Developer и
  entitlement Network Extension **[Предположение: документация Apple не прочитана]**.
- Память: проектировать под ≲15 MiB с запасом (§5); `aws-lc-rs`, `quinn` и буферы нужно
  измерять. Это главный технический риск **[Вывод]**.
- macOS: то же расширение (System/App Extension) либо вне App Store — отдельный
  привилегированный процесс; нотаризация обязательна **[Предположение]**.
- Распространение: App Store (с рисками витрин, §5) или TestFlight. Трудоёмкость —
  **высокая**.

### 7.4. Windows

- TUN — Wintun (используется Firezone, крейт `wintun`; Mullvad — `wintun-bindings`)
  **[Факт: Cargo.lock]**. Kill switch — WFP (у Mullvad отдельный крейт `talpid-winfw`)
  **[Факт: дерево репозитория]**. Служба Windows + неприв. UI, подпись драйвера Wintun
  уже есть у поставщика **[Предположение]**. Трудоёмкость — **средняя/высокая**.

### 7.5. Linux

Целевая платформа MVP (`ARCHITECTURE.md` §6); трудоёмкость — наименьшая из пяти.

### 7.6. Известные проекты с единым Rust-ядром [Факт: репозитории, 2026-11-14]

| Проект | Что общее | Платформы | Лицензия |
|---|---|---|---|
| Firezone | `rust/libs/connlib` — «connectivity library shared by all clients»; `rust/client-ffi` с UniFFI; клиенты `kotlin/android`, `swift/apple`, gui/headless для Windows/Linux | Android, iOS, macOS, Windows, Linux | Apache-2.0 (корневой LICENSE) |
| NymVPN | `nym-vpn-core` (Rust), `nym-vpn-lib-uniffi`; каталоги `nym-vpn-android`, `nym-vpn-apple`, `nym-vpn-windows`; README: «cross-platform VPN client written in Rust» | Android, iOS, macOS, Windows, Linux | GPL-3.0 |
| Mullvad VPN | Rust-демон (`talpid-*`, `mullvad-daemon`) для desktop и Android (`mullvad-jni`); **iOS — «completely standalone implementation»** | Desktop + Android общее ядро; iOS отдельно | см. `LICENSE.md` [Не проверено] |

Вывод: единое Rust-ядро на всех пяти платформах **реализуемо и подтверждено практикой**
(Firezone, NymVPN); Mullvad показывает, что iOS может потребовать отдельной реализации.

## 8. Сводная таблица и рекомендация

| Способ | INCY | Happ | Что требуется | Ограничения | Оценка |
|---|---|---|---|---|---|
| (а) Outbound PHANTOM в Xray/sing-box | Нет без разработчика | Нет без разработчика | Go-реализация протокола; приём в upstream или форк; обновление клиентов | Вторая реализация TLS-профиля; GPL у sing-box; закрытые клиенты | Низкая |
| (б) Локальный мост SOCKS/TUN | Desktop — технически да; моб. — нет | То же | `phantom-client` + SOCKS-inbound | Один VPN на iOS/Android; ломает kill switch/DNS | Низкая (только отладка) |
| (в) SIP003/плагины | Нет | Нет [Не проверено] | — | Только встроенные плагины; не L3 | Неприменимо |
| (г) Стандарт: CONNECT-IP (T3) | Возможно, если в сборке Xray есть `masque` [Не проверено] | То же [Не проверено] | T3 строго по RFC 9484; режим аутентификации для чужих клиентов; генератор JSON | Нет mTLS/9729/Activate; сторонний kill switch; после MVP | Средняя, требует эксперимента |
| (д) Импорт конфигурации | Полный Xray JSON, `incy://import` | JSON-серверы | Только вместе с (г) | Секреты в подписке | Вспомогательный |
| Собственный клиент | — | — | Слои платформ над Rust-ядром | iOS-память и entitlement; подпись; магазины | **Высокая, рекомендуется** |

**Рекомендация.** (1) Собственный клиент — основной путь; порядок: Linux → Windows →
Android → macOS/iOS. (2) Ядро сразу проектировать как библиотеку с FFI (UniFFI) и
интерфейсом «пакеты внутрь/наружу» без собственного TUN — по образцу connlib. (3) Путь
(г) держать как необязательную цель T3; до решения не тратить ресурсы на (а)–(в).
(4) Перед любыми обещаниями совместимости провести эксперимент: Xray `masque` outbound
против тестового CONNECT-IP-сервера, затем INCY и Happ (выполняет владелец).

## 9. Вопросы владельцу

1. Какой именно INCY имеется в виду — клиент `incy.cc` (INCY-DEV)? Если другой — дать ссылку.
2. Нужна ли совместимость со сторонними клиентами вообще, или достаточно собственного
   клиента? От ответа зависит, входит ли T3 в обязательный объём.
3. Допустим ли для «режима совместимости» более слабый профиль безопасности (пароль вместо
   Ed25519-ключа, без `Activate`, чужой kill switch)?
4. Целевые платформы и порядок; нужен ли iOS в первой версии; есть ли платная учётная
   запись Apple Developer и Google Play.
5. Готов ли владелец связаться с разработчиками INCY/Happ (их каналы: feedback.incy.cc,
   issues.happ.su) и проверить на устройствах, проходит ли JSON с outbound `masque`?
6. Разрешить среде доступ к `docs.incy.cc`, `www.happ.su`, `apps.apple.com`,
   `developer.apple.com`, `developer.android.com` для перепроверки.

## 10. Не удалось проверить

- Страницы App Store и Google Play (продавец, версии, минимальные ОС) — сайты недоступны.
- Документация Happ (`happ.su/main/dev-docs`): форматы `happ://crypt*`, список протоколов,
  допустимые outbound в JSON — только по выдаче поиска.
- Наличие модуля `masque` в сборках Xray внутри INCY и Happ и фактическая
  интероперабельность Xray `masque` с CONNECT-IP-сервером на Rust.
- Поддержка клиентского сертификата в TLS-outbound Xray.
- Документация Apple о Network Extension (entitlements, лимит памяти), правила App Review;
  документация Android VpnService прочитана только в пересказе поиска.
- Политика upstream Xray/sing-box по приёму новых протоколов.
- Лицензия Mullvad VPN (файл не прочитан), использование `libbox` официальными клиентами
  sing-box.

## 11. Источники (проверено 2026-11-14)

Прочитаны (клоны GitHub): `INCY-DEV/incy-platforms` (README, `RELEASE.json`);
`INCY-DEV/incy-docs` (`ru/dev-docs/*.en.md`: subscription-format, share-links,
full-xray-config, deep-links, app-management, routing, premium-api, README);
`Happ-proxy/happ-desktop`, `happ-ios`, `happ-android` (README, `release` и его история);
`XTLS/Xray-core` (LICENSE, `proxy/masque`, `transport/internet/masque`,
`transport/internet/tls/config.go`, `infra/conf/{masque,transport_security}.go`, теги);
`SagerNet/sing-box` (LICENSE, `protocol/`, `docs/configuration/endpoint/masque-client.md`,
`shared/tls.md`, `shared/v2ray-transport.md`, `outbound/shadowsocks.md`, теги);
`firezone/firezone`, `nymtech/nym-vpn-client`, `mullvad/mullvadvpn-app` (README, деревья,
`Cargo.lock`).

По выдаче поиска (не открывались): `docs.incy.cc`, `www.happ.su/main/dev-docs`,
`apps.apple.com` (Happ id6504287215), `www.apkmirror.com/apk/happdev/happ-proxy-utility/`,
`sourceforge.net/projects/incy.mirror/`; `developer.apple.com/forums/thread/73148`,
`.../728876`, `.../697800` (память Packet Tunnel Provider);
`developer.android.com/develop/connectivity/vpn`,
`developer.android.com/reference/android/net/VpnService` (один активный VPN).

Недоступны из среды: `docs.incy.cc`, `www.happ.su`, `apps.apple.com` (DNS вне allowlist).
