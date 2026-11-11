# R6. Технологический стек Rust и зависимости PROJECT PHANTOM

**Дата проверки источников:** 2026-11-10 (метаданные crates.io, база RustSec, первая проверка контейнера) и 2026-11-11 (README и исходники upstream, документация systemd/cargo-deny, поиск, повторная проверка контейнера).
**Область:** этап 1, исследование стека. Код проекта не пишется, зависимости не устанавливались.
**Toolchain в среде:** rustc/cargo 1.97.0.

Метки достоверности: **[Факт]** — подтверждено источником [n]; **[Вывод]** — рассуждение на основе фактов; **[Предположение]** — гипотеза; **[Не проверено]** — знание из памяти, источник в этой сессии открыть не удалось.

## Резюме

1. **[Вывод]** Рекомендуемое ядро MVP: `tokio` 1.54.1 + `quinn` 0.11.12 (`quinn-proto` 0.11.19) + `rustls` 0.23.46 с провайдером `aws-lc-rs` 1.19.0 + `tokio-rustls` 0.26.6 для резервного TCP/TLS. Ровно эту связку (quinn + rustls/aws-lc-rs + h3 + tokio) использует Mullvad в своём MASQUE-прокси и приложении [11].
2. **[Факт]** `quinn-proto` получил в 2026 г. восемь advisories класса DoS/panic/исчерпание памяти; все закрыты в `>= 0.11.18` [2]. Независимого аудита quinn поиск не нашёл [26]. Это главный риск транспортного слоя: версии надо фиксировать не ниже 0.11.19 и ограничивать ресурсы на соединение.
3. **[Факт]** `rustls` 0.23.46 закрывает четыре advisories от 2026-10-14, включая downgrade гибридного key exchange к классическому (RUSTSEC-2026-0349) [2]. X25519MLKEM768 доступен только с `aws-lc-rs`; feature `prefer-post-quantum` входит в default-набор 0.23 и ставит группу первой по приоритету [5].
4. **[Факт]** `snow` 0.10.0 не проходил формального аудита (предупреждение в README) [8]. `gotatun` 0.10.3 (Mullvad, форк BoringTun) прошёл аудит Assured в январе–феврале 2026 г., лицензия MPL-2.0, MSRV 1.95 [1][10]. `boringtun` 0.7.1: README предупреждает о реструктуризации и не советует опираться на master [9].
5. **[Факт]** `ml-kem` 0.3.4 (RustCrypto) никогда не аудировался независимо [18]. **[Вывод]** Постквантовый обмен лучше получать через `rustls` + `aws-lc-rs`, а не собирать вручную.
6. **[Вывод]** Для MVP достаточно многопоточного work-stealing рантайма tokio. io_uring- и thread-per-core-рантаймы не рекомендуются: последние релизы `tokio-uring`, `monoio`, `glommio` датированы 2024 г. [1].
7. **[Факт]** В контейнере есть root, `CAP_NET_ADMIN`, `/dev/net/tun`, `nft` 1.0.9, `unshare`/`nsenter`; нет `ip`, `tc`, `resolvectl`, `ping`, `tcpdump`; в ядре `CONFIG_NET_SCH_NETEM` не включён, PID 1 не systemd [3]. **[Вывод]** netns + veth + TUN + nftables тестировать здесь можно (через netlink из тестового кода), netem и systemd-resolved — нет.
8. **[Факт]** Блоги Cloudflare, Mullvad и Google из сессии недоступны (хосты вне списка разрешённых). Обоснование «Rust против Go/C» по этим публикациям помечено **[Не проверено]**.

## 1. Версии, лицензии, MSRV (crates.io, проверено 2026-11-10) [1]

| Крейт | Стабильная версия | Дата релиза | Лицензия | MSRV (rust-version) |
|---|---|---|---|---|
| tokio | 1.54.1 | 2026-10-21 | MIT | 1.85 |
| quinn | 0.11.12 | 2026-09-14 | MIT OR Apache-2.0 | 1.85 |
| quinn-proto | 0.11.19 | 2026-09-30 | MIT OR Apache-2.0 | 1.85 |
| quinn-udp | 0.6.3 | 2026-09-30 | MIT OR Apache-2.0 | 1.88 |
| s2n-quic | 1.91.0 | 2026-10-14 | Apache-2.0 | 1.95 |
| quiche | 0.30.1 | 2026-11-10 | BSD-2-Clause | 1.88 |
| tokio-quiche | 0.23.0 | 2026-11-10 | BSD-2-Clause | 1.88 |
| noq | 1.4.0 | 2026-10-20 | MIT OR Apache-2.0 | 1.88 |
| iroh-quinn | 0.16.1 | 2026-01-31 | MIT OR Apache-2.0 | 1.88 |
| msquic | 2.5.1-beta | 2025-07-11 | MIT | не указан |
| h3 | 0.0.8 | 2025-05-06 | MIT | 1.70 |
| h3-quinn | 0.0.10 | 2025-05-06 | MIT | 1.70 |
| h3-datagram | 0.0.2 | 2025-05-06 | MIT | не указан |
| rustls | 0.23.46 (есть 0.24.0-dev.2) | 2026-10-14 | Apache-2.0 OR ISC OR MIT | 1.71 |
| tokio-rustls | 0.26.6 | 2026-09-28 | MIT OR Apache-2.0 | 1.71 |
| rustls-platform-verifier | 0.7.1 | 2026-09-24 | MIT OR Apache-2.0 | 1.85 |
| rustls-webpki | 0.103.16 | 2026-10-20 | ISC | 1.71 |
| ring | 0.17.14 | 2025-03-11 | Apache-2.0 AND ISC | 1.66 |
| aws-lc-rs | 1.19.0 | 2026-10-28 | ISC AND (Apache-2.0 OR ISC) | 1.71 |
| snow | 0.10.0 | 2025-07-19 | Apache-2.0 OR MIT | 1.85 |
| boringtun | 0.7.1 | 2026-05-01 | BSD-3-Clause | не указан |
| gotatun | 0.10.3 | 2026-11-09 | MPL-2.0 | 1.95 |
| wireguard-rs (crates.io) | 0.0.0 | 2022-07-30 | AGPL-3.0-or-later | не указан |
| chacha20poly1305 | 0.11.0 | 2026-06-28 | Apache-2.0 OR MIT | 1.85 |
| aes-gcm | 0.11.1 | 2026-08-21 | Apache-2.0 OR MIT | 1.85 |
| x25519-dalek | 3.0.0 | 2026-07-06 | BSD-3-Clause | 1.85 |
| ed25519-dalek | 3.0.0 | 2026-07-06 | BSD-3-Clause | 1.85 |
| hkdf | 0.13.0 | 2026-03-30 | MIT OR Apache-2.0 | 1.85 |
| sha2 | 0.11.1 | 2026-10-12 | MIT OR Apache-2.0 | 1.88 |
| blake3 | 1.8.7 | 2026-08-20 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception | не указан |
| ml-kem | 0.3.4 | 2026-10-31 | Apache-2.0 OR MIT | 1.87 |
| zeroize | 1.9.1 | 2026-10-06 | Apache-2.0 OR MIT | 1.85 |
| subtle | 2.6.1 | 2024-06-24 | BSD-3-Clause | не указан |
| rand | 0.10.3 | 2026-09-20 | MIT OR Apache-2.0 | 1.85 |
| getrandom | 0.4.3 | 2026-06-17 | MIT OR Apache-2.0 | 1.85 |
| secrecy | 0.10.3 | 2024-10-09 | Apache-2.0 OR MIT | 1.60 |
| tun | 0.8.14 | 2026-07-21 | WTFPL | не указан |
| tun-rs | 2.8.18 | 2026-11-04 | Apache-2.0 | не указан |
| tokio-tun | 1.0.0 | 2026-11-08 | MIT OR Apache-2.0 | 1.88 |
| rtnetlink | 0.24.0 | 2026-11-04 | MIT | 1.85 |
| netlink-packet-route | 0.34.0 | 2026-11-03 | MIT | 1.77 |
| nftables | 0.6.3 | 2025-08-15 | MIT OR Apache-2.0 | 1.76 |
| rustables | 0.9.0 | 2026-09-21 | GPL-3.0-or-later | не указан |
| nftnl | 0.9.4 | 2026-08-11 | MIT OR Apache-2.0 | 1.85 |
| zbus | 6.2.1 | 2026-11-01 | MIT | 1.89 |
| serde | 1.0.229 | 2026-07-18 | MIT OR Apache-2.0 | 1.56 |
| toml | 1.2.1+spec-1.1.0 | 2026-11-06 | MIT OR Apache-2.0 | 1.85 |
| clap | 4.6.7 | 2026-09-14 | MIT OR Apache-2.0 | 1.85 |
| tracing | 0.1.44 | 2025-12-18 | MIT | 1.65 |
| tracing-subscriber | 0.3.23 | 2026-03-13 | MIT | 1.65 |
| metrics | 0.24.6 | 2026-05-13 | MIT | 1.71.1 |
| sd-notify | 0.5.0 | 2026-03-09 | MIT OR Apache-2.0 | 1.82 |
| minisign-verify | 0.3.0 | 2026-09-25 | MIT | не указан |
| sigstore | 0.15.0 | 2026-11-05 | Apache-2.0 | не указан |
| cargo-deny | 0.20.2 | 2026-07-09 | MIT OR Apache-2.0 | 1.88 |
| cargo-audit | 0.23.0 | 2026-11-10 | Apache-2.0 OR MIT | 1.88 |
| cargo-vet | 0.10.3 | 2026-10-22 | Apache-2.0/MIT | 1.85 |
| cargo-fuzz | 0.13.2 | 2026-06-09 | MIT OR Apache-2.0 | не указан |
| proptest | 1.12.0 | 2026-10-10 | MIT OR Apache-2.0 | 1.88 |
| loom | 0.7.3 | 2026-11-08 | MIT | 1.73 |
| criterion | 0.8.2 | 2026-02-04 | Apache-2.0 OR MIT | 1.86 |
| cargo-nextest | 0.9.151 | 2026-11-03 | Apache-2.0 OR MIT | 1.91 |
| tokio-uring | 0.5.0 | 2024-05-27 | MIT | не указан |
| monoio | 0.2.4 | 2024-08-20 | MIT OR Apache-2.0 | не указан |
| glommio | 0.9.0 | 2024-03-25 | Apache-2.0 OR MIT | 1.65 |

**[Вывод]** Минимальный MSRV рабочего пространства при рекомендуемом стеке — 1.88 (задают `quinn-udp`, `sha2`, `tokio-tun`); при включении `gotatun` или `s2n-quic` — 1.95. Установленный toolchain 1.97.0 покрывает оба варианта.

## 2. Advisories RustSec (база на коммите 28d73fc от 2026-11-10) [2]

- **tokio:** RUSTSEC-2026-0384 (race в `time::Interval`, затронута только 1.54.0, исправлено в 1.54.1); RUSTSEC-2026-0386 (unsound: `AsyncFd::new` нарушает I/O safety, исправлено в 1.51.6 и 1.53.3). `AsyncFd` — типичный способ обернуть TUN fd, поэтому версия ниже 1.53.3 недопустима.
- **quinn-proto:** RUSTSEC-2026-0037, -0185, -0338, -0339, -0340, -0341, -0342, -0343 — DoS, удалённая паника, исчерпание памяти при сборке потоков, обход лимита буфера DATAGRAM; все исправлены в `>= 0.11.18`.
- **rustls:** RUSTSEC-2026-0285 (handshake-сообщения принимались через границы уровней шифрования; исправлено в 0.23.45); RUSTSEC-2026-0346 (`Debug` раскрывал TLS-секреты сессии), -0347 (данные уходили внешнему серверу после отказа ECH), -0348 (до 1 GiB аллокации при brotli-декомпрессии сертификата), -0349 (downgrade к классическому key exchange) — исправлено в 0.23.46.
- **rustls-webpki:** RUSTSEC-2026-0049, -0098, -0099, -0104, -0382 — последнее исправлено в 0.103.16.
- **aws-lc-sys:** RUSTSEC-2026-0044…-0048 (X.509 name constraints, timing в AES-CCM, PKCS7, CRL) — исправлено в `>= 0.39.0`; актуальная версия 0.47.0.
- **ring:** RUSTSEC-2025-0009 (паника в AES при overflow checks, исправлено в 0.17.12); RUSTSEC-2025-0007 «unmaintained» отозван 2025-02-22, в тексте advisory указано, что сопровождение вернулось к прежнему режиму.
- **snow:** RUSTSEC-2024-0011 (инкремент nonce без аутентификации, исправлено в 0.9.5).
- **nftnl:** RUSTSEC-2025-0126 (heap-buffer-overflow в `Batch::with_page_size`, исправлено в 0.9.0).
- **rand:** RUSTSEC-2026-0097 (unsound, исправлено в 0.10.1). **bytes:** RUSTSEC-2026-0007 (исправлено в 1.11.1). **tracing-subscriber:** RUSTSEC-2025-0055 (ANSI-последовательности в логах, исправлено в 0.3.20).
- **Без записей в базе:** quinn-udp, s2n-quic, quiche, tokio-quiche, h3, h3-quinn, noq, boringtun, gotatun, chacha20poly1305, x25519-dalek, hkdf, blake3, ml-kem, zeroize, subtle, getrandom, secrecy, tun, tun-rs, tokio-tun, rtnetlink, netlink-packet-route, nftables, rustables, zbus, serde, toml, clap, metrics, rustix, libc.

**[Вывод]** Все перечисленные актуальные версии таблицы раздела 1 находятся выше исправленных границ. Отсутствие записей в RustSec не означает отсутствия дефектов: у молодых крейтов (`tokio-tun` 1.0.0, `h3-datagram`) оно скорее отражает малую изученность.

## 3. Анализ по областям

### 3.1 Язык и runtime

- **[Факт]** Mullvad перевёл свою реализацию WireGuard на Rust: `gotatun` — userspace-реализация и форк BoringTun (Cloudflare), прошедшая независимый аудит; рабочее пространство приложения Mullvad объявляет `rust-version = "1.97.1"` и зависит от `gotatun` 0.10.2 [10][11].
- **[Не проверено]** Мотивы Cloudflare (BoringTun, 2019) и Mullvad (GotaTun, 2025: замена wireguard-go из-за сбоев на границе Go/FFI), а также статистика Google/Microsoft о доле memory-safety уязвимостей (порядка 70 %) известны из памяти; блоги из сессии недоступны, цифры в документ не включены.
- **[Вывод]** Против C: парсеры пакетов и handshake обрабатывают недоверенный ввод, а аудит GotaTun отдельно отметил пользу проверок на этапе компиляции [10]. Против Go: сборщик мусора и собственный runtime усложняют встраивание и контроль времени жизни секретов (`zeroize`); это аргумент по существу, но количественно в этой сессии не подтверждён.
- **[Факт]** Многопоточный планировщик tokio исполняет futures на пуле потоков со стратегией work-stealing, по умолчанию по одному worker на ядро; есть и current-thread вариант [25].
- **[Вывод]** Для пакетной обработки цена work-stealing — миграция задач между ядрами и синхронизация очередей. В MVP это компенсируется батчингом (GSO/GRO в `quinn-udp` [4], offload на TUN [19]) и закреплением пути «TUN → шифрование → сокет» за одной задачей на соединение. Thread-per-core и io_uring-рантаймы отложить: `tokio-uring` 0.5.0 (2024-05), `monoio` 0.2.4 (2024-08), `glommio` 0.9.0 (2024-03) не выпускались более двух лет [1], а quinn поддерживает из коробки только рантаймы tokio и smol [4].

### 3.2 QUIC

- **[Факт]** quinn: «application-layer datagrams for small, unreliable messages»; API `Datagrams::send(data, drop)` с вытеснением старых датаграмм и `max_size()`; настраиваемые буферы приёма и отправки датаграмм [4].
- **[Факт]** quinn: MTU discovery включён по умолчанию (`MtuDiscoveryConfig`), есть детектор black hole, `initial_mtu` и `min_mtu` не ниже 1200; congestion controllers — Cubic (по умолчанию), NewReno, BBR; `enable_segmentation_offload` по умолчанию `true`; idle timeout по умолчанию 30 с; серверный флаг `migration`; ACK frequency — опция [4].
- **[Факт]** `quinn-udp` реализует segmentation offload для отправки и приёма (GSO/GRO), пакетный ввод-вывод и ECN [4].
- **[Факт]** Криптография quinn подключаемая; feature по умолчанию — `rustls-ring`, есть `rustls-aws-lc-rs`, `rustls-aws-lc-rs-fips`, `platform-verifier`, `qlog` [4].
- **[Не проверено]** Соответствие реализации датаграмм именно RFC 9221 и поддержка 0-RTT в quinn: в открытых файлах номер RFC и API 0-RTT не найдены; проверить по docs.rs на этапе 2.
- **[Факт]** Независимого аудита quinn поиск не выявил [26].
- **[Факт]** Mullvad: `mullvad-masque-proxy` («A limited functionality UDP over HTTP3 proxy») зависит от `quinn`, `quinn-proto`, `h3` 0.0.7, `h3-datagram` 0.0.1, `h3-quinn` 0.0.9 (feature `datagram`) и `rustls`; quinn собирается с `runtime-tokio` и `rustls-aws-lc-rs` [11]. QUIC-обфускация Mullvad построена на MASQUE (RFC 9298, проксирование UDP в HTTP) и доступна в desktop-приложении с версии 2025.9 [12].
- **[Факт]** `h3`: README называет крейт «still very experimental»; версия 0.0.8 от 2025-05-06; `h3-datagram` 0.0.2 — «rfc9297 extension for the h3 crate» [1][15]. Готового крейта CONNECT-IP (RFC 9484) в ходе исследования не найдено; крейт `masque` на crates.io — заглушка 0.0.0 [1].
- **[Факт]** `quiche`: QUIC и HTTP/3 от Cloudflare, используется на edge-сети Cloudflare, в DNS-резолвере Android и в curl; MSRV 1.88; C API через feature `ffi` [14]. `tokio-quiche` связывает `quiche` с tokio и даёт готовый `H3Driver` [14]. **[Не проверено]** Использование quiche/tokio-quiche в WARP (MASQUE) и зависимость от BoringSSL — из памяти, блог недоступен.
- **[Факт]** `s2n-quic` (AWS): Apache-2.0, MSRV 1.95 со скользящей политикой, CUBIC, pacing, GSO, PMTUD, TLS через s2n-tls или rustls, на Linux криптография через `aws-lc-rs` [13]. `noq` — форк quinn от n0 с фокусом на QUIC Multipath и NAT traversal [16]. `neqo` — реализация Mozilla для Firefox, TLS через NSS [16]. `msquic` — библиотека на C с Rust-обвязкой, версия крейта 2.5.1-beta [1][16].

### 3.3 TLS

- **[Факт]** rustls 0.23: TLS 1.2 и 1.3, 0-RTT в TLS 1.3, raw public keys RFC 7250 для TLS 1.3, клиентский ECH, сжатие сертификатов RFC 8879, гибридный X25519MLKEM768 [5]. `#![forbid(unsafe_code)]` на уровне крейта [5].
- **[Факт]** Провайдер по умолчанию — `aws-lc-rs`; `ring` — через feature. X25519MLKEM768 доступен только с `aws-lc-rs`. Default features 0.23: `aws_lc_rs`, `logging`, `prefer-post-quantum`, `std`, `tls12`; `prefer-post-quantum` делает X25519MLKEM768 группой высшего приоритета, без него группа доступна, но не первая [5].
- **[Факт]** При `default-features = false` feature `prefer-post-quantum` теряется; Mullvad включает его явно [11]. **[Вывод]** В проекте включать явно и проверять тестом согласованную группу.
- **[Факт]** С 0.24 провайдеры вынесены в отдельные крейты (`rustls-aws-lc-rs`, `rustls-ring`), и провайдер нужно передавать явно; 0.24 пока в статусе dev (0.24.0-dev.2 от 2026-10-14) [1][6]. Политика: исправления безопасности — для веток моложе 2 лет; MSRV не новее 9 версий [6].
- **[Факт]** Аудит: Cure53, май–июнь 2020, rustls 0.16.0+ вместе с ring и webpki, финансирование CNCF; отчёт `audit/TLS-01-report.pdf` лежит в репозитории [6][7]. **[Вывод]** Аудиту более шести лет, с тех пор сменился провайдер по умолчанию; более свежих аудитов в этой сессии не найдено.
- **[Факт]** `aws-lc-rs`: ring-совместимый API поверх AWS-LC; обычная сборка не требует CMake, bindgen и Go; FIPS-сборка требует CMake и Go [17]. **[Вывод]** Это C/asm-код под FFI — основная unsafe-поверхность стека; компенсируется фиксацией версий и отслеживанием advisories `aws-lc-sys`.

### 3.4 Noise и реализации WireGuard

- **[Факт]** `snow` 0.10.0: «This library has not received any formal audit»; отслеживает Noise rev. 34; резолверы — default (RustCrypto: aes-gcm, chacha20poly1305, blake2, sha2, curve25519) и `ring` (features `ring-resolver`, `ring-accelerated`); есть `hfs`, `pqclean_kyber1024`, `risky-raw-split`. Последний релиз — 2025-07-19 [1][8].
- **[Факт]** `boringtun` 0.7.1 (2026-05-01), BSD-3-Clause: библиотека реализует протокол WireGuard без сетевого и туннельного стека; README предупреждает о реструктуризации и советует использовать версии с crates.io [1][9].
- **[Факт]** `gotatun` 0.10.3 (2026-11-09): форк BoringTun; вклад после 2026-03-05 под MPL-2.0, более ранний — BSD-3-Clause; собирается как библиотека (`--lib --no-default-features`); AEAD-бэкенд `aws-lc-rs` (по умолчанию) или `ring`; features `device`, `socket`, `tun`, `daita` [10].
- **[Факт]** Аудит GotaTun: Assured Security Consultants, 2026-01-19…2026-02-15; вне области CLI, DAITA и внешние зависимости; крупных уязвимостей нет, 2 находки low (LFSR для идентификаторов peer, отсутствие padding до 16 байт), 9 notes; отмечена зависимость от крейтов с одним сопровождающим [10].
- **[Факт]** `wireguard-rs` на crates.io — заглушка 0.0.0 (2022), AGPL-3.0-or-later [1]. **[Не проверено]** Состояние официального репозитория wireguard-rs (git.zx2c4.com недоступен из сессии).
- **[Вывод]** Если внутренний протокол PHANTOM совместим с WireGuard, `gotatun` можно переиспользовать как библиотеку (аудит, активные релизы); цена — MPL-2.0 (file-level copyleft) и MSRV 1.95. Если нужен собственный Noise-handshake, `snow` применим, но требует собственного ревью и фаззинга. Решение зависит от спецификации протокола (вопрос к архитектору).

### 3.5 Крипто-крейты

- **[Факт]** `chacha20poly1305` и `aes-gcm` прошли аудит NCC Group (2020, без существенных находок); реализации задуманы как constant-time [18].
- **[Факт]** `ml-kem`: «has never been independently audited! USE AT YOUR OWN RISK!» [18].
- **[Факт]** `x25519-dalek` 3.0.0: MSRV 1.85; `Zeroize` для секретов убран, обнуление только при drop; `StaticSecret` и `ReusableSecret` — за features [18]. Advisory RUSTSEC-2024-0344 для `curve25519-dalek` (timing) исправлен в 4.1.3 [2].
- **[Факт]** `zeroize` использует `core::ptr::write_volatile`, чтобы обнуление не было убрано оптимизатором [18]. `secrecy` 0.10.3: `SecretBox<T>`, доступ только через `ExposeSecret`, `#![forbid(unsafe_code)]`; последний релиз 2024-10-09 [1][18].
- **[Факт]** `blake3` предоставляет режимы `keyed_hash` и `derive_key` [18]. `ring` 0.17.14 не выпускался с 2025-03-11 [1].
- **[Вывод]** Не добавлять `blake3`, `ml-kem`, `ed25519-dalek` и `ring` в MVP без требования протокола: TLS-слой закрывается `aws-lc-rs`, Noise-слой (если будет) — набором RustCrypto, который тянет `snow`. Дублирование криптопровайдеров увеличивает поверхность и нарушает запрет дубликатов.
- **[Не проверено]** Аудит dalek-крейтов (Quarkslab, 2019) и аудит `subtle` — из памяти.

### 3.6 TUN и сеть в Linux

| Крейт | Версия, лицензия | Multi-queue | Offload (vnet_hdr) | Зависимости и замечания |
|---|---|---|---|---|
| `tokio-tun` | 1.0.0, MIT OR Apache-2.0, MSRV 1.88 | да (`TunBuilder::queues(n)`) | да: `recv`/`send` разбирают virtio-net header, GSO/checksum-метаданные | только `libc` и `tokio`; Unix-only; релиз 1.0.0 от 2026-11-08 [1][19] |
| `tun-rs` | 2.8.18, Apache-2.0 | да (Linux) | да: TSO/GSO на Linux | `libc`, `nix`, `route_manager`, опционально tokio/async-io; кроссплатформенный; цифры производительности (до 70,6 Gbps) — собственные замеры авторов [19] |
| `tun` (meh/rust-tun) | 0.8.14, WTFPL | не заявлено в README | не заявлено в README | используется Mullvad и GotaTun (feature `async`) [10][11][19] |

- **[Вывод]** Для MVP достаточно одного Linux-крейта с минимальными зависимостями: кандидат — `tokio-tun`; резерв — `tun-rs`. `tun` отклонён из-за лицензии WTFPL (не входит в типовой allow-list) и отсутствия заявленного offload. Риск `tokio-tun`: мажорный релиз трёхдневной давности, один сопровождающий; до фиксации нужен ревью кода (он мал) и собственный бенчмарк.
- **[Факт]** `rtnetlink` 0.24.0 управляет links, адресами и таблицами маршрутизации через netlink route protocol; Mullvad использует `rtnetlink` 0.23 и `netlink-packet-route` 0.33 [11][20]. **[Вывод]** Использовать `rtnetlink` вместо вызова `ip`: нет зависимости от наличия `iproute2` (в текущем контейнере `ip` отсутствует [3]), нет разбора текстового вывода, ошибки типизированы. Риск: API 0.x меняется между минорными версиями.
- **[Факт]** `wg-quick` для маршрута по умолчанию: fwmark (51820 или следующий свободный номер таблицы), `ip rule add not fwmark <t> table <t>`, `ip rule add table main suppress_prefixlength 0`, включение `net.ipv4.conf.all.src_valid_mark=1`, а также таблица nftables с цепочками `preraw` (drop пакетов на адрес туннеля не с интерфейса туннеля, `fib saddr type != local`) и `premangle`/`postmangle` (сохранение mark в conntrack для UDP); правила загружаются через `nft -f` [21].
- **[Вывод]** Kill switch MVP: policy routing с fwmark по схеме `wg-quick` плюс отдельная таблица `inet` в nftables с политикой drop для исходящего трафика вне туннеля (исключения: lo, сокет транспорта по mark, адрес сервера), отдельно для IPv4 и IPv6. Таблица должна переживать падение демона (ставится до подъёма туннеля, снимается только явной командой).
- **[Факт]** Крейт `nftables` 0.6.3 — типизированная обёртка над JSON API: запускает исполняемый файл `nft` (поиск в PATH) с аргументом `-j`, есть sync и async варианты; требует nftables >= 0.9.3 [20]. `nftnl` 0.9.4 — safe-обёртка над C-библиотекой `libnftnl`, используется в приложении Mullvad, покрывает не весь libnftnl; имел heap-buffer-overflow (RUSTSEC-2025-0126) [2][20]. `rustables` 0.9.0 — GPL-3.0-or-later [1].
- **[Вывод]** Для MVP: генерировать ruleset из фиксированного шаблона и применять атомарно через `nft -f -` с argv-списком и вводом через stdin (без shell); в правила попадают только проверенные числа, адреса и имена интерфейсов. Крейт `nftables` уместен, если понадобится читать состояние в JSON. `nftnl` отложить (FFI к C, advisory), `rustables` отклонить (GPL).
- **[Факт]** systemd-resolved: D-Bus интерфейс `org.freedesktop.resolve1` предоставляет `SetLinkDNS`, `SetLinkDomains`, `SetLinkDefaultRoute`, `SetLinkDNSOverTLS`, `SetLinkDNSSEC`, `RevertLink`; `resolvectl` даёт команды `dns`, `domain`, `default-route`; домен `~.` направляет DNS-трафик преимущественно на данный link; stub слушает 127.0.0.53/127.0.0.54; режим работы зависит от того, является ли `/etc/resolv.conf` symlink на `stub-resolv.conf` [22].
- **[Вывод]** DNS в MVP: при наличии resolved — `SetLinkDNS` + `SetLinkDomains("~.")` + `SetLinkDefaultRoute` на интерфейс туннеля, откат через `RevertLink`. Вызов `resolvectl` (argv) проще; `zbus` 6.2.1 (MSRV 1.89) добавляет заметное дерево зависимостей — решать после замера. Прямая перезапись `/etc/resolv.conf` рискованна: файл может быть symlink под управлением resolved/NetworkManager, изменения теряются при перезапуске сети, а при аварии демона остаётся нерабочий DNS. Независимо от механизма утечки DNS закрывает nftables: порт 53/853 разрешён только через туннель.

### 3.7 Конфигурация, CLI, логирование, метрики

- **[Факт]** `serde` 1.0.229, `toml` 1.2.1 (`#![forbid(unsafe_code)]`), `clap` 4.6.7 — MIT OR Apache-2.0, без записей в RustSec [1][2][27].
- **[Факт]** RUSTSEC-2026-0346: `Debug`-реализации клиентских сессий rustls раскрывали TLS-секреты [2]. **[Вывод]** Утечка через `Debug`/`Display` — реальный класс дефектов, а не теоретический.
- **[Вывод]** Правила исключения секретов из логов: (1) все секреты — только в `secrecy::SecretBox`/собственном newtype без `Display`, с `Debug`, печатающим `[REDACTED]`; (2) `serde::Serialize` для секретных типов не реализуется; (3) в `tracing` запрещены `?`/`%`-поля для структур конфигурации и handshake-состояния — логируются только явно перечисленные поля; (4) lint-запрет `dbg!` и `{:?}` на типах из крипто-модуля, проверка в CI; (5) тест, который прогоняет полный сценарий с известными ключами и ищет их байты в выводе логов. Гарантию даёт только сочетание типов и теста: `secrecy` не защищает от копий, сделанных после `expose_secret()`.
- **[Вывод]** Метрики: в MVP — счётчики в памяти через `metrics` 0.24.6 с выдачей по локальному Unix-сокету или в журнал; HTTP-экспортёр Prometheus отложить (лишний слушающий порт и зависимости). Метрики не содержат адресов клиентов и идентификаторов ключей.

### 3.8 Hardening сервиса

- **[Факт]** systemd.exec документирует `DynamicUser=`, `CapabilityBoundingSet=`, `AmbientCapabilities=`, `NoNewPrivileges=`, `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `PrivateDevices=`, `DeviceAllow=`, `RestrictAddressFamilies=`, `RestrictNamespaces=`, `SystemCallFilter=`, `MemoryDenyWriteExecute=`, `LockPersonality=`, `ProtectKernelTunables=`, `StateDirectory=`, `LoadCredential=`, `LoadCredentialEncrypted=` [22].
- **[Факт]** Credentials передаются сервису через каталог `$CREDENTIALS_DIRECTORY`; `LoadCredential=имя:путь` загружает файл с диска, `LoadCredentialEncrypted=` — зашифрованный вариант [22].
- **[Вывод]** Набросок unit (проверить `systemd-analyze security` на целевой системе): `DynamicUser=yes`, `AmbientCapabilities=CAP_NET_ADMIN`, `CapabilityBoundingSet=CAP_NET_ADMIN`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `DeviceAllow=/dev/net/tun rw` (вместо `PrivateDevices=yes`, который скрывает `/dev/net/tun`), `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `LoadCredential=` для приватного ключа, `Type=notify` (`sd-notify` 0.5.0).
- **[Предположение]** Сочетание `DynamicUser=yes` с доступом к `/dev/net/tun` и netlink требует проверки на реальном systemd; в контейнере PID 1 не systemd, проверить нельзя [3].
- **[Вывод]** Privilege separation: `CAP_NET_ADMIN` нужен для создания TUN, маршрутов и nftables. Вариант A (проще, MVP): один процесс с единственной capability и sandbox. Вариант B: привилегированный helper создаёт TUN, правила и передаёт fd по Unix-сокету непривилегированному процессу с криптографией и сетевым парсингом. Вариант B уменьшает ущерб от компрометации парсера; выбор — за архитектором.

### 3.9 Качество и supply chain

- **[Факт]** Актуальные версии инструментов: cargo-deny 0.20.2, cargo-audit 0.23.0, cargo-vet 0.10.3, cargo-fuzz 0.13.2 (libfuzzer-sys 0.4.13), proptest 1.12.0, loom 0.7.3, criterion 0.8.2, cargo-nextest 0.9.151, cargo-auditable 0.7.7 [1].
- **[Факт]** cargo-deny: секции `[advisories]` (`version = 2`, `yanked`, `unmaintained`, `ignore`), `[licenses]` (`allow`, `exceptions`, `confidence-threshold`, `clarify`), `[bans]` (`multiple-versions`, `wildcards`, `deny`, `skip`, `skip-tree`), `[sources]` (`unknown-registry`, `unknown-git`, `allow-registry`) [23].
- **[Вывод]** Обязательный CI-набор MVP: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo nextest run`, `cargo deny check`, `cargo audit` (дублирует advisories, но быстрее обновляется), сборка с `--locked`. Фаззинг (`cargo-fuzz`) — для парсеров пакетов, handshake и конфигурации с первого дня; `proptest` — для кодеков и anti-replay окна; `loom` — только для собственных lock-free структур; `miri` — для модулей с `unsafe` (не исполняет FFI, поэтому `aws-lc-rs` и ioctl TUN останутся вне покрытия); ASan/TSan — на nightly для интеграционных тестов.
- **[Вывод]** `cargo-vet`: вести с этапа 2, импортируя публичные аудит-наборы; для MVP обязателен хотя бы ручной ревью крейтов с одним сопровождающим (`tokio-tun`, `snow`, `secrecy`).
- **[Вывод]** Обновления: Renovate или Dependabot с группировкой security-обновлений; `Cargo.lock` в репозитории; точные версии (`=x.y.z`) для `quinn-proto`, `rustls`, `aws-lc-rs`, TUN-крейта. **[Не проверено]** Детали текущих возможностей Dependabot/Renovate для Cargo.
- **[Вывод]** Подпись релизов и обновлений конфигурации: Ed25519-подпись в формате minisign, проверка в клиенте крейтом `minisign-verify` 0.3.0 (MIT) с публичным ключом, вшитым в бинарник; у конфигурации — монотонный номер версии и срок действия против отката. `sigstore` 0.15.0 тянет крупное дерево зависимостей и сетевые обращения — уместен только для CI-аттестаций, не в клиенте.

### 3.10 Тестовая инфраструктура без реальной сети

- **[Вывод]** Схема: два или три network namespace (client, server, опционально router) + veth-пары; в namespace клиента поднимается TUN, маршруты и nftables; потери, задержка, reorder и ограничение скорости — `tc qdisc ... netem` на veth [24]; изменение MTU — на veth в router-namespace. Проверка утечек: в client-namespace слушатель на «физическом» veth фиксирует любой пакет DNS (53/853) и любой IPv6-пакет вне туннеля при поднятом kill switch, в том числе после принудительного завершения демона.
- **[Факт]** Требуется root или `CAP_NET_ADMIN` (+ `CAP_SYS_ADMIN` для создания namespace без user namespace); `unshare` поддерживает `--net`, `--user`, `--map-root-user` [3].

Проверка текущего контейнера (только чтение, 2026-11-10 и повторно 2026-11-11) [3]:

| Возможность | Состояние |
|---|---|
| Пользователь и capabilities | `uid=0`, `CapEff=000001fffeffffff` (есть `cap_net_admin`, `cap_sys_admin`, `cap_net_raw`), seccomp выключен |
| `/dev/net/tun` | есть (`crw------- root root 10,200`), `CONFIG_TUN=y` |
| Namespaces | `CONFIG_NET_NS=y`, `CONFIG_USER_NS=y`; `unshare`/`nsenter` (util-linux 2.39.3) есть |
| veth, policy routing | `CONFIG_VETH=y`, `CONFIG_IP_MULTIPLE_TABLES=y`, `CONFIG_IPV6=y` |
| nftables | `nft` v1.0.9; `CONFIG_NF_TABLES=y`, `NF_TABLES_INET`, `NFT_CT`, `NFT_FIB`, `NFT_NAT`, `NFT_MASQ` |
| netem | **нет**: `# CONFIG_NET_SCH_NETEM is not set` (при этом `CONFIG_NET_SCHED=y`, `CONFIG_IFB=y`) |
| WireGuard в ядре | нет: `# CONFIG_WIREGUARD is not set` |
| io_uring | `CONFIG_IO_URING=y` |
| Утилиты | нет `ip`, `tc`, `resolvectl`, `wg`, `tcpdump`, `ping`, `dig`, `ss`, `ethtool`, `iperf3`; есть `iptables`, `systemctl`, `systemd-analyze` (systemd 255), `busctl`, `capsh`, `setpriv` |
| systemd | PID 1 — `process_api`, не systemd: unit-файлы и resolved проверить нельзя |

- **[Вывод]** В контейнере выполнимы: создание netns/veth/TUN и маршрутов из тестового кода через netlink (`rtnetlink`), применение nftables через `nft`, проверка kill switch и утечек IPv6/DNS собственным слушателем. Невыполнимы: `tc netem` (нет модуля в ядре и нет `tc`), сценарии systemd sandbox и systemd-resolved. Сами операции создания namespace **не запускались** (задание разрешало только чтение), поэтому работоспособность — **[Предположение]** по конфигурации ядра и capabilities.
- **[Вывод]** Замена netem в этой среде — userspace-эмулятор канала: тестовый UDP-ретранслятор между двумя namespace, вносящий потери, задержку и обрезку по MTU. Он детерминирован (seed) и полезен в CI независимо от ядра; netem оставить для стенда с полноценным ядром.

## 4. Рекомендуемый стек MVP

Версии — актуальные стабильные на 2026-11-10 [1]; фиксируются в `Cargo.lock`, для критичных крейтов — точным требованием `=x.y.z`.

| Компонент | Крейт | Версия | Лицензия | Обоснование | Риск |
|---|---|---|---|---|---|
| Async runtime | `tokio` | 1.54.1 | MIT | work-stealing планировщик, `AsyncFd` для TUN, рантайм quinn по умолчанию [4][25] | unsound в `AsyncFd` и race в `Interval` исправлены только в 2026-10 [2]; не опускаться ниже 1.54.1 |
| QUIC | `quinn` / `quinn-proto` / `quinn-udp` | 0.11.12 / 0.11.19 / 0.6.3 | MIT OR Apache-2.0 | датаграммы, MTU discovery, GSO/GRO, Cubic/NewReno/BBR, подключаемая криптография; используется Mullvad [4][11] | 8 advisories в 2026 г., аудита нет [2][26]; 0-RTT и RFC 9221 не подтверждены |
| TLS | `rustls` | 0.23.46 | Apache-2.0 OR ISC OR MIT | `forbid(unsafe_code)`, TLS 1.3, X25519MLKEM768, RPK, ECH-клиент [5] | 5 advisories в 2026 г.; аудит 2020 г. [2][7]; предстоит миграция на 0.24 |
| Криптопровайдер | `aws-lc-rs` | 1.19.0 | ISC AND (Apache-2.0 OR ISC) | провайдер rustls по умолчанию, единственный с X25519MLKEM768 [5][17] | C/asm под FFI; advisories в `aws-lc-sys` [2]; сборка требует C-компилятор |
| TCP/TLS fallback | `tokio-rustls` | 0.26.6 | MIT OR Apache-2.0 | тот же TLS-стек и провайдер, что у QUIC [1] | head-of-line blocking — свойство TCP, не крейта |
| Проверка сертификатов | закреплённый ключ/собственный CA через `rustls-webpki` | 0.103.16 | ISC | для частной сети системное хранилище не нужно | 5 advisories в 2026 г., исправлены [2] |
| TUN | `tokio-tun` | 1.0.0 | MIT OR Apache-2.0 | только `libc` + `tokio`, multi-queue, vnet_hdr offload [19] | релиз от 2026-11-08, один сопровождающий; резерв — `tun-rs` 2.8.18 |
| Маршруты и правила | `rtnetlink` (+ `netlink-packet-route`) | 0.24.0 (0.34.0) | MIT | netlink без вызова `ip`; используется Mullvad [11][20] | нестабильный API 0.x |
| Firewall / kill switch | вызов `nft -f -` (argv, stdin) | системный nftables >= 1.0 | — | атомарная загрузка, без новых зависимостей; схема как в `wg-quick` [21] | зависимость от бинарника `nft`; нужен строгий шаблон правил |
| DNS | `resolvectl` (argv) или D-Bus `org.freedesktop.resolve1` | системный systemd | — | `SetLinkDNS`/`SetLinkDomains`/`RevertLink` [22] | системы без resolved; не проверено в контейнере |
| Конфигурация | `serde` + `toml` | 1.0.229 + 1.2.1 | MIT OR Apache-2.0 | стандарт экосистемы, `toml` без unsafe [27] | proc-macro `serde_derive` в цепочке сборки |
| CLI | `clap` | 4.6.7 | MIT OR Apache-2.0 | derive-API, проверка аргументов [1] | размер дерева зависимостей; допустим `default-features = false` |
| Логи | `tracing` + `tracing-subscriber` | 0.1.44 + 0.3.23 | MIT | структурные поля, фильтрация уровней [1] | утечка секретов через поля — закрывается типами и тестом (3.7) |
| Секреты в памяти | `zeroize` + `secrecy` | 1.9.1 + 0.10.3 | Apache-2.0 OR MIT | обнуление через `write_volatile`, редактирование `Debug` [18] | `secrecy` без релизов с 2024-10; не защищает от копий |
| Сравнение секретов | `subtle` | 2.6.1 | BSD-3-Clause | constant-time сравнение [1] | без релизов с 2024-06; аудит не подтверждён |
| Случайность | `getrandom` (через `aws-lc-rs`/`rand_core`) | 0.4.3 | MIT OR Apache-2.0 | системный CSPRNG [1] | отдельный `rand` не нужен |
| Метрики | `metrics` | 0.24.6 | MIT | фасад без сетевого экспортёра [1] | можно исключить из MVP |
| systemd-интеграция | `sd-notify` | 0.5.0 | MIT OR Apache-2.0 | `Type=notify`, watchdog [1] | минимальный |
| Проверка подписи обновлений | `minisign-verify` | 0.3.0 | MIT | только проверка, малый объём [1] | один сопровождающий; кода не читали |
| Внутренний туннельный протокол (опция) | `gotatun` или `snow` | 0.10.3 / 0.10.0 | MPL-2.0 / Apache-2.0 OR MIT | `gotatun` аудирован в 2026 г.; `snow` — Noise rev. 34 [8][10] | `snow` без аудита; `gotatun` — MPL-2.0 и MSRV 1.95; нужно решение архитектора |
| Тесты и качество (dev) | `proptest`, `cargo-fuzz`, `loom`, `criterion`, `cargo-nextest`, `cargo-deny`, `cargo-audit` | см. раздел 1 | MIT / Apache-2.0 | см. 3.9 | не попадают в релизный бинарник |

**[Вывод]** Целевой MSRV проекта: 1.88 (без `gotatun`) или 1.95 (с ним); toolchain фиксируется файлом `rust-toolchain.toml` на 1.97.0.

## 5. Отвергнутые альтернативы

| Альтернатива | Причина отказа |
|---|---|
| Go (wireguard-go, quic-go), C | GC и runtime либо ручное управление памятью в парсерах недоверенного ввода; практика Mullvad — переход на Rust [10][11]. Количественные данные **[Не проверено]** |
| `s2n-quic` 1.91.0 | качественная реализация, но MSRV 1.95 со скользящей политикой, второй TLS-стек (s2n-tls) в экосистеме, меньше внешних пользователей (850 тыс. загрузок против 410 млн у quinn) [1][13]; оставить как запасной вариант |
| `quiche` / `tokio-quiche` | более низкоуровневый API, C API и собственная цепочка TLS; релизы 0.30.1/0.23.0 вышли 2026-11-10 — слишком свежие для фиксации [1][14]; вернуться к оценке, если понадобится MASQUE CONNECT-IP |
| `noq`, `iroh-quinn` | форки quinn под задачи iroh (multipath, NAT traversal) [16]; для MVP лишний риск расхождения с upstream |
| `neqo` | ориентирован на Firefox, TLS через NSS, нет на crates.io под именем `neqo-transport` [1][16] |
| `msquic` | C-библиотека, Rust-обвязка в статусе beta [1][16] |
| `h3` + `h3-datagram` (MASQUE) в MVP | «still very experimental», версии 0.0.x, релизов с 2025-05 нет [1][15]; MASQUE — кандидат на этап после MVP |
| `ring` как провайдер | нет X25519MLKEM768, релизов с 2025-03 нет [1][5][6] |
| `rustls` 0.24.0-dev | предрелиз [1] |
| `rustls-platform-verifier` | системное хранилище CA не нужно при закреплённом ключе сервера |
| `boringtun` | README: реструктуризация; активная линия развития — форк `gotatun` [9][10] |
| `wireguard-rs` | на crates.io заглушка под AGPL [1] |
| `ml-kem`, `libcrux-ml-kem`, `x-wing` напрямую | `ml-kem` без аудита [18]; гибридный обмен уже даёт rustls + aws-lc-rs |
| `blake3`, `ed25519-dalek`, отдельный `chacha20poly1305` | нет технической необходимости в MVP при TLS-слое на aws-lc-rs |
| `tun` (meh) | лицензия WTFPL, offload не заявлен [1][19] |
| `rustables` | GPL-3.0-or-later [1] |
| `nftnl` | FFI к `libnftnl`, heap-buffer-overflow в 2025 г. [2][20] |
| Вызов `ip` через процесс | разбор текста, зависимость от `iproute2` (в контейнере отсутствует) [3] |
| `tokio-uring`, `monoio`, `glommio` | нет релизов с 2024 г. [1]; quinn их не поддерживает [4] |
| `zbus` в MVP | MSRV 1.89 и крупное дерево зависимостей ради трёх вызовов [1] |
| `sigstore` в клиенте | объём зависимостей и сетевые обращения [1] |
| `metrics-exporter-prometheus`, `prometheus` | лишний слушающий порт в MVP |

## 6. Политика зависимостей

1. Новая зависимость добавляется только с записью: зачем, чем нельзя заменить, лицензия, дата последнего релиза, число сопровождающих, advisories, наличие `unsafe`/FFI.
2. `Cargo.lock` хранится в репозитории; сборка и CI — только с `--locked`. Критичные крейты (`quinn-proto`, `rustls`, `aws-lc-rs`, `rustls-webpki`, TUN-крейт) — точные версии.
3. Источник — только crates.io; git-зависимости и сторонние registry запрещены.
4. `default-features = false` для всех прямых зависимостей с явным списком features (с учётом `prefer-post-quantum`, см. 3.3).
5. Один криптопровайдер и один TLS-стек; `ring` допускается только как транзитивная зависимость с записью в `skip` и обоснованием.
6. Advisory с исправлением — обновление в течение 72 часов; без исправления — запись в `ignore` с причиной и датой пересмотра.
7. Крейты с одним сопровождающим или младше 30 дней от релиза фиксируемой версии — ручной ревью diff перед обновлением.

Предлагаемый `deny.toml` (схема cargo-deny 0.20 [23]; **не запускался** — Cargo-проекта нет, перед применением проверить `cargo deny check`):

```toml
[graph]
targets = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
all-features = true

[advisories]
version = 2
yanked = "deny"
unmaintained = "all"
ignore = []            # каждая запись: id + reason + дата пересмотра

[licenses]
version = 2
confidence-threshold = 0.93
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "ISC",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "Unicode-3.0",
]
# MPL-2.0 — только адресным исключением, если будет принят gotatun:
exceptions = []        # { allow = ["MPL-2.0"], crate = "gotatun" }

[bans]
multiple-versions = "deny"
wildcards = "deny"
highlight = "all"
deny = [
    { crate = "openssl-sys", reason = "единственный криптопровайдер — aws-lc-rs" },
    { crate = "native-tls",  reason = "единственный TLS-стек — rustls" },
    { crate = "rustables",   reason = "GPL-3.0-or-later" },
]
skip = []              # дубликаты версий — только с обоснованием

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

**[Предположение]** `Unicode-3.0` понадобится транзитивным зависимостям; `multiple-versions = "deny"` на практике потребует нескольких записей `skip` — уточнить по реальному графу. Набор лицензий `aws-lc-sys` шире (включает MIT-0 в OR-выражении) [1], возможно понадобится `clarify`.

## 7. Не удалось проверить

1. **Публикации о Rust против Go/C** — блоги Cloudflare (BoringTun, WARP/MASQUE, tokio-quiche), Mullvad (анонс GotaTun) и Google Security Blog недоступны из сессии (хосты вне списка разрешённых). Конкретные цифры (доля memory-safety уязвимостей, статистика сбоев wireguard-go) в документ не включены.
2. **quinn:** поддержка 0-RTT, точное соответствие RFC 9221, статус BBR (экспериментальный или нет), проходит ли `prefer-post-quantum` через feature `rustls-aws-lc-rs` — нужна проверка по docs.rs и `Cargo.toml` рабочего пространства quinn. README quinn указывает MSRV 1.80, crates.io — 1.85; принят crates.io.
3. **Аудиты:** свежие (после 2020 г.) аудиты rustls; аудиты s2n-quic, quiche, aws-lc-rs (в т. ч. статус FIPS 140-3 и формальной верификации AWS-LC); аудиты dalek-крейтов и `subtle`; содержание отчёта Cure53 (PDF не открывался, подтверждено только его наличие и описание в поиске).
4. **Активность репозиториев** (дата последнего коммита, число открытых issue, число сопровождающих) — GitHub API для сторонних репозиториев в сессии закрыт; активность оценена только по датам релизов на crates.io.
5. **Unsafe-поверхность количественно** (`cargo-geiger`) — не измерялась: Cargo-проект не создавался. Проверено только наличие `forbid(unsafe_code)` у `rustls`, `secrecy`, `toml`; у `snow`, `quinn`, `quinn-proto`, `h3`, `tokio-rustls`, `rtnetlink` такого атрибута в `lib.rs` не найдено.
6. **wireguard-rs** (официальный репозиторий), **wg-quick** на git.zx2c4.com — хост недоступен; `wg-quick` прочитан по зеркалу на GitHub.
7. **Использование библиотек в WARP** (quiche, MASQUE CONNECT-IP) и поддержка CONNECT-UDP/CONNECT-IP в `quiche::h3`/`tokio-quiche` — не подтверждено.
8. **Контейнер:** фактическое создание netns/veth/TUN и загрузка nftables не выполнялись (только чтение); systemd sandbox и resolved не проверяемы (PID 1 не systemd).
9. **Сайт rustsec.org** напрямую не открывался; advisories прочитаны из официального git-репозитория базы.
10. **`deny.toml`** и набросок unit-файла не запускались.

## 8. Открытые вопросы к архитектору

1. Внутренний протокол: только TLS 1.3 внутри QUIC (без второго слоя), WireGuard-совместимый слой (`gotatun`) или собственный Noise (`snow`)? От этого зависят MSRV, лицензии и объём аудита.
2. Допустима ли MPL-2.0 в зависимостях?
3. Нужен ли MASQUE (CONNECT-UDP/CONNECT-IP) в MVP или достаточно QUIC DATAGRAM с собственным фреймингом?
4. Аутентификация сервера: закреплённый raw public key (RFC 7250) или собственный CA?
5. Privilege separation: один процесс с `CAP_NET_ADMIN` или helper с передачей fd?
6. Целевые дистрибутивы и минимальные версии systemd/nftables/ядра (влияет на DNS-интеграцию и offload).

## Источники

1. https://crates.io/api/v1/crates/{имя} — метаданные crates.io (версия, дата, лицензия, rust-version, загрузки) для каждого упомянутого крейта; проверено 2026-11-10.
2. https://github.com/rustsec/advisory-db — база RustSec, клон на коммите 28d73fc95e5972af3403225a217def57dcaba3c4 от 2026-11-10, каталоги `crates/<имя>/`; проверено 2026-11-10.
3. Локальные команды на чтение в контейнере (`id`, `capsh --print`, `/proc/self/status`, `ls -l /dev/net/tun`, `command -v`, `nft --version`, `unshare --help`, `systemd-analyze --version`, `zcat /proc/config.gz`, `/proc/1/comm`); выполнено 2026-11-10 и 2026-11-11.
4. https://raw.githubusercontent.com/quinn-rs/quinn/main/ — `README.md`, `quinn-proto/Cargo.toml`, `quinn-proto/src/config/transport.rs`, `quinn-proto/src/config/mod.rs`, `quinn-proto/src/congestion.rs`, `quinn-proto/src/connection/datagrams.rs`, `quinn-proto/src/connection/mtud.rs`, `quinn-udp/src/lib.rs`, `quinn/src/lib.rs`; проверено 2026-11-11.
5. https://raw.githubusercontent.com/rustls/rustls/rel-0.23/ — `README.md`, `rustls/Cargo.toml`, `rustls/src/lib.rs`, `rustls/src/manual/features.rs`, `rustls/src/manual/defaults.rs`; проверено 2026-11-11.
6. https://raw.githubusercontent.com/rustls/rustls/main/ — `README.md` (провайдеры с 0.24), `SECURITY.md` (политика поддержки и MSRV), `audit/TLS-01-report.pdf` (наличие файла, HTTP 200); проверено 2026-11-11.
7. https://cure53.de/pentest-report_rustls.pdf и https://jbp.io/2020/06/14/rustls-audit/ — аудит rustls/ring/webpki, Cure53, 2020 (по выдаче поиска, сами страницы не открывались); проверено 2026-11-11.
8. https://raw.githubusercontent.com/mcginty/snow/main/ — `README.md`, `Cargo.toml`, `SECURITY.md`; проверено 2026-11-11.
9. https://raw.githubusercontent.com/cloudflare/boringtun/master/README.md — статус и назначение BoringTun; проверено 2026-11-11.
10. https://raw.githubusercontent.com/mullvad/gotatun/main/ — `README.md`, `gotatun/Cargo.toml`, `audits/README.md`, `audits/2026-02-17-Assured.md`; проверено 2026-11-11.
11. https://raw.githubusercontent.com/mullvad/mullvadvpn-app/main/ — `Cargo.toml` (workspace), `mullvad-masque-proxy/Cargo.toml`, `audits/README.md`; проверено 2026-11-11.
12. https://mullvad.net/en/blog/introducing-quic-obfuscation-for-wireguard — QUIC-обфускация Mullvad на MASQUE (по выдаче поиска, страница не открывалась); проверено 2026-11-11.
13. https://raw.githubusercontent.com/aws/s2n-quic/main/README.md — возможности и MSRV s2n-quic; проверено 2026-11-11.
14. https://raw.githubusercontent.com/cloudflare/quiche/master/ — `README.md`, `tokio-quiche/README.md`; проверено 2026-11-11.
15. https://raw.githubusercontent.com/hyperium/h3/master/ — `README.md`, `h3-datagram/Cargo.toml`; проверено 2026-11-11.
16. README: https://raw.githubusercontent.com/n0-computer/noq/main/README.md , https://raw.githubusercontent.com/mozilla/neqo/main/README.md , https://raw.githubusercontent.com/microsoft/msquic/main/README.md ; проверено 2026-11-11.
17. https://raw.githubusercontent.com/aws/aws-lc-rs/main/aws-lc-rs/README.md и https://raw.githubusercontent.com/briansmith/ring/main/README.md ; проверено 2026-11-11.
18. README RustCrypto и смежных крейтов: https://raw.githubusercontent.com/RustCrypto/AEADs/master/chacha20poly1305/README.md , `.../AEADs/master/aes-gcm/README.md`, https://raw.githubusercontent.com/RustCrypto/KEMs/master/ml-kem/README.md , https://raw.githubusercontent.com/RustCrypto/utils/master/zeroize/README.md , https://raw.githubusercontent.com/dalek-cryptography/curve25519-dalek/main/x25519-dalek/README.md , https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/master/README.md , https://raw.githubusercontent.com/iqlusioninc/crates/main/secrecy/README.md (и `secrecy/src/lib.rs`); проверено 2026-11-11.
19. TUN-крейты: https://raw.githubusercontent.com/yaa110/tokio-tun/master/README.md (и `Cargo.toml`), https://raw.githubusercontent.com/tun-rs/tun-rs/main/README.md (и `Cargo.toml`), https://raw.githubusercontent.com/meh/rust-tun/master/README.md ; проверено 2026-11-11.
20. https://raw.githubusercontent.com/rust-netlink/rtnetlink/main/README.md , https://raw.githubusercontent.com/nftables-rs/nftables-rs/main/README.md (и `src/helper.rs`), https://raw.githubusercontent.com/mullvad/nftnl-rs/main/README.md ; проверено 2026-11-11.
21. https://raw.githubusercontent.com/WireGuard/wireguard-tools/master/src/wg-quick/linux.bash — `wg-quick` для Linux (зеркало на GitHub); проверено 2026-11-11.
22. https://raw.githubusercontent.com/systemd/systemd/main/ — `man/systemd.exec.xml`, `docs/CREDENTIALS.md`, `man/org.freedesktop.resolve1.xml`, `man/resolvectl.xml`, `man/systemd-resolved.service.xml`; проверено 2026-11-11.
23. https://raw.githubusercontent.com/EmbarkStudios/cargo-deny/main/ — `deny.template.toml`, `docs/src/checks/advisories/cfg.md`, `docs/src/checks/licenses/cfg.md`, `docs/src/checks/bans/cfg.md`; проверено 2026-11-11.
24. https://raw.githubusercontent.com/iproute2/iproute2/main/man/man8/tc-netem.8 — man-страница netem (delay, loss, corrupt, duplication, reordering, rate); проверено 2026-11-11.
25. https://raw.githubusercontent.com/tokio-rs/tokio/master/tokio/src/runtime/mod.rs — документация планировщиков tokio; проверено 2026-11-11.
26. Поиск «quinn QUIC independent security audit» — в выдаче только CVE/advisories (например https://osv.dev/vulnerability/CVE-2026-31812 ), упоминаний аудита нет; проверено 2026-11-11.
27. https://raw.githubusercontent.com/toml-rs/toml/main/crates/toml/src/lib.rs — атрибут `#![forbid(unsafe_code)]`; проверено 2026-11-11.
