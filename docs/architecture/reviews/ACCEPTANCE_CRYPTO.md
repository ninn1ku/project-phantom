# Архитектурная приёмка: криптография (фаза 0)

**Дата:** 2026-11-14. **Исполнитель:** независимый криптограф (не автор решений CRYPTO_PROFILE, ADR-0003…0005, 0011,
0013, SYSTEM §1.8). **Статус:** ЧЕРНОВИК, дополняется по ходу работы.
**Метод:** чтение нормативных документов проекта; сверка с исходниками текущих версий крейтов, скачанных с crates.io в
scratch-каталог; база RustSec; первичные тексты RFC. Кода проекта нет; ничего из профиля не собиралось и не запускалось.
Эксперименты фазы 1 не проводились.

Метки: [Факт: источник] — источник прочитан; [Вывод]; [Предположение]; [Не проверено].

## 0. Вердикт

(заполняется)

## 1. Версии и advisories

Проверка 2026-11-14, источник — crates.io API `https://crates.io/api/v1/crates/<name>` (поля `max_stable_version`,
`max_version`, `updated_at`).

| Крейт | Стабильная | Предварительная | Обновлён | Нижняя граница handoff §4.1 | Оценка |
|---|---|---|---|---|---|
| `rustls` | 0.23.46 | 0.24.0-dev.3 | 2026-11-12 | ≥ 0.23.46 | (заполняется) |
| `rustls-webpki` | 0.103.17 | 0.104.0-alpha.8 | 2026-11-12 | ≥ 0.103.16 | (заполняется) |
| `quinn` | 0.11.12 | — | 2026-09-14 | нет | (заполняется) |
| `quinn-proto` | 0.11.19 | — | 2026-09-30 | ≥ 0.11.18 | (заполняется) |
| `quinn-udp` | 0.6.3 | — | 2026-09-30 | нет | (заполняется) |
| `aws-lc-rs` | 1.19.0 | — | 2026-10-28 | нет | (заполняется) |
| `aws-lc-sys` | 0.47.0 | — | 2026-10-28 | ≥ 0.39 | (заполняется) |
| `tokio` | 1.54.1 | — | 2026-10-21 | ≥ 1.53.3 | (заполняется) |
| `tokio-rustls` | 0.26.6 | — | 2026-09-28 | нет | (заполняется) |
| `rustls-pki-types` | 1.16.0 | — | 2026-11-10 | нет | (заполняется) |
| `rcgen` | 0.14.10 | — | 2026-08-28 | не нужен при RPK | (заполняется) |
| `ring` | 0.17.14 | — | 2025-03-11 | не в профиле | — |

[Факт: crates.io API] Стабильная ветка `rustls` — 0.23.x, последняя 0.23.46; 0.24 существует только как
предварительные выпуски `0.24.0-dev.N`; `cargo info rustls` показывает 0.24.0-dev.3, потому что это `max_version`.

### 1.1. Advisories RustSec 2025–2026

Источник: клон `https://github.com/rustsec/advisory-db`, последний коммит 4ef2df8e (2026-11-13), каталоги `crates/<имя>/`.
Прочитаны файлы целиком для новых записей; для остальных — поля `patched` и заголовок.

| Advisory | Крейт | Суть | Исправлено | Значение | Есть в CRYPTO_PROFILE §2.7 |
|---|---|---|---|---|---|
| 2026-0285 | rustls | Сообщения рукопожатия через границу уровня шифрования | ≥ 0.23.45 | Закрыто 0.23.46 | да |
| 2026-0346…0349 | rustls | `Debug` секретов; ECH; brotli 1 ГиБ; понижение до X25519 | ≥ 0.23.46 | Закрыто 0.23.46 | да |
| 2026-0049, -0098, -0099, -0104 | rustls-webpki | CRL, name constraints, panic CRL | ≥ 0.103.10…0.103.13 | Путь X.509 не используется | да |
| 2026-0382 | rustls-webpki | Принятие недоверенных промежуточных | ≥ 0.103.16 | Путь X.509 не используется; граница верна | да |
| 2026-0044…0048 | aws-lc-sys | X.509, PKCS7, CRL, тайминг AES-CCM | ≥ 0.38/0.39 | Закрыто 0.47.0 | да |
| 2026-0037, -0185, -0338…-0343 | quinn-proto | Panic и исчерпание памяти | ≥ 0.11.14…0.11.18 | Закрыто 0.11.18+ | да |
| **2026-0523** | quinn-proto | `MAX_STREAM_DATA` открывает потоки сверх лимита → >2^40 потоков у `accept_bi`, OOM/зависание; после рукопожатия | **≥ 0.11.19** | Применимо: T1 принимает один двунаправленный поток (TS §5.2). Аутентифицированный пир (украденный ключ, RR9) роняет сервер | **нет** |
| **2026-0524** | quinn-proto | Длинный Retry-токен: panic (debug) / аллокация > 10 ГиБ и abort (release) у **клиента**; Retry строится по первому Initial, атакующий — любой, кто видит Initial и отвечает раньше сервера | **≥ 0.11.19** | Применимо к клиенту PHANTOM: внешний атакующий на пути (T2/T4) роняет клиент до аутентификации | **нет** |
| **2026-0538** | quinn-udp | Зацикливание приёма после усечённой датаграммы | ≥ 0.6.3 | Linux, Windows не затронуты (по тексту advisory); закрепить версию | **нет** |
| **2026-0384** | tokio | Гонка/UAF в `time::Interval` на многопоточном runtime; 1.54.0 отозвана (yanked) | ≥ 1.54.1 (затронута только 1.54.0) | Применимо: таймер CP-20 и keepalive естественно строятся на `Interval`. Граница «≥ 1.53.3» допускает 1.54.0 | **нет** |
| **2026-0386** | tokio | `AsyncFd::new` нарушает I/O safety (informational: unsound) | ≥ 1.53.3 (конструкторы объявлены deprecated) | Применимо к TUN fd на Linux (обёртки TUN используют `AsyncFd`); граница верна, но обёртка TUN должна перейти на `AsyncFd::register` | **нет** |
| 2025-0023 | tokio | `broadcast` без `Sync` (unsound) | ≥ 1.44.2 | Закрыто | — |
| 2025-0007, -0009, -0010 | ring | unmaintained (отозвано), panic AES | — | `ring` не в профиле | да |

Advisories на `aws-lc-rs`, `quinn`, `tokio-rustls`, `rustls-pki-types`, `rcgen` за 2025–2026 нет [Факт: клон RustSec].
`rustls-webpki` 0.103.17 вышел 2026-11-12, advisory к нему в базе на 2026-11-13 нет; причина выпуска не выяснена
[Не проверено].

### 1.2. Нижние границы handoff §4.1

| Крейт | В handoff | Верно? | Предлагается | Причина |
|---|---|---|---|---|
| `rustls` | ≥ 0.23.46 | верно и достаточно | ≥ 0.23.46, `< 0.24` | 0.24 — только dev-выпуски |
| `rustls-webpki` | ≥ 0.103.16 | верно | ≥ 0.103.17 (текущая) | -0382; 0.103.17 — текущая, причина выпуска не выяснена |
| `quinn-proto` | ≥ 0.11.18 | **недостаточно** | **≥ 0.11.19** | RUSTSEC-2026-0523, -0524 |
| `quinn` | нет | неполно | ≥ 0.11.12 | тянет `quinn-proto` 0.11.19 только через `Cargo.lock` |
| `quinn-udp` | нет | неполно | ≥ 0.6.3 | RUSTSEC-2026-0538 |
| `aws-lc-sys` | ≥ 0.39 | верно | ≥ 0.47.0 (через `aws-lc-rs` 1.19.0) | -0044…0048; брать то, что тянет текущий `aws-lc-rs` |
| `tokio` | ≥ 1.53.3 | **неточно** | ≥ 1.54.1 (или 1.53.3 с запретом 1.54.0 в `cargo-deny`) | RUSTSEC-2026-0384; 1.54.x требует MSRV 1.85 |

## 2. Сверка профиля с исходниками

Исходники скачаны с `static.crates.io` 2026-11-14 и распакованы в
`/tmp/claude-0/-home-user-project-phantom/b2d0bc50-bfb1-5f87-b9e8-22543bc314ba/scratchpad/crypto/src/` (далее `$S`):
`rustls-0.23.46`, `rustls-0.24.0-dev.3`, `quinn-0.11.12`, `quinn-proto-0.11.19`, `aws-lc-rs-1.19.0`, `aws-lc-sys-0.47.0`
(включает исходник AWS-LC), `rustls-webpki-0.103.17`, `tokio-rustls-0.26.6`. Каталог `$REG/rustls-0.23.46`, на который
ссылается CRYPTO_PROFILE, в текущей среде отсутствует (в реестре только `rustls-0.24.0-dev.3`), поэтому всё
перечитано заново.

Значения столбца «Итог»: **подтверждено** (исходник прочитан, утверждение верно), **уточнено** (верно частично или
неполно), **опровергнуто**, **только экспериментом** (исходник не даёт ответа или нужен запуск).

| # | Утверждение профиля | Итог | Источник и комментарий |
|---|---|---|---|
| 2.1 | Константа группы — `aws_lc_rs::kx_group::X25519MLKEM768`, длины 1184/1088, ML-KEM первым | подтверждено | [Факт: `$S/rustls-0.23.46/src/crypto/aws_lc_rs/pq/mod.rs` стр. 14–25; `mod.rs` модуль `kx_group`]. Модуль `pq` компилируется без условий (`mod.rs` стр. 24) |
| 2.2 | `prefer-post-quantum` на профиль не влияет | подтверждено | [Факт: `Cargo.toml` `prefer-post-quantum = ["aws_lc_rs"]`; `mod.rs` стр. 254–278] — feature меняет только порядок в `DEFAULT_KX_GROUPS`/`ALL_KX_GROUPS`; при собственном `kx_groups = vec![X25519MLKEM768]` не используется. В `default` входит `prefer-post-quantum` и `tls12`, поэтому `default-features = false` обязателен |
| 2.3 | Провайдер с одной группой и одной схемой подписи собирается | подтверждено по коду; сборка — экспериментом | [Факт: `src/builder.rs` стр. 207–224] — `with_protocol_versions` требует хотя бы один suite и хотя бы одну группу; других ограничений на состав нет. Поля `CryptoProvider` публичны (`mod.rs` стр. 43–51). `WebPkiSupportedAlgorithms { all, mapping }` с одним `ED25519` — публичные поля [Факт: `SUPPORTED_SIG_ALGS`, `mod.rs` стр. 160–236] |
| 2.4 | Принуждение «только Ed25519» держится на наборе алгоритмов, переданном в проверку подписи (V-01) | подтверждено | [Факт: `src/client/tls13.rs` стр. 1192–1219, `src/server/tls13.rs` стр. 1204] — `rustls` не сверяет `dss.scheme` с `supported_verify_schemes()`; `verify_tls13_signature_with_raw_key` (`src/webpki/verify.rs` стр. 213–228) берёт `convert_scheme(dss.scheme)?[0]`, а `convert_scheme` возвращает ошибку для схемы вне `mapping` (стр. 95–104) |
| 2.5 | Verifier обязан сам вызвать проверку подписи; маркеры создаются без проверки | подтверждено | [Факт: `src/verify.rs` стр. 22–64] — `HandshakeSignatureValid::assertion()`, `ServerCertVerified::assertion()`, `ClientCertVerified::assertion()` публичны. Клиент вызывает `verify_server_cert(end_entity, …)`, затем `verify_tls13_signature(…, end_entity, …)` с тем же `end_entity`; сервер — `verify_client_cert` (`server/tls13.rs` стр. 1152), затем `verify_tls13_signature(msg, &certs[0], sig)` (стр. 1204) |
| 2.6 | RPK объявляются и принуждаются: клиент — `verifier.requires_raw_public_keys()` и `client_auth_cert_resolver.only_raw_public_keys()`; сервер — `cert_resolver.only_raw_public_keys()` и `verifier.requires_raw_public_keys()`; отката к X.509 нет | подтверждено | [Факт: `src/client/hs.rs` стр. 351–362, 657–681, 1084–1102; `src/server/hs.rs` стр. 225–290] — при требовании RPK и его отсутствии у пира: сервер `IncorrectCertificateTypeExtension`, клиент — `handshake_failure`. Готовые резолверы — `server::AlwaysResolvesServerRawPublicKeys`, `client::AlwaysResolvesClientRawPublicKeys` (`lib.rs` стр. 603, 643) |
| 2.7 | RPK через `quinn` работает без изменений | **только экспериментом** | [Факт: `$S/quinn-proto-0.11.19/src/crypto/rustls.rs` стр. 80–88] — `peer_identity()` отдаёт `Vec<CertificateDer>` из `peer_certificates()`; `quinn` сертификаты не разбирает. Отказа по коду не видно, но это вывод, не запуск (эксперимент I0 п. 1) |
| 2.8 | `TLS13_AES_128_GCM_SHA256` MUST быть в провайдере, иначе `quinn` не создаёт конфигурацию | **уточнено** | [Факт: `quinn-proto` `src/crypto/rustls.rs` стр. 392–401, 500–510, 567–580] — так только для `TryFrom<…Config>`. `QuicClientConfig::with_initial` / `QuicServerConfig::with_initial` (стр. 331–340, 461–470) принимают suite для Initial отдельно («useful if you want to avoid the initial cipher suite for traffic encryption»). Основание требования — RFC 9001 §5: Initial и Retry защищаются `AEAD_AES_128_GCM` [Факт: rfc9001.txt, перечень в §5]. Решение профиля «три suite» остаётся допустимым; формулировку причины исправить |
| 2.9 | `tls12` отключается feature | подтверждено для 0.23 | [Факт: `Cargo.toml` `tls12 = []`, модуль `tls12` под `cfg(feature = "tls12")`]. В 0.24 feature `tls12` нет, TLS 1.2 выключается пустым `tls12_cipher_suites` в провайдере [Факт: `$S/rustls-0.24.0-dev.3/Cargo.toml`; `src/crypto/mod.rs` стр. 136–163] |
| 2.10 | Профиль ограничивает features только у `rustls` | **неполно** | [Факт: `$S/quinn-0.11.12/Cargo.toml` `[features]`] — `quinn` по умолчанию включает `rustls-ring`, `platform-verifier`, `bloom`; `quinn-proto` — `rustls-ring`. Без `default-features = false` у `quinn` в дерево попадают `ring` и `rustls-platform-verifier` (на Windows — системное хранилище сертификатов). CP-02 должен покрывать и `quinn`/`quinn-proto` |
| 2.11 | Resumption выключен: `Resumption::disabled()`, `send_tls13_tickets = 0`, `NoServerSessionStorage`, `send_ticket_request = None` | **неполно** | [Факт: `src/server/server_conn.rs` стр. 395–410; `src/server/tls13.rs` стр. 353–368; `src/server/builder.rs` стр. 111–124] — в 0.23.46 есть поле `ServerConfig::max_tls13_tickets` (RFC 9149): при значении > 0 запрос клиента **заменяет** `send_tls13_tickets`. По умолчанию 0. В профиль добавить `SC.max_tls13_tickets = 0` и включить в снимок T-PR1. По умолчанию `session_storage = ServerSessionMemoryCache::new(256)` при `std` — явная замена на `NoServerSessionStorage` обязательна |
| 2.12 | Сервер MUST NOT отправлять HRR (CP-18) | **опровергнуто как исполнимое требование** | [Факт: `src/server/tls13.rs` стр. 221–245] — сервер `rustls` сам шлёт HRR, если клиент указал `X25519MLKEM768` в `supported_groups` без доли этой группы; отключить нельзя. Фильтр CP-12 видит только `named_groups()`, а не `key_share` (`src/server/server_conn.rs` стр. 157–245: аксессоры `server_name`, `signature_schemes`, `alpn`, `cipher_suites`, `server_cert_types`, `client_cert_types`, `certificate_authorities`, `named_groups`). Собственный клиент HRR не вызывает. Переформулировать: «штатно не возникает; зондирующий может получить HRR; повторный ClientHello без доли — отказ (`RefusedToFollowHelloRetryRequest`)» |
| 2.13 | 0-RTT/0.5-RTT: `max_early_data_size = 0`, `send_half_rtt_data = false`, `into_0rtt` запрещён | подтверждено | [Факт: `src/server/builder.rs` стр. 119–120 — значения по умолчанию 0 и `false`; `quinn-proto` `src/crypto/rustls.rs` стр. 435–436, 480–488 — `max_early_data_size = u32::MAX` ставит только внутренний `QuicServerConfig::inner()` для `with_single_cert`, путь `TryFrom` значение не меняет; `$S/quinn-0.11.12/src/connection.rs` стр. 126 — `into_0rtt`] |
| 2.14 | Чтение согласованной группы в T1 недоступно | подтверждено | [Факт: `quinn-proto` `src/crypto/rustls.rs` стр. 259–272] — поле `negotiated_key_exchange_group` только под `__rustls-post-quantum-test` |
| 2.15 | Key update: T2 `refresh_traffic_keys()`, T1 `force_key_update()` | подтверждено наличие API | [Факт: `src/conn.rs` стр. 145, 574; `quinn-0.11.12/src/connection.rs` стр. 609]. Удаление прежних ключей и поведение `tokio-rustls` — **только экспериментом** (CP §5 п. 4–5) |
| 2.16 | Проверка Ed25519 в AWS-LC отвергает `S ≥ L` (CP §5 п. 6, T-ED1) | **подтверждено по исходнику** (было «не проверено») | [Факт: `$S/aws-lc-sys-0.47.0/aws-lc/crypto/fipsmodule/curve25519/curve25519.c` стр. 485–553] — `ed25519_verify_internal`: отказ, если старшие 3 бита `S` ненулевые; сравнение `S` с порядком `kOrder` по словам, `S == L` тоже отказ; уравнение без кофактора: вычисляется `[S]B − [k]A'` и сравнивается кодировка с `R` (`CRYPTO_memcmp`). Что `aws_lc_rs::signature::ED25519` доходит именно до этой функции — [Вывод: `aws-lc-rs` `src/ed25519.rs` стр. 83–115 через `EVP_PKEY_ED25519`], цепочка EVP не прослежена. Тест T-ED1 остаётся обязательным |
| 2.17 | QUIC отвергает иной поток сам (TS §5.2: «STREAM_LIMIT_ERROR») | **опровергнуто для `quinn-proto` < 0.11.19** | [Факт: RUSTSEC-2026-0523] — `MAX_STREAM_DATA` открывал потоки без проверки лимита. Исправлено в 0.11.19; нижняя граница должна быть 0.11.19 |
| 2.18 | Состояние между соединениями отсутствует (CP-08…10) | **неполно для T1** | [Факт: `quinn-proto` `src/config/mod.rs` стр. 455–535, 561–610] — при feature `bloom` (входит в default) сервер шлёт 2 токена `NEW_TOKEN` со сроком 2 недели; клиент хранит их в `TokenMemoryCache` по имени сервера и вставляет в открытый заголовок Initial. RFC 9000 §8.1.3: токен позволяет серверу связать соединения; клиент MUST NOT подставлять токен неприменимому серверу [Факт: rfc9000.txt §8.1.3]. При общем «имени-заглушке» для разных серверов (SNI выключен, N-11) токен сервера A уйдёт серверу B [Вывод]. Пользы без 0-RTT мало. Предлагается: `ValidationTokenConfig::sent(0)` на сервере, `token_store(NoneTokenStore)` на клиенте |
| 2.19 | `ClientHello` для CP-12 даёт `alpn()`, `named_groups()`, `server_cert_types()`, `client_cert_types()` | подтверждено | [Факт: `src/server/server_conn.rs` стр. 157–245] |
| 2.20 | Состояние `rustls` 0.24 | dev-ветка, API несовместим | [Факт: crates.io; `$S/rustls-0.24.0-dev.3`] — провайдеры вынесены в отдельные крейты (`rustls-aws-lc-rs` 0.24.0-dev.3), `logging` заменён на `tracing`, verifier — `ServerVerifier::verify_identity(&ServerIdentity)` с `Identity::RawPublicKey`, TLS 1.2 выключается пустым `tls12_cipher_suites`. `quinn` 0.11 зависит от `rustls` ^0.23.5 [Факт: `quinn-0.11.12/Cargo.toml`]. Вывод: MVP на 0.23.x; миграция — отдельным ADR после стабильного 0.24 и совместимого `quinn` |

Что можно подтвердить только экспериментом фазы 1: 2.7 (RPK через `quinn`), фактическую сборку провайдера 2.3 и
отказ `quinn` при его составе, размер ClientHello и число Initial, отсутствие 0.5-RTT в T1 на проводе, удаление
прежних ключей после обновления, поведение `refresh_traffic_keys()` через `tokio-rustls`, поведение `webpki` на
неканоническом SPKI (при RPK проект сравнивает 44 байта сам — риск снят, если сравнение идёт до вызова `webpki`).

## 3. Сборка на Windows

Цель — `x86_64-pc-windows-msvc`, без FIPS. Источник — `$S/aws-lc-sys-0.47.0/README.md` и
`$S/aws-lc-sys-0.47.0/builder/main.rs`, `cc_builder.rs`.

| Вопрос | Ответ | Источник |
|---|---|---|
| Нужен ли CMake | Нет. Без FIPS, без `bindgen`, при наличии предгенерированных привязок выбирается `CcBuilder` (компилятор C через крейт `cc`) | [Факт: `builder/main.rs` стр. 709–795: CMake — только для FIPS, `NO_ASM`, санитайзеров, явного `AWS_LC_SYS_CMAKE_BUILDER=1` или если нужен `bindgen`] |
| Есть ли предгенерированные привязки для x64 MSVC | Да, `x86_64_pc_windows_msvc` в списке | [Факт: README, «Pregenerated Bindings Availability»] |
| Нужен ли NASM | Для x86/x86-64 Windows ассемблер нужен; если `nasm` не найден, при feature `prebuilt-nasm` используются готовые объектные файлы из крейта (26 файлов `builder/prebuilt-nasm/*.obj`) | [Факт: README «Use of prebuilt NASM objects»; `main.rs` стр. 1155–1183 `use_prebuilt_nasm`]. `rustls` feature `aws_lc_rs` и `quinn-proto` feature `aws-lc-rs` включают `aws-lc-rs/prebuilt-nasm` [Факт: оба `Cargo.toml`] |
| Нужен ли clang | Для x64 MSVC — нет. `clang-cl` ищется для `aarch64` MSVC и для `bindgen` | [Факт: `cc_builder.rs` стр. 1136–1145; `main.rs` стр. 930–941] |
| Что нужно на машине CI | MSVC Build Tools (`cl.exe`) и Rust MSVC toolchain; NASM — по выбору (см. ниже) | [Вывод]. Что именно предустановлено на образе GitHub Actions `windows-latest` — [Не проверено] |
| Подхват чужой AWS-LC | Скрипт сборки **автоматически** ищет установленный AWS-LC по `OPENSSL_DIR`, `OPENSSL_INCLUDE_DIR`/`OPENSSL_LIB_DIR`, pkg-config (Unix); принимает только настоящий AWS-LC не ниже минимальной версии, иначе собирает из исходника | [Факт: README «Automatic detection»; `main.rs` стр. 719–756] |

Рекомендации для CI и выпусков (нормативно предложить в TEST_STRATEGY §7 и ADR-0011):

1. `AWS_LC_SYS_USE_SYSTEM=0` во всех сборках (Linux и Windows): сборка не зависит от случайно установленной библиотеки
   и переменных `OPENSSL_*` — воспроизводимость и одна доверенная копия AWS-LC.
2. Выпускная сборка Windows: установить NASM и задать `AWS_LC_SYS_PREBUILT_NASM=0` — ассемблер собирается из
   исходника, а не берётся бинарным объектом из пакета. Готовые объекты проверяются CI `aws-lc-rs` на совпадение со
   сборкой из исходника [Факт: README], но для проекта это доверие к чужому CI. Для быстрых сборок на каждый коммит
   допустимы готовые объекты — компромисс записать в ADR.
3. Feature `fips` не включать (`aws-lc-fips-sys` требует CMake, Go и др. — [Не проверено], не нужен).
4. Проверка `cargo tree -e features` в CI: нет `ring`, нет `rustls-platform-verifier`, нет `tls12`, `brotli`, `zlib`,
   нет `fips`, `bindgen` (п. 2.10).

Фактическая сборка на Windows не выполнялась — [Не проверено]; это задача CI фазы 1.

## 4. Конфигурация и устройства

(заполняется)

## 5. Ключ подписи конфигураций

(заполняется)

## 6. Ротация и отзыв

(заполняется)

## 7. Хранение секретов

(заполняется)

## 8. Состояние замечаний

(заполняется)

## 9. Предлагаемые изменения в нормативные документы

(заполняется)

## 10. Обязательные тесты до выпуска

(заполняется)

## 11. Не проверено

(заполняется)
