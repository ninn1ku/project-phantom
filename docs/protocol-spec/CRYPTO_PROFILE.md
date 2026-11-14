# PROJECT PHANTOM — криптографический профиль (поток K1)

**Дата:** 2026-11-14. **Статус:** предложение для этапа 6; ADR-0003…0005 остаются Proposed. **Основание:** RFC 8446,
9846, 10024, 7250, 9001, 8032 (разделы — в §6); исходники `rustls` 0.23.46, `quinn` 0.11.12, `quinn-proto` 0.11.19,
`aws-lc-rs` 1.19.0 (`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`, далее `$REG`); клон RustSec.
**Не сделано:** ничего не собиралось и не запускалось; производительность не измерялась («требует измерения»).

## 0. Метки и нормативный язык

**[Факт]** — первичный текст или исходник прочитан; **[Вывод]** — следствие из фактов; **[Предположение]**;
**[Не проверено]**. Требования профиля имеют идентификаторы `CP-nn`; MUST / MUST NOT / SHOULD — в смысле BCP 14.
TLS 1.3 теперь определён RFC 9846 (июль 2026, «Obsoletes: … 8446»; §1.2 называет его «minor update», та же версия
протокола) **[Факт]**. Спецификация PHANTOM ссылается на RFC 9846; номера разделов RFC 8446 даны там, где текст
читался по нему.

## 1. Итог

| # | Решение | Отношение к ADR |
|---|---|---|
| 1 | TLS 1.3 — единственный криптографический слой (T1 — QUIC, T2 — TLS поверх TCP) | ADR-0003 подтверждён, формулировки уточнены (§3.6) |
| 2 | Одна группа `X25519MLKEM768` на обеих сторонах; ML-KEM-1024 и «чистый» ML-KEM отвергнуты | ADR-0004 подтверждён |
| 3 | **Raw public keys (RFC 7250) вместо самоподписанных X.509** на обеих сторонах, без согласования типов | Закрывает открытый вопрос ADR-0005 (C-10), **меняет** §3.1 архитектуры |
| 4 | Идентичность = SHA-256 от DER SubjectPublicKeyInfo (44 байта для Ed25519); текстовый формат `ed25519-spki-sha256:<64 hex>` | Уточнение ADR-0005 |
| 5 | Подпись — только Ed25519; ML-DSA отложен до профиля v2 | ADR-0004 «Риск» подтверждён |
| 6 | Cipher suites — три TLS 1.3 suite провайдера; `TLS13_AES_128_GCM_SHA256` обязателен (нужен `quinn` для Initial) | Уточнение |
| 7 | Обновление ключей: автоматическое у лимита AEAD в обеих библиотеках **плюс** обновление по таймеру; свежий обмен — новое соединение по сроку жизни, который исполняет и сервер | Уточнение ADR-0004, §3.3 (C-07) |
| 8 | ALPN `phantom/1` проверяется явно в T2 (в QUIC — строго библиотекой); сервер T2 отбрасывает неподходящий ClientHello до криптографии | Новое (C-09) |
| 9 | Нижние границы версий: добавить `rustls-webpki` ≥ 0.103.16 и `aws-lc-sys` ≥ 0.39.0 | Дополнение ADR-0011 |

## 2. Повторная оценка компонентов

### 2.1. TLS 1.3 (RFC 8446 / RFC 9846)

- **0-RTT.** Early data не имеет защиты от повтора на уровне TLS; сервер обязан ограничивать повторы, клиент MUST
  отправлять только данные, безопасные при повторе (RFC 8446 §8, App. E.1.3, E.5) **[Факт]**. В PHANTOM 0-RTT
  невозможен конструктивно: без PSK нет early data (RFC 8446 §2.3) **[Факт]**. Решение: выключен (CP-06, CP-07).
- **PSK/resumption.** `psk_ke` не даёт forward secrecy (App. E.1) **[Факт]**. Resumption позволяет серверу связывать
  соединения (RFC 9001 §4.5) **[Факт]**, а в `rustls` хранилище клиента стало каналом понижения группы
  (RUSTSEC-2026-0349, §2.7) **[Факт]**. Решение: выключен с обеих сторон (CP-08…CP-10).
- **KeyUpdate.** Ключи обновляются односторонне, `update_requested` заставляет ответить; KeyUpdate шифруется старыми
  ключами (RFC 8446 §4.6.3). Следующий секрет — `HKDF-Expand-Label(secret_N, "traffic upd", …)` (§7.2) — новой
  энтропии нет **[Факт]**. RFC 9846 §1.2 поднял требование обновиться до лимита до MUST и ограничил число KeyUpdate;
  §4.7.3: эпоха не более 2^48−1 **[Факт]**.
- **Лимиты.** AES-GCM — до 2^24.5 полноразмерных записей на один набор ключей, ChaCha20-Poly1305 — счётчик
  переполнится раньше лимита (RFC 8446 §5.5; RFC 9846 §5.5: «MUST either close the connection or do a key update»,
  получатель SHOULD NOT их исполнять) **[Факт]**.
- **Post-handshake auth.** Требует расширения `post_handshake_auth` от клиента (RFC 8446 §4.6.2); в QUIC запрещена
  (RFC 9001 §4.4) **[Факт]**. В PHANTOM не используется: клиент аутентифицируется в рукопожатии.
- **Свойства (App. E.1, E.2).** Против активного сетевого атакующего: секретность и уникальность сеансовых ключей,
  аутентификация пира, защита от понижения (`Finished` и подпись), forward secrecy относительно долговременных
  ключей «as long as the session key itself has been erased», устойчивость к KCI, идентичность клиента защищена от
  пассивного **и активного** атакующего. Post-compromise security нет ни для долговременных ключей (E.1.5), ни для
  трафикового секрета: «an attacker who learns a traffic secret can compute all future traffic secrets on that
  connection» (E.2) **[Факт]**. E.1 требует padding записей, чтобы длина не выдавала идентичность **[Факт]**.
- RFC 9846 §4.2.8 (строки текста о key_share): «Clients and Servers MUST NOT reuse a key share for multiple
  connections» **[Факт]** — исполняется библиотекой, проверяется тестом (§4, T-KS).

### 2.2. X25519MLKEM768 (RFC 10024, прочитан целиком)

- Standards Track, август 2026; codepoint 0x11EC, IANA «Recommended: Y»; `SecP256r1MLKEM768` и `SecP384r1MLKEM1024` —
  «Recommended: N» (§7) **[Факт]**.
- Доля клиента 1216 байт (1184 ML-KEM + 32 X25519), сервера 1120 байт (1088 + 32); общий секрет 64 байта, ML-KEM
  первым (§4.1–4.3). Сервер MUST проверить ключ инкапсуляции (FIPS 203 §7.2), клиент — длину шифртекста; X25519 —
  с проверкой нулевого результата (§4.2–4.3) **[Факт]**.
- §6: анализ «relies crucially on the TLS 1.3 message transcript»; ML-KEM раскрывает пиру случайность `m`, поэтому
  важен качественный RNG **[Факт]**. **[Вывод]** Переносить гибрид в собственный протокол нельзя — ещё один довод
  за ADR-0003.
- §5: для X25519MLKEM768 в FIPS-режиме сертифицированной должна быть реализация ML-KEM **[Факт]**.
- `rustls` 0.23.46: `X25519MLKEM768` с `post_quantum_first: true` и длинами 1184/1088
  (`$REG/rustls-0.23.46/src/crypto/aws_lc_rs/pq/mod.rs`) — совпадает с RFC **[Факт]**. Гибрида с ML-KEM-1024 в
  `rustls` 0.23.46 нет; есть только «чистые» `MLKEM768`, `MLKEM1024` (там же; `mod.rs`, `ALL_KX_GROUPS`) **[Факт]**.
- **Выбор:** `X25519MLKEM768`. ML-KEM-1024 в `rustls` доступен только без классической части — это отказ от
  гибридной страховки ради запаса уровня 5, против которого у T9 нет специфических оснований **[Вывод]**.
  `SecP384r1MLKEM1024` потребовал бы другого провайдера. Пересмотр — когда гибрид с ML-KEM-1024 появится в `rustls`.

### 2.3. Raw public keys (RFC 7250)

- Certificate содержит DER SubjectPublicKeyInfo вместо X.509 (§3); тип выбирается расширениями
  `client_certificate_type`/`server_certificate_type`; в TLS 1.3 ответ — в EncryptedExtensions (RFC 8446 §4.2,
  таблица: «CH, EE»), при RawPublicKey `certificate_list` «MUST contain no more than one CertificateEntry» (§4.4.2)
  **[Факт]**. Привязка ключа к сущности — только вне полосы (RFC 7250 §4.3, §4.4, §6) **[Факт]**: у нас это
  закреплённый отпечаток.
- RFC 7250 §6: подмена выбора типа обнаруживается по `Finished` **[Факт]**.
- **[Вывод]** Расширения типов в ClientHello видны наблюдателю. Отличительный признак уже есть (собственный ALPN,
  ADR-0006), поэтому прирост различимости мал; для T3 (HTTP/3 на своём домене) этот профиль не предназначен.

### 2.4. QUIC-TLS (RFC 9001)

- §6: TLS KeyUpdate в QUIC MUST NOT отправляться; ключи меняются битом Key Phase, обновление затрагивает обе
  стороны; разрешено только после подтверждения рукопожатия (§4.1.2) **[Факт]**.
- §6.6: лимит конфиденциальности AES-GCM — 2^23 пакетов, ChaCha20-Poly1305 — «greater than the number of possible
  packets (2^62)»; лимит целостности — 2^52 и 2^36 неверных пакетов на соединение; при достижении — закрытие с
  `AEAD_LIMIT_REACHED`. Лимит, превышение которого нельзя избежать обновлением, — закрыть соединение **[Факт]**.
- §4.3: ClientHello может занимать несколько Initial-пакетов; сервер MAY требовать Retry, чтобы буферизовать
  частичный ClientHello только от проверенных адресов **[Факт]**. §4.7: HRR для проверки адреса SHOULD NOT — для
  этого Retry **[Факт]**.
- §5.7: сервер MUST NOT обрабатывать 1-RTT пакеты до завершения рукопожатия; клиент до проверки сервера не
  аутентифицирован **[Факт]**. §8.1: ALPN обязателен, при несогласовании — закрыть с 0x0178 **[Факт]**.

### 2.5. Ed25519 (RFC 8032)

- §5.1.7: S в диапазоне `0 <= s < L`, иначе подпись недействительна; допускаются уравнения с кофактором и без
  (`[8][S]B = [8]R + [8][k]A'`, «sufficient, but not required» без 8) **[Факт]**. §8.4: неподделываемость формы
  подписи держится на проверке `S < L` **[Факт]**. §8.5: Ed25519 RECOMMENDED при уровне 128 бит **[Факт]**.
- **[Вывод]** Расхождение «с кофактором / без» важно для консенсусных систем, не для двухточечного TLS, где
  проверяет одна реализация (AWS-LC). Требуется отказ при `S >= L` — проверяется тестовым вектором (T-ED1).
  Какое уравнение использует AWS-LC — **[Не проверено]** (исходник `aws-lc-sys` в среде отсутствует).

### 2.6. `rustls` 0.23.46 и `aws-lc-rs` 1.19.0

- Features по умолчанию: `aws_lc_rs, logging, prefer-post-quantum, std, tls12` (`Cargo.toml`) **[Факт]**.
  `DEFAULT_KX_GROUPS` содержит X25519, P-256, P-384 (`src/crypto/aws_lc_rs/mod.rs`) — профиль строит собственный
  `CryptoProvider` с одной группой, поэтому от `prefer-post-quantum` не зависит **[Вывод]**.
- `aws-lc-rs` 1.19.0 зависит от `aws-lc-sys` 0.47.0 (`$REG/aws-lc-rs-1.19.0/Cargo.toml`) — исправления
  RUSTSEC-2026-0044…0048 (≥ 0.39.0) включены **[Факт]**. `rustls` объявляет `rustls-webpki` `^0.103.14` — этого
  недостаточно (§2.7) **[Факт]**.
- Провайдер `aws-lc-rs` в `rustls` 0.23.46 умеет подписывать и проверять ML-DSA-44/65/87
  (`src/crypto/aws_lc_rs/sign.rs`, `PqdsaKeyKind`; `mod.rs`, `mapping`) **[Факт]**.
- Аудит: Cure53 2020 по версии 0.16 (R4 [35]); нового аудита в материалах проекта нет **[Факт по R4]**.

### 2.7. Advisories 2025–2026 (локальный клон RustSec, `crates/<имя>/`)

| Advisory | Crate | Суть | Исправлено | Значение для профиля |
|---|---|---|---|---|
| RUSTSEC-2026-0285 | rustls | Сообщения рукопожатия принимались через границу уровня шифрования | ≥ 0.23.45 | Закрыто версией |
| RUSTSEC-2026-0346 | rustls | `Debug` значений сеанса клиента раскрывает секреты | ≥ 0.23.46 | Закрыто; плюс CP-28 |
| RUSTSEC-2026-0347 | rustls | Буферизованные данные уходят внешнему серверу после отказа ECH | ≥ 0.23.46 | ECH не используется |
| RUSTSEC-2026-0348 | rustls | Brotli-распаковка сертификата — до 1 ГиБ до аутентификации | ≥ 0.23.46 | Сжатие выключено (CP-17) |
| RUSTSEC-2026-0349 | rustls | Неаутентифицированный ServerHello понижает будущие соединения до X25519 | ≥ 0.23.46 | Не применимо: нет resumption **и** сервер принимает одну группу (CP-03, CP-08) |
| RUSTSEC-2026-0049, -0098, -0099, -0104, -0382 | rustls-webpki | CRL, name constraints, panic в разборе CRL, недоверенные промежуточные | ≥ 0.103.16 (для -0382) | Путь цепочек не используется при RPK, но версию закрепить (CP-30) |
| RUSTSEC-2026-0044…0048 | aws-lc-sys | X.509, PKCS7, CRL, тайминг AES-CCM | ≥ 0.39.0 | X.509/PKCS7/CCM не используются; версия 0.47.0 |
| RUSTSEC-2026-0037, -0185, -0338…-0343 | quinn-proto | Panic и исчерпание памяти до/после рукопожатия | ≥ 0.11.18 | ADR-0011 уже требует 0.11.18 |
| RUSTSEC-2025-0009 | ring | Panic AES при overflow-checks | ≥ 0.17.12 | `ring` не в профиле |
| RUSTSEC-2025-0007 | ring | «unmaintained» | отозван 2025-02-22 | — |

Advisories на `aws-lc-rs` за 2025–2026 в клоне не найдено **[Факт]**.

### 2.8. Альтернативы и выбор

| Вариант | Что даёт | Почему не выбран |
|---|---|---|
| Провайдер `ring` | Чистая история аудита 2020 | Нет ML-KEM: `kx_group` — только X25519, P-256, P-384 (`src/crypto/ring/mod.rs`) **[Факт]**; нарушает G5 |
| `rustls-rustcrypto` | Чистый Rust | В README `rustls` назван «experimental» **[Факт]**; `ml-kem` RustCrypto без аудита (R4 [40]) |
| OpenSSL / BoringSSL (`rustls-openssl`, `boring-rustls-provider`) | Гибрид есть в OpenSSL ≥ 3.5 (R4 [33]) | Второй C-стек вместо первого; BoringSSL-провайдер — «work-in-progress» (README) **[Факт]**; выигрыша нет |
| ML-KEM-1024 | Уровень 5 | В `rustls` 0.23.46 только без X25519 (§2.2) |
| ML-DSA для аутентификации | Защита аутентификации от будущего T9 | HNDL аутентификацию не затрагивает (RR10); подписи и ключи больше — растёт серверный полёт при лимите 3× до проверки адреса (RFC 9001 §4.4) **[Вывод]**; размеры по FIPS 204 **[Не проверено]**; стандарт ML-DSA для TLS **[Не проверено]**. Путь миграции — профиль v2, формат отпечатка уже агностичен |
| WireGuard + Rosenpass | Доказательства WireGuard; PQ-PSK каждые ~2 мин (R4 §6.4) | Нет TCP-режима; два протокола и демона; аудит Rosenpass не найден (R4 [49]); вне ADR-0003. Допустим как внешний инструмент пользователя, не как часть PHANTOM |

## 3. Решения по замечаниям ревью

### 3.1. C-07. Обновление ключей и срок жизни

**Что делают библиотеки (по исходникам).**
- T2, `rustls`: перед шифрованием `pre_encrypt_action` возвращает `RefreshOrClose` при достижении
  `write_seq_max = min(SEQ_SOFT_LIMIT, confidentiality_limit)` (`src/record_layer.rs`); для TLS 1.3 это
  `refresh_traffic_keys_pending = true` (`src/common_state.rs`, `write_plaintext`), и библиотека отправляет
  KeyUpdate с **`update_requested`** (`request_key_update_and_update_encrypter`, `src/tls13/key_schedule.rs`) —
  обновляются оба направления **[Факт]**. Лимиты: AES-128/256-GCM — `1 << 24` записей, ChaCha20 — `u64::MAX`
  (`src/crypto/aws_lc_rs/tls13.rs`) **[Факт]**. Приём: не более 32 KeyUpdate-запросов подряд без данных
  приложения (`TemperCounters::INITIAL_KEY_UPDATE_REQUESTS`) **[Факт]**. Ручной вызов —
  `ConnectionCommon::refresh_traffic_keys()` (`src/conn.rs`) **[Факт]**.
- T1, `quinn-proto`: первое обновление — после случайных 10…999 пакетов (`key_phase_size:
  rng.random_range(10..1000)`, `src/connection/mod.rs`), далее при `confidentiality_limit − 10_000`
  (`KEY_UPDATE_MARGIN`, `update_keys`); проверка — `PacketBuilder::new` (`src/connection/packet_builder.rs`)
  **[Факт]**. Лимиты QUIC: AES-GCM `1 << 23`, ChaCha20 `u64::MAX`; лимит целостности `1 << 52` / `1 << 36`,
  превышение — `AEAD_LIMIT_REACHED` (`src/connection/mod.rs`) **[Факт]**. Ручной вызов —
  `quinn::Connection::force_key_update()` (`$REG/quinn-0.11.12/src/connection.rs`) **[Факт]**.
- **[Вывод]** При ChaCha20 автоматического обновления по объёму нет ни в T2, ни в T1 (кроме первого случайного в
  QUIC). При AES-GCM оно происходит примерно каждые 2^24 записей / 2^23 пакетов (≈ 22 / 11 ГБ при пакетах
  ~1,3 КБ — оценка ревью, требует измерения).

**Что даёт обновление и что даёт новое соединение (RFC 8446 App. E.2).** KeyUpdate при удалении старых ключей
защищает трафик **до** обновления от последующей утечки памяти; от атакующего, уже знающего трафиковый секрет, не
защищает — он вычисляет все следующие. Восстанавливает секретность только новое рукопожатие **[Факт]**.

**Решение.**
- CP-20: каждая сторона MUST вызывать обновление ключей по таймеру `KEY_UPDATE_INTERVAL` (стартовое значение
  600 с; T2 — `refresh_traffic_keys()`, T1 — `force_key_update()`), независимо от объёма. Отказ вызова
  (соединение не готово) — повтор при следующем тике, не ошибка.
- CP-21: клиент MUST устанавливать новое соединение не позже `CONN_REKEY_AFTER` (стартовое 3000 с ± 10 % случайно)
  по схеме «новое, `Activate`, затем закрыть старое»; сервер MUST закрывать соединение по `CONN_MAX_LIFETIME`
  (3600 с) сам (C-05). Значения — стартовые **[Вывод]**: число рукопожатий в час и стоимость гибридного обмена на
  сервере требуют измерения.
- CP-22: реализация MUST NOT отключать автоматическое обновление библиотек и MUST NOT экспортировать трафиковые
  секреты (`enable_secret_extraction = false`, `key_log` — `NoKeyLog`).

**Нормативная формулировка G4 (замена).**
- **G4a. Forward secrecy относительно долговременных ключей.** Кража ключа идентичности сервера или клиента после
  завершения рукопожатия не раскрывает трафик этого соединения. Механизм — эфемерный гибридный обмен в каждом
  рукопожатии; от срока жизни не зависит (RFC 8446 App. E.1). Допущение: resumption и 0-RTT выключены.
- **G4b. Ограничение ущерба от утечки сеансовых ключей.** Однократное чтение памяти процесса в момент t раскрывает
  трафик соединения, начиная с последнего обновления ключей до t (не более `KEY_UPDATE_INTERVAL` назад, при условии
  удаления прежних ключей библиотекой) и после t — до закрытия соединения (не более `CONN_MAX_LIFETIME`).
- RR8 дополнить: «трафик текущего соединения — от последнего обновления ключей до его закрытия — раскрыт».

**Тесты.** T-KU1: T2, suite AES-128-GCM, тестовая сборка с уменьшенным лимитом через собственный
`Tls13CipherSuite` с `confidentiality_limit = 1000` (только в тестах) — после 5000 записей соединение живо, данные
целы, наблюдаются KeyUpdate в обе стороны. T-KU2: то же в T1 с `force_key_update()` в цикле и проверкой фазы.
T-KU3: таймерное обновление при ChaCha20 (обе стороны). T-KU4: пир шлёт 33 KeyUpdate без данных — соединение
закрыто. T-KU5: сервер закрывает соединение по `CONN_MAX_LIFETIME` при молчащем клиенте.

### 3.2. C-08. Идентичность клиента (A4)

**Факт по коду:** клиент `rustls` проверяет `Certificate` и `CertificateVerify` сервера в
`ExpectCertificateVerify` и `Finished` сервера через `ConstantTimeEq::ct_eq` в `ExpectFinished`; свой `Certificate`
и `CertificateVerify` он формирует только после этого (`$REG/rustls-0.23.46/src/client/tls13.rs`,
`emit_certificate_tls13` в `ExpectFinished::handle`). Сообщения идут под ключами рукопожатия **[Факт]**.

**Новая гарантия G17.** Публичный ключ клиента не раскрывается пассивному наблюдателю (T1, в том числе при
последующей краже любых долговременных ключей) и активному атакующему (T2, T3, T4), не владеющему приватным ключом
ни одного из закреплённых у клиента ключей сервера. Против T9 защищён гибридом (ключи рукопожатия выводятся из
общего секрета `X25519MLKEM768`). Граница: свойство теряется при дефекте verifier (C-01); идентичность известна
серверу, T5 и обладателю любого закреплённого ключа сервера, включая старый в период перекрытия.
- CP-23: клиент MUST NOT передавать что-либо, зависящее от его идентичности, вне сообщения `Certificate` TLS.
- CP-24: тип сертификата — RPK (§3.4), поэтому длина `Certificate` клиента одинакова для всех клиентов (44 байта
  SPKI) и не требует padding для сокрытия идентичности (RFC 8446 App. E.1) **[Вывод]**.

**Тест T-ID1.** Сервер с незакреплённым ключом и инструментированным `ClientCertVerifier`: клиент обрывает
рукопожатие, `verify_client_cert` ни разу не вызван, после `Finished` сервера от клиента приходит только alert.
T-ID2: то же при верном отпечатке и чужом приватном ключе сервера (сочетается с тестом C-01).

### 3.3. C-09. ALPN в T2, момент аутентификации, данные до `Finished`

**Факты по коду.** Сервер `rustls` отвечает `no_application_protocol`, только если клиент прислал ALPN без
пересечения; если клиент ALPN не прислал вовсе, рукопожатие продолжается без протокола; строгая проверка — только
для QUIC (`src/server/hs.rs`, начало `process_common`). Клиент проверяет, что выбранный протокол был предложен
(`check_selected_alpn`, по умолчанию `true`, `src/client/builder.rs`), а отсутствие протокола считает ошибкой только
в QUIC (`process_alpn_protocol`, `src/client/hs.rs`) **[Факт]**. Сервер `rustls` не отправляет 0.5-RTT данных при
запросе клиентского сертификата независимо от `send_half_rtt_data` (`src/server/tls13.rs`: `if
!doing_client_auth && self.config.send_half_rtt_data`) **[Факт]**. В `quinn` серверная сторона отправит 0.5-RTT
данные, только если приложение вызовет `Connecting::into_0rtt()` (`$REG/quinn-0.11.12/src/connection.rs`) **[Факт]**.

**Решение и нормы.**
- CP-11: `alpn_protocols = [b"phantom/1"]` на обеих сторонах обоих транспортов.
- CP-12 (T2, сервер): ClientHello MUST быть разобран через `rustls::server::Acceptor` (в `tokio-rustls` —
  `LazyConfigAcceptor`) до выбора конфигурации; соединение закрывается без ответа TLS, если `ClientHello::alpn()`
  не равен ровно `["phantom/1"]`, `named_groups()` не содержит `X25519MLKEM768` или `server_cert_types()` /
  `client_cert_types()` не равны ровно `[RawPublicKey]`. Это отсекает зондирующих до гибридного обмена и подписи.
- CP-13 (обе стороны, оба транспорта): после завершения рукопожатия MUST проверить `alpn_protocol() ==
  Some(b"phantom/1")` (в T1 — `HandshakeData::protocol`), `protocol_version() == TLSv1_3`,
  `negotiated_key_exchange_group()` = `X25519MLKEM768` (в T1 — **требует проверки**, §5), иначе закрыть.
- CP-14: версия протокола PHANTOM определяется **только** ALPN; `Hello` несёт лишь минорные возможности. Поле
  версии в `Hello`, не совпадающее с ALPN, — закрытие соединения.
- CP-15: сторона считается аутентифицированной, когда библиотека сообщила о завершении рукопожатия
  (`is_handshaking() == false`; в `quinn` — завершение `Connecting`), что для сервера означает проверку `Finished`
  клиента (RFC 9001 §4.1.1). До этого MUST NOT отправлять и обрабатывать данные приложения, включая `Config`.
  `Connecting::into_0rtt()` MUST NOT вызываться ни клиентом, ни сервером (правило CI: поиск вызова);
  `send_half_rtt_data = false`.

**Тесты.** T-AL1: клиент T2 без расширения ALPN — сервер закрывает до ServerHello. T-AL2: клиент с `h2` — то же.
T-AL3: «сервер» T2, не выбравший ALPN, — клиент закрывает после рукопожатия. T-AL4: в T1 то же — ошибка 0x0178.
T-HR1: в T1 и T2 сервер не отправляет ни одного байта данных приложения до `Finished` клиента (захват, ключи из
тестового key log только в тестовой сборке).

### 3.4. C-10. Самоподписанные X.509 или raw public keys

**Поддержка по исходникам.**
- `rustls` 0.23.46: клиент объявляет RPK, если `client_auth_cert_resolver.only_raw_public_keys()` и
  `verifier.requires_raw_public_keys()` (`src/client/hs.rs`); сервер — по `cert_resolver.only_raw_public_keys()` и
  `verifier.requires_raw_public_keys()`; при требовании RPK и его отсутствии у пира — `handshake_failure`, отката к
  X.509 нет (`process_cert_type_extension`, `src/server/hs.rs`; `src/client/hs.rs`) **[Факт]**. Готовые резолверы
  `AlwaysResolvesServerRawPublicKeys`, `AlwaysResolvesClientRawPublicKeys` (`src/server/handy.rs`,
  `src/client/handy.rs`); проверка подписи — `rustls::crypto::verify_tls13_signature_with_raw_key`, разбирающая
  только SPKI (`webpki::RawPublicKeyEntity`, `src/webpki/verify.rs`) **[Факт]**. В RPK-режиме те же методы
  `verify_server_cert` / `verify_client_cert` получают SPKI как `CertificateDer` (`src/client/tls13.rs`,
  `src/server/tls13.rs`) **[Факт]**.
- `quinn` / `quinn-proto`: сертификаты не разбирает (в `src/` нет `webpki`/X.509), всё делегирует `rustls`;
  `peer_identity()` возвращает `Vec<CertificateDer>` из `peer_certificates()` (`src/crypto/rustls.rs`) **[Факт]**.
  **[Вывод]** RPK работает в `quinn` без изменений; `peer_identity()[0]` — это SPKI. Подтвердить тестом (§5).

**Сравнение.** Самоподписанный X.509: разбор X.509 неаутентифицированного пира в `verify_tls13_signature`
(`webpki::EndEntityCert::try_from`) и в собственном извлечении SPKI; поля сертификата (серийный номер, сроки, имена)
видны зондирующему и различают установки; длина `Certificate` клиента зависит от содержимого; нужен генератор
сертификатов. RPK: нет X.509 вовсе, сравнение — по байтам, длина фиксирована, меньше серверный полёт. Цена RPK —
расширения типа в ClientHello (§2.3) и более молодой код `rustls` (поддержка RPK в 0.23 — **[Не проверено]**, с
какой версии).

**Решение: RPK на обеих сторонах, X.509 не поддерживается (CP-16).**
- `ServerCertVerifier`/`ClientCertVerifier`: `requires_raw_public_keys() == true`;
  `verify_server_cert`/`verify_client_cert`: `intermediates` MUST быть пуст; `end_entity` MUST иметь длину ровно 44
  байта и префикс `30 2a 30 05 06 03 2b 65 70 03 21 00` (DER SPKI Ed25519, OID 1.3.101.112 **[Вывод]**: префикс
  сверить тестом с `public_key()` ключа `aws-lc-rs`); `SHA-256(end_entity)` MUST совпасть с закреплённым значением.
  Имя сервера и время MUST игнорироваться.
- `verify_tls13_signature` MUST вызывать `verify_tls13_signature_with_raw_key` с алгоритмами `{ED25519}`;
  `verify_tls12_signature` MUST возвращать ошибку; `supported_verify_schemes() == [ED25519]`.
- Серверный verifier: `offer_client_auth() == true`, `client_auth_mandatory() == true`, `root_hint_subjects()`
  пуст.
- Идентичность сеанса вычисляет **одна** функция `identity(spki: &[u8]) -> [u8; 32]` = SHA-256, вызываемая и
  verifier, и таблицей сеансов (с `peer_certificates()[0]` / `peer_identity()[0]`).

**Формат отпечатка.** Двоичный — 32 байта SHA-256 от 44-байтного DER SPKI. Текстовый (конфигурации, журналы
оператора) — `ed25519-spki-sha256:` + 64 строчные шестнадцатеричные цифры; разборщик принимает только эту форму
(заглавные, пробелы, иные префиксы — ошибка). Показ человеку — первые 16 цифр, сравнение — только полного значения.
Хеш, а не сам 32-байтный ключ, выбран ради переноса формата на ML-DSA (профиль v2) **[Вывод]**.

**Тесты.** T-RPK1: клиент или сервер, предложивший только X.509, — `handshake_failure`. T-RPK2: два
`CertificateEntry` — отказ. T-RPK3: SPKI 45 байт / другой OID / ключ P-256 — отказ. T-RPK4: верный SPKI, подпись
чужим ключом — отказ (в обе стороны; это тест C-01). T-RPK5: `peer_identity()` в T1 и `peer_certificates()` в T2
дают одинаковый отпечаток. T-RPK6: разборщик отпечатка отвергает 9 некорректных форм.

### 3.5. C-11. Формулировки ADR-0003

Предлагаемая замена «Причин» и «Последствий»:
- «Своей криптографии нет» → «Своих примитивов, KDF и рукопожатия нет. Собственный код безопасности остаётся:
  verifier закреплённых ключей, автомат сеанса (`Activate`), управляющие сообщения, подпись конфигураций; от него
  зависят G2, G3, G6, G15».
- «Формальный анализ TLS 1.3» → «Формальный анализ рукопожатия TLS 1.3 с (EC)DHE (RFC 8446 App. E.1.6 — список
  работ). Гибрид опирается на transcript TLS (RFC 10024 §6) и отдельный анализ гибридов; защита пакетов QUIC и слой
  сеанса PHANTOM этими работами не покрыты».
- Добавить довод «за»: идентичность клиента скрыта от активного атакующего с forward secrecy (G17).
- Добавить цену: до аутентификации сервер выполняет гибридную инкапсуляцию и подпись Ed25519 для каждого
  ClientHello; в T2 частично снимается CP-12, в T1 — Retry и лимитами (G13).

### 3.6. C-12. G5 и ADR-0004

- G5, столбец «Допущение»: «Стойкость ML-KEM-768 (FIPS 203) против T9 и корректность реализации в AWS-LC; против
  классического атакующего достаточно стойкости любого из компонентов (RFC 10024 §3)».
- ADR-0004, «Причины»: «RUSTSEC-2026-0349 неприменим по двум независимым причинам: у клиента нет хранилища
  сеансов (`Resumption::disabled()`), а сервер принимает только `X25519MLKEM768` и не может согласиться на долю
  X25519». Тест — серверный (T-KX2).

### 3.7. C-13. HelloRetryRequest и ClientHello в нескольких Initial

- HRR штатно не возникает: клиент всегда шлёт долю единственной группы. Клиент `rustls` отвергает HRR без cookie,
  запрашивающий уже отправленную группу, и HRR без изменений (`IllegalHelloRetryRequestWithOfferedGroup`,
  `…WithNoChanges`, `src/client/hs.rs`); второй HRR запрещён RFC 8446 §4.1.4 **[Факт]**. HRR с cookie и той же
  группой по коду не отвергается — это не понижение, transcript его покрывает **[Вывод]**.
- CP-18: сервер MUST NOT отправлять HRR; появление HRR у клиента — журналируемое событие, рукопожатие допускается
  только с `X25519MLKEM768`.
- Размер ClientHello: доля 1216 байт (RFC 10024 §4.1) плюс прочие расширения; по оценке 1,4–1,6 КБ **[Вывод,
  требует измерения]** — больше 1200 байт, т. е. два Initial-пакета. RFC 9001 §4.3 это допускает.
- CP-19: сервер T1 под нагрузкой MUST использовать Retry (`Incoming::retry()`), чтобы буферизовать частичный
  ClientHello только от проверенных адресов; лимит на число незавершённых рукопожатий с непроверенных адресов —
  параметр G13.
- Тесты: T-HRR1 — «сервер» шлёт HRR с `X25519MLKEM768` без cookie — клиент закрывает с `illegal_parameter`;
  T-HRR2 — HRR с X25519 — отказ (группа не предлагалась); T-IN1 — ClientHello, разбитый на два Initial, в том
  числе после Retry и с переставленным порядком пакетов; T-IN2 — потеря второго Initial.

### 3.8. C-14. Полный профиль

Сведён в таблицу §4; ключевые решения: `send_tls13_tickets = 0`, `session_storage = NoServerSessionStorage`,
`Resumption::disabled()`, `max_early_data_size = 0`, `enable_early_data = false`, схемы подписи — только
`ED25519`, `cert_compressors`/`cert_decompressors` пусты и features `brotli`/`zlib` не включены, `default-features =
false` без `tls12`, версии — `&[&TLS13]`. Набор cipher suites: три TLS 1.3 suite `aws-lc-rs`;
`TLS13_AES_128_GCM_SHA256` MUST присутствовать — без него `quinn` не создаёт конфигурацию
(`initial_suite_from_provider`, `quinn-proto/src/crypto/rustls.rs`) **[Факт]**. Порядок — библиотеки
(`ignore_client_order = false`); набор не сужается, обе ветки AEAD тестируются (§3.1).

### 3.9. C-15. Тесты целостности и повторов

T-INT1: изменение одного байта записи T2 — соединение закрыто с `bad_record_mac`, данные не доставлены.
T-INT2: изменение байта пакета T1 — пакет отброшен, счётчик неудач растёт, соединение живо. T-INT3: превышение
лимита целостности в тестовой сборке — `AEAD_LIMIT_REACHED`. T-RP1: повтор отдельного пакета T1 — отброшен.
T-RP2: повтор записанного рукопожатия целиком (T1, T2) — не завершается. T-EOF1: обрыв TCP без `close_notify` в T2 —
ошибка `UnexpectedEof`, неполный кадр не обрабатывается.

### 3.10. C-16. Роли ключей

- CP-25: три роли — ключ идентичности сервера, ключи клиентов, ключ подписи конфигураций — MUST быть разными
  ключевыми парами. Загрузка конфигурации MUST отвергать: отпечаток сервера в списке клиентов; совпадение ключа
  подписи с любым ключом идентичности; повтор отпечатка в списке клиентов; пересечение внутренних адресов.
- Обоснование: RFC 8032 §8.6 разрешает один ключ для Ed25519/ctx/ph, но не для разных протоколов; подпись
  `CertificateVerify` TLS 1.3 имеет префикс контекста (RFC 8446 §4.4.3), формат подписи конфигурации — отдельный
  (C-03), и разделение ключей убирает зависимость от этих деталей **[Вывод]**.
- CP-26: проверка подписи конфигурации — `aws_lc_rs::signature::UnparsedPublicKey` с `ED25519`; подпись с `S >=
  L` MUST отвергаться (T-ED1, вектор из RFC 8032 §7.1 с прибавленным L).

## 4. Таблица профиля

Обозначения: `SC` — `rustls::ServerConfig`, `CC` — `rustls::ClientConfig`, `P` — `rustls::crypto::CryptoProvider`
(поля и методы сверены по `$REG/rustls-0.23.46/src/` и `$REG/quinn-*/src/`).

| CP | Параметр | Значение | Как задаётся | Тест |
|---|---|---|---|---|
| 01 | Версии | только TLS 1.3 | `ServerConfig::builder_with_provider(p).with_protocol_versions(&[&version::TLS13])`; то же для `ClientConfig` | T-V1: ClientHello TLS 1.2 — отказ (оба транспорта) |
| 02 | Feature `tls12` | выключена | `rustls = { default-features = false, features = ["aws_lc_rs", "std", "logging"] }`; `cargo tree -e features` в CI | T-V2: CI-проверка дерева features |
| 03 | Группы | `[X25519MLKEM768]` | `P.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768]` | T-KX1: согласована эта группа (`negotiated_key_exchange_group()`); T-KX2: ClientHello только с X25519 — отказ сервера |
| 04 | Cipher suites | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 (TLS 1.3) | `P.cipher_suites` = три `aws_lc_rs::cipher_suite::TLS13_*` | T-CS1: каждый suite принудительно на клиенте — соединение и KeyUpdate работают |
| 05 | Схемы подписи | только `ED25519` | `P.signature_verification_algorithms = WebPkiSupportedAlgorithms { all: &[ED25519], mapping: &[(ED25519, &[ED25519])] }`; `supported_verify_schemes()` | T-SG1: пир с ключом P-256 — отказ |
| 06 | Early data, сервер | 0 | `SC.max_early_data_size = 0` (QUIC допускает 0 или `u32::MAX`) | T-ED0: early data отвергается |
| 07 | Early data, клиент | выключено | `CC.enable_early_data = false` | Тест конфигурации |
| 08 | Resumption, клиент | нет | `CC.resumption = Resumption::disabled()`; `CC.send_ticket_request = None` | T-RS1: повторное соединение — `handshake_kind() == Full` |
| 09 | Tickets, сервер | 0 | `SC.send_tls13_tickets = 0` (по умолчанию 2) | T-RS2: `NewSessionTicket` не отправляется |
| 10 | Хранилище, сервер | нет | `SC.session_storage = Arc::new(NoServerSessionStorage {})`; `SC.ticketer` по умолчанию `NeverProducesTickets` | Тест конфигурации |
| 11 | ALPN | `phantom/1` | `SC.alpn_protocols`, `CC.alpn_protocols`; `CC.check_selected_alpn = true` | T-AL1…AL4 |
| 12 | Фильтр ClientHello (T2) | см. §3.3 | `server::Acceptor` / `LazyConfigAcceptor`; `ClientHello::alpn()`, `named_groups()`, `server_cert_types()`, `client_cert_types()` | T-AL1, T-AL2, T-KX2 |
| 13 | Проверка после рукопожатия | версия, группа, ALPN, идентичность | `protocol_version()`, `negotiated_key_exchange_group()`, `alpn_protocol()`, `peer_certificates()`; T1: `handshake_data()`, `peer_identity()` | T-PH1 |
| 14 | 0.5-RTT | нет | `SC.send_half_rtt_data = false`; запрет `Connecting::into_0rtt()` | T-HR1 |
| 15 | Тип сертификата | RPK обеих сторон | `AlwaysResolvesServerRawPublicKeys`, `AlwaysResolvesClientRawPublicKeys` с `CertifiedKey::new(vec![spki], key)`; `requires_raw_public_keys() == true` | T-RPK1…6 |
| 16 | Verifier | §3.4 | `dangerous().with_custom_certificate_verifier`, `with_client_cert_verifier`; `verify_tls13_signature_with_raw_key` | T-RPK4 (обе стороны) |
| 17 | Сжатие сертификатов | нет | `SC/CC.cert_compressors = vec![]`, `cert_decompressors = vec![]`; features `brotli`, `zlib` не включать | T-CC1: CI-проверка features; ClientHello без `compress_certificate` |
| 18 | HRR | сервер не шлёт | следствие CP-03 и доли в ClientHello | T-HRR1, T-HRR2 |
| 19 | Retry (T1) | под нагрузкой | `quinn::Incoming::retry()`, `remote_address_validated()` | T-IN1, нагрузочный G13 |
| 20 | KeyUpdate по таймеру | 600 с | T2 `refresh_traffic_keys()`; T1 `Connection::force_key_update()` | T-KU3 |
| 21 | Срок жизни | клиент 3000 с ±10 %, сервер 3600 с | слой сеанса | T-KU5 |
| 22 | Экспорт секретов | нет | `enable_secret_extraction = false`; `key_log` по умолчанию (`NoKeyLog`) | T-SL1: в выпускной сборке `SSLKEYLOGFILE` игнорируется |
| 27 | SNI | не несёт секретов; verifier его игнорирует | `CC.enable_sni` — решение потока транспортов | T-SN1: verifier не зависит от имени |
| 28 | Секреты в журналах | нет | не логировать `Debug` объектов `rustls` (RUSTSEC-2026-0346) | G14 |
| 29 | Провайдер | `aws-lc-rs` 1.19.0 / `aws-lc-sys` ≥ 0.39 | `CryptoProvider` собирается одной функцией; `install_default` не используется | T-PR1: снимок `P` (группы, suites, схемы) |
| 30 | Версии зависимостей | `rustls` ≥ 0.23.46, `rustls-webpki` ≥ 0.103.16, `quinn-proto` ≥ 0.11.18 | `Cargo.lock`, `cargo deny` / `cargo audit` | CI |

KeyUpdate по объёму встроен в библиотеки и не отключается (CP-22). T-KS: два ClientHello подряд — разные доли.

## 5. Требует практической проверки при реализации

1. RPK в `quinn` 0.11.12: рукопожатие проходит, `peer_identity()` возвращает SPKI (вывод сделан по отсутствию
   разбора X.509 в `quinn-proto`, не запуском).
2. Точная длина ClientHello с RPK, ALPN и транспортными параметрами QUIC; число Initial-пакетов; поведение при
   Retry.
3. Как прочитать согласованную группу в T1: `quinn` её не отдаёт (поле есть только под test-feature
   `__rustls-post-quantum-test`, `quinn-proto/src/crypto/rustls.rs`). Поскольку провайдер содержит одну группу,
   иное согласование невозможно по построению; для теста T-KX1 в T1 — либо эта test-feature, либо тест той же
   функции сборки конфигурации через `rustls::quic::{ClientConnection, ServerConnection}` без `quinn`. Выбрать
   при реализации.
4. Удаляют ли `rustls` и `quinn` прежние ключи сразу после обновления (условие G4b); у `quinn` прежние ключи живут в
   `prev_crypto` до подтверждения — длительность измерить.
5. Поведение `refresh_traffic_keys()` у `tokio-rustls` (KeyUpdate уходит только при следующей записи).
6. Уравнение проверки Ed25519 в AWS-LC и отказ при `S >= L` (T-ED1).
7. Стоимость гибридного обмена и подписи на сервере на запрос, пропускная способность AES-GCM и ChaCha20 на целевых
   CPU, частота автоматических KeyUpdate при реальной нагрузке — требуют измерения.
8. Наблюдаемость CP-12: закрытие TCP без alert против `handshake_failure` — согласовать с потоком транспортов
   (различимость для зондирующего).
9. Префикс DER SPKI Ed25519 (CP-16) — сверить с `public_key()` ключа `aws-lc-rs`; покрытие RPK тестами самого
   `rustls` (каталог `tests` в опубликованном пакете отсутствует).

## 6. Источники

- RFC 8446 §2.3, §4.1.4, §4.2 (таблица расширений), §4.4.2, §4.6.2, §4.6.3, §5.5, §7.2, §8, App. E.1, E.1.2, E.1.3,
  E.1.5, E.2 — `…/scratchpad/rfc/rfc8446.txt`.
- RFC 9846 §1.2, §4.2.8 (повтор доли ключа), §4.7.3, §5.5, App. F.1 — `https://www.rfc-editor.org/rfc/rfc9846.txt`
  (загружен 2026-11-14 в `…/scratchpad/rfc9846dl/`).
- RFC 10024 целиком — `…/scratchpad/rfc/rfc10024.txt`.
- RFC 7250 §3, §4.1–4.4, §6 — `…/scratchpad/rfc/rfc7250.txt`.
- RFC 9001 §4.1.1, §4.1.2, §4.3, §4.4, §4.5, §4.7, §5.7, §6, §6.6, §8.1 — `…/scratchpad/rfc/rfc9001.txt`.
- RFC 8032 §5.1.7, §8.1–8.6 — `…/scratchpad/rfc/rfc8032.txt`.
- `rustls` 0.23.46 (`$REG/rustls-0.23.46/`): `Cargo.toml`; `src/record_layer.rs`; `src/common_state.rs`
  (`write_plaintext`, `TemperCounters`); `src/conn.rs` (`refresh_traffic_keys`); `src/tls13/key_schedule.rs`;
  `src/crypto/aws_lc_rs/{mod.rs, tls13.rs, sign.rs, pq/mod.rs}`; `src/crypto/ring/mod.rs`; `src/verify.rs`;
  `src/webpki/verify.rs`; `src/client/{hs.rs, tls13.rs, builder.rs, client_conn.rs, handy.rs}`;
  `src/server/{hs.rs, tls13.rs, builder.rs, server_conn.rs, handy.rs}`; `src/compress.rs`; `README.md`.
- `quinn-proto` 0.11.19: `src/connection/mod.rs` (`key_phase_size`, `force_key_update`, `update_keys`,
  `KEY_UPDATE_MARGIN`, лимит целостности), `src/connection/packet_builder.rs`, `src/crypto/rustls.rs`
  (`QuicServerConfig`, `initial_suite_from_provider`, `peer_identity`, `HandshakeData`).
- `quinn` 0.11.12: `src/connection.rs`, `src/incoming.rs`; `aws-lc-rs` 1.19.0: `Cargo.toml`, `src/ed25519.rs`.
- RustSec (`…/scratchpad/r6/advdb/advisory-db/crates/`): `rustls/RUSTSEC-2026-{0285,0346,0347,0348,0349}`;
  `rustls-webpki/RUSTSEC-2026-{0049,0098,0099,0104,0382}`; `aws-lc-sys/RUSTSEC-2026-{0044..0048}`;
  `quinn-proto/RUSTSEC-2026-{0037,0185,0338..0343}`; `ring/RUSTSEC-2025-{0007,0009,0010}`.
- Проектные: `docs/research/04-cryptography.md` (R4, ссылки [33], [35], [40], [49]),
  `docs/architecture/reviews/REVIEW_CRYPTO.md`, `ARCHITECTURE_DECISIONS.md`, `docs/architecture/ARCHITECTURE.md`,
  `docs/threat-model/THREAT_MODEL.md`.
