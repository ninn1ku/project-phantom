# PROJECT PHANTOM — исследование R3: транспортные технологии для туннеля

**Поток:** R3 (Network Engineering). **Этап:** 1 — техническое исследование, кода нет.
**Дата проверки источников:** 2026-11-10 и 2026-11-11 (у каждого источника в списке указан свой день).
**Способ проверки:** веб-поиск с выдержками из первоисточников. Прямое открытие `datatracker.ietf.org` и `www.rfc-editor.org` из рабочей среды было заблокировано сетевой политикой, поэтому тексты RFC целиком не читались — проверены только те положения, которые вернул поиск. Всё остальное помечено **[Не проверено]** и продублировано в разделе 13.

**Метки:** **[Факт]** — подтверждено источником [n]; **[Вывод]** — рассуждение автора на основе фактов; **[Предположение]** — гипотеза, требующая измерения; **[Не проверено]** — знание из памяти, источником в этой сессии не подтверждено.

## Резюме

1. **Основной транспорт — QUIC с DATAGRAM (RFC 9221).** Ненадёжные датаграммы внутри зашифрованного соединения с congestion control дают то, что нужно для переноса IP-пакетов: нет head-of-line blocking и нет вложенной повторной передачи [2][4]. Потоки QUIC оставляем для control plane.
2. **Резервный транспорт — TLS 1.3 поверх TCP (порт 443).** Он неизбежно даёт «TCP-over-TCP» для внутренних TCP-потоков: два congestion control и два механизма восстановления потерь мешают друг другу [41][4]. Это режим «работает везде, но хуже», а не равноценная альтернатива.
3. **MTU — главный практический риск.** QUIC гарантирует лишь 1200 байт UDP payload [1]; DATAGRAM не фрагментируется [2]; CONNECT-IP требует, чтобы туннель переносил 1280 байт для IPv6, иначе туннель должен быть разорван [5]. Нужны фиксированный консервативный MTU на tun, DPLPMTUD (RFC 8899) на внешнем пути и MSS clamping.
4. **Стоимость QUIC в userspace выше TCP+TLS**, особенно на приёме и на быстрых каналах (до −45,2 % data rate в измерениях 2024 г. [27]); с GSO и редкими ACK разрыв на отправке сокращается до единиц процентов [28]. QUIC в ядре Linux в mainline не принят (серия патчей v12, май–июнь 2026) [32].
5. **Статусы на 2026-11:** ECH — RFC 9849 (март 2026) [13]; hybrid key exchange — RFC 9954 [15]; X25519MLKEM768 — RFC 10024 (август 2026, Proposed Standard; исправлено при сверке, см. «Поправки при сверке»); Multipath QUIC — draft-21, передан в RFC Editor, номера RFC нет [11][12]; Happy Eyeballs v3 — draft-04 (июль 2026) [10].
6. **MASQUE (CONNECT-UDP RFC 9298, CONNECT-IP RFC 9484) — готовый стандартный формат «IP-туннель в HTTP/3 с откатом на HTTP/2»** [3][4][5]; его использует Cloudflare WARP, в том числе с TCP-fallback [33][34]. Заимствовать стоит модель (datagram + capsule fallback), а полный стек HTTP/3 для прототипа — предмет решения архитектора.
7. **Fallback UDP→TCP должен быть гонкой с форой, а не последовательным тайм-аутом,** с памятью о «сломанном UDP» по каждой сети, экспоненциальным backoff повторных проб и сбросом при смене сети — так устроены Chromium [36][37] и curl [38]. Без гистерезиса неизбежен flapping.
8. **0-RTT не использовать для данных туннеля в прототипе:** early data воспроизводимы (replay), а защита от повтора лишь снижает риск [8][7].

---

## 1. Постановка: что требуется от несущего транспорта

**[Вывод]** Туннель переносит IP-пакеты (L3) пользователя. Внутри уже работают собственные транспортные протоколы (TCP, QUIC, RTP) со своей надёжностью и congestion control. Идеальный несущий транспорт поэтому: (а) доставляет пакеты **ненадёжно и без упорядочивания**, (б) шифрует и аутентифицирует, (в) имеет congestion control на уровне туннеля либо доказуемо не нуждается в нём, (г) переживает смену сети и NAT rebinding, (д) проходит через сети, где UDP режут. Требования (а) и (д) противоречат друг другу — отсюда два транспорта и раздел 10 про fallback.

## 2. TCP

1. **Модель.** **[Не проверено]** Надёжный упорядоченный байтовый поток; границ сообщений нет, поэтому IP-пакеты нужно кадрировать (length prefix). Один потерянный сегмент задерживает все последующие данные — head-of-line (HoL) blocking на всё соединение.
2. **Криптография.** Нет; нужна TLS 1.3 поверх (раздел 5).
3. **Установление соединения.** **[Не проверено]** 1 RTT на TCP handshake + 1 RTT на TLS 1.3 = 2 RTT до первых данных приложения; TCP Fast Open сокращает это, но плохо проходит middlebox'ы. Точные формулировки RFC в этой сессии не проверялись.
4. **CPU/RAM.** **[Факт]** В измерениях Fastly TLS 1.3 поверх TCP взят за базу, причём без аппаратного offload с обеих сторон [28]. **[Факт]** На быстрых каналах стек TCP+TLS+HTTP/2 опережает QUIC+HTTP/3 из-за меньшей стоимости обработки на приёмнике [27]. **[Не проверено]** kTLS и TSO/GRO дают TCP дополнительное преимущество на сервере; цифр с источником нет.
5. **Вложенность.** **[Факт]** При TCP-туннеле одновременно работают два congestion control — сквозной и туннельный — и мешают друг другу; когда RTO сквозного TCP короче туннельного, сквозной TCP ретранслирует быстрее, чем туннель успевает обработать («TCP meltdown») [41]. **[Факт]** Классическое описание проблемы — заметка O. Titz «Why TCP Over TCP Is A Bad Idea» [42]. **[Факт]** RFC 9298 отдельно отмечает: если HTTP-соединение идёт поверх TCP, вложенное восстановление потерь снижает производительность, так как оба уровня могут независимо ретранслировать одни и те же данные [4].
6. **Потери и смена сети.** **[Не проверено]** Соединение привязано к 4-tuple; смена IP (Wi‑Fi ↔ LTE) рвёт соединение, нужна переустановка и возобновление сессии на уровне протокола туннеля. MPTCP решает это, но требует поддержки с обеих сторон и плохо проходит middlebox'ы.
7. **Ограничения.** **[Вывод]** MTU для TCP-транспорта не является жёстким ограничением (поток сегментируется сам), но внутренним TCP-потокам всё равно нужен MSS clamping, иначе один внутренний пакет размажется на два внешних сегмента (раздел 8).
8. **Масштабирование.** **[Не проверено]** Зрелое: accept-очереди, SO_REUSEPORT, L4-балансировщики, offload в NIC.
9. **Зрелость.** Максимальная.
10. **Компромисс.** **[Вывод]** Лучшая проходимость (TCP/443 открыт почти везде) ценой HoL blocking и meltdown-эффектов. Роль в PHANTOM — только fallback.

## 3. UDP (без надстройки)

1. **Модель.** **[Не проверено]** Датаграммы без соединения, надёжности, порядка и congestion control. Идеально соответствует семантике IP-пакета; так работает WireGuard.
2. **Криптография.** Нет; собственный AEAD-протокол поверх UDP означает собственные handshake, key update, защиту от replay и amplification — то есть повторение существенной части QUIC.
3. **Задержки.** **[Вывод]** Время установления определяется собственным handshake (1 RTT достижим).
4. **CPU.** **[Факт]** UDP GSO появился в Linux 4.18, включается опцией сокета `UDP_SEGMENT`, в одном вызове батчится до 64 сегментов; `sendmmsg()` дополнительно сокращает число системных вызовов [29]. **[Факт]** В wireguard-go (userspace) UDP segmentation offload и receive coalescing на TUN позволили превысить 10 Гбит/с на bare-metal Linux [30]; для UDP-потоков поверх туннеля заявлен рост пропускной способности в 4 раза (Tailscale ≥ 1.54, Linux ≥ 6.2) [31]. **[Вывод]** Узкое место userspace-туннеля — число системных вызовов и проходов стека на пакет, а не криптография; батчинг обязателен при любом выборе транспорта.
5. **Вложенность.** **[Вывод]** Вложенных ретрансляций нет — главный плюс.
6. **NAT.** **[Факт]** Middlebox'ы создают состояние для UDP по первому пакету и держат его существенно меньше, чем для TCP; RFC 9308 ссылается на исследование 2010 г., по которому NAT binding может истечь после 30 секунд простоя [7].
7. **Ограничения.** **[Факт]** Часть сетей блокирует или ограничивает UDP: по данным Google (2017) QUIC успешно работал у 95,3 % клиентов, у 4,4 % был заблокирован или имел проблемы с размером пакета, у 0,3 % работал плохо (в основном rate limiting UDP) [25]. **[Вывод]** Данные старые; актуальная доля — в разделе 13.
8–10. **[Вывод]** «Голый» UDP со своим протоколом — зрелый подход (WireGuard), но для PHANTOM QUIC даёт то же плюс готовые handshake/TLS 1.3, миграцию и congestion control, поэтому отдельный UDP-протокол не оправдан, пока QUIC не упрётся в производительность.

## 4. QUIC (RFC 9000/9001/9002) и расширения

### 4.1. Модель и что она даёт туннелю

- **[Факт]** DATAGRAM-кадры (RFC 9221) не ретранслируются при потере, но являются ack-eliciting и подчиняются congestion control соединения; типы кадра 0x30 (без поля Length, данные до конца пакета) и 0x31 (с Length) [2].
- **[Факт]** Поддержка объявляется transport parameter `max_datagram_frame_size` (0x20); рекомендуется значение 65535; фактический предел задаётся `max_udp_payload_size` и MTU пути; DATAGRAM-кадр нельзя фрагментировать [2].
- **[Вывод]** Для туннеля: data plane — DATAGRAM (1 IP-пакет = 1 кадр), control plane (аутентификация, выдача адресов, keepalive, rekey-сигналы) — надёжные потоки. Потоки QUIC не блокируют друг друга, но для IP-пакетов они всё равно избыточны: возвращают повторную передачу и порядок внутри потока.

### 4.2. Криптография

**[Не проверено]** TLS 1.3 handshake встроен (RFC 9001), шифруются payload и большая часть заголовка; AEAD tag 16 байт на пакет. **[Вывод]** Отдельного слоя шифрования туннелю не нужно; вопрос второго слоя — в зоне потока по криптографии.

### 4.3. Установление соединения и 0-RTT

- **[Не проверено]** 1 RTT до данных приложения при новом соединении, 0 RTT при возобновлении; против 2 RTT у TCP+TLS 1.3.
- **[Факт]** Early data (0-RTT) воспроизводимы; TLS требует стратегий обнаружения повтора, но они снижают риск, а не устраняют его; повтор возможен, если early data принимают несколько экземпляров сервера [8]. **[Факт]** RFC 9308 советует включать 0-RTT осознанно из-за риска replay [7].
- **[Вывод]** В туннеле повтор 0-RTT-данных = повторная инъекция пользовательских IP-пакетов и повтор control-сообщений. Для прототипа 0-RTT выключить; позже — разрешить только для идемпотентного control plane.

### 4.4. Производительность и CPU

- **[Факт]** На быстрых каналах QUIC+HTTP/3 теряет до 45,2 % data rate относительно TCP+TLS+HTTP/2; причина — стоимость обработки на приёмнике (много пакетов, ACK в userspace); эффект растёт с полосой; авторы рекомендуют UDP GRO и QUIC-friendly offload [27].
- **[Факт]** Fastly (quicly): после GSO-пачек по 10 пакетов — 425 Мбит/с (на 8 % медленнее TLS 1.3/TCP) при пакетах 1350 байт и 464 Мбит/с (на 1 % быстрее) при 1460 байт; только снижение частоты ACK с «каждые 2» до «каждые 10» пакетов дало 240 Мбит/с; аппаратный offload был выключен у обоих [28].
- **[Факт]** Пейсинг каждого пакета в userspace мешает батчингу отправки [29].
- **[Факт]** QUIC в ядре Linux (сокет `IPPROTO_QUIC`) — серия патчей net-next v12 на рецензии (конец мая — июнь 2026), в mainline не принят [32].
- **[Не проверено]** Оценка Google «QUIC изначально стоил ~3,5× CPU против TLS/TCP, после оптимизаций ~2×» — в этой сессии источником не подтверждена.
- **[Вывод]** Для PHANTOM: GSO/GRO и `sendmmsg`/`recvmmsg` закладывать в архитектуру I/O сразу; частоту ACK снижать (draft-ietf-quic-ack-frequency-14, февраль 2026 [23]) — в туннеле каждый DATAGRAM ack-eliciting, и ACK-нагрузка заметна [43].

### 4.5. Миграция соединения, NAT rebinding, keepalive

- **[Факт]** Path validation проверяет достижимость после смены адреса; при неудаче endpoint обязан вернуться к последнему проверенному адресу peer [1].
- **[Факт]** После успешной проверки нового пути сбрасываются состояние congestion control и оценки RTT; при смене только UDP-порта их допустимо сохранить [1].
- **[Факт]** До завершения path validation на новый адрес нельзя отправлять больше минимального congestion window непробных пакетов; пробными являются только PATH_CHALLENGE, PATH_RESPONSE, NEW_CONNECTION_ID и PADDING [1].
- **[Факт]** NAT rebinding маловероятен, если по старому пути недавно приходили пакеты, и редок на IPv6 [1].
- **[Факт]** Keepalive — PING-кадры, интервал выбирает приложение [7]; ориентир для UDP NAT — 30 секунд простоя [7].
- **[Вывод]** Миграция — главное преимущество QUIC для мобильного клиента: смена Wi‑Fi ↔ LTE не требует нового handshake. Цена: congestion window начинается заново, а на время проверки пути трафик ограничен. Параметры `max_idle_timeout`, `disable_active_migration`, preferred address — **[Не проверено]** (раздел 13).

### 4.6. Path MTU

- **[Факт]** Клиент обязан расширять UDP-датаграммы с Initial-пакетами минимум до 1200 байт; сервер отбрасывает Initial в меньшей датаграмме; это и проверка пути, и ограничение amplification [1].
- **[Факт]** DPLPMTUD (RFC 8899) позволяет транспорту поверх датаграмм находить размер пакета без ICMP и обнаруживать black hole, когда Packet Too Big не доходят; раздел 6.3 RFC 8899 посвящён QUIC [6].
- **[Факт]** quinn реализует DPLPMTUD (`MtuDiscoveryConfig`) [48]; s2n-quic заявляет Path MTU discovery, GSO, pacing [50].

### 4.7. Multipath QUIC

- **[Факт]** draft-ietf-quic-multipath-21 (март 2026), Standards Track; расширение QUIC v1 для одновременного использования нескольких путей, новый transport parameter `initial_max_path_id` [11]. В трекере IANA — версия 21, статус «RFC-Ed-ACK», изменение 2026-04-07 [12]. Номера RFC поиск не показал.
- **[Факт]** Реализация на Rust: noq (n0, начинался как fork quinn) заявляет полную реализацию QUIC Multipath и стал транспортом iroh с v0.97.0 [47]. Есть ли multipath в upstream quinn — поиск не показал.
- **[Вывод]** Для прототипа multipath не нужен: обычной миграции достаточно. Закладывать на будущее только то, что не мешает (идентификаторы путей в логах/метриках).

### 4.8. Уязвимости и ограничения

- **[Факт]** Anti-amplification: до проверки адреса endpoint отправляет не более чем втрое больше данных, чем получил; сервер может потребовать проверку адреса пакетом Retry с токеном [1].
- **[Факт]** Optimistic ACK и некорректные ACK-диапазоны: CVE-2025-4820 и CVE-2025-4821 в Cloudflare quiche (исправлено в 0.24.4) [44].
- **[Факт]** Server preferred address можно использовать для эксфильтрации данных (QUIC-Exfil) [51]; handshake flooding до проверки адреса — отдельное направление исследований (QFAM) [52].
- **[Вывод]** Для сервера PHANTOM: Retry включать под нагрузкой, лимитировать число незавершённых handshake на адрес/префикс, не использовать preferred address без необходимости.

### 4.9. Масштабирование, зрелость

- **[Не проверено]** Маршрутизация по connection ID (QUIC-LB), SO_REUSEPORT + eBPF — раздел 13.
- **[Факт]** Реализации на Rust: quinn [48], Cloudflare quiche и tokio-quiche (async-обёртка, open source с конца 2025 г.) [49], AWS s2n-quic [50], noq [47].
- **[Факт]** Расширения рядом со стандартом: RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-10, август 2026, подан в IESG) [22].

## 5. TLS 1.3 (RFC 8446), ECH, PQ-гибрид

- **Модель.** **[Не проверено]** Защищённый канал поверх надёжного потока; запись (record) — единица шифрования.
- **0-RTT.** **[Факт]** См. 4.3: early data воспроизводимы; сервер не может выборочно отклонять early data на уровне TLS [8].
- **ECH.** **[Факт]** RFC 9849 «TLS Encrypted Client Hello», Proposed Standard, опубликован 2026-03-03; сопутствующий RFC 9848 — доставка конфигурации ECH через DNS SVCB/HTTPS [13]. **[Вывод]** ECH скрывает SNI, но требует получения ключа через DNS (обычно зашифрованный) и сам по себе заметен. Уровень развёртывания и блокировок — раздел 13.
- **PQ-гибрид.** **[Факт]** «Hybrid key exchange in TLS 1.3» одобрен IESG в сентябре 2025 г. и стал RFC 9954 (Informational) [15]. **[Факт]** X25519MLKEM768 определён в draft-ietf-tls-ecdhe-mlkem (версия -05, май 2026), codepoint 4588 (0x11EC), поле Recommended = N [14]; RFC нет. **[Не проверено]** Размер client share ≈ 1216 байт (1184 ML-KEM + 32 X25519) — выдержки поиска противоречивы; из этого следует, что ClientHello не помещается в один пакет/одну Initial-датаграмму.
- **[Вывод]** PQ-гибрид включать через библиотеку TLS (rustls), не изобретая своего; учесть рост первого полёта handshake при расчёте anti-amplification и тайм-аутов гонки.

## 6. HTTP/2, HTTP/3, CONNECT, extended CONNECT, WebSocket

- **HTTP/2 (RFC 9113).** **[Не проверено]** Мультиплексирование потоков поверх одного TCP — HoL blocking на уровне TCP сохраняется для всех потоков. **[Факт]** Протокол уязвим к классу атак на сброс потоков: Rapid Reset (CVE-2023-44487; по данным Cloudflare пик чуть выше 201 млн запросов/с) [46] и MadeYouReset (CVE-2025-8671, CVSS 7,5; обходит защиты от Rapid Reset) [45].
- **HTTP/3 (RFC 9114).** **[Не проверено]** HTTP поверх QUIC; каждый запрос — свой поток, HoL между потоками нет.
- **CONNECT / extended CONNECT.** **[Факт]** MASQUE использует extended CONNECT в HTTP/2 и HTTP/3 и HTTP Upgrade в HTTP/1.x [4]. **[Факт]** «Template-Driven HTTP CONNECT Proxying for TCP» — draft-ietf-httpbis-connect-tcp, активный документ httpbis (версия -13, август 2026), RFC нет [24].
- **WebSocket (RFC 6455).** **[Не проверено]** Кадрирование сообщений поверх TCP/TLS, обязательное маскирование client→server, overhead 2–14 байт на кадр; поверх HTTP/2 — RFC 8441, поверх HTTP/3 — RFC 9220.
- **[Вывод]** Для fallback-транспорта PHANTOM достаточно TLS 1.3/TCP со своим кадрированием. HTTP/2 extended CONNECT или WebSocket дают маскировку под обычный веб-трафик и проход через HTTP-прокси/CDN ценой дополнительного слоя, flow control HTTP/2 и поверхности атак HTTP/2. Выбор — вопрос к архитектору (раздел 12).

## 7. MASQUE

- **[Факт]** RFC 9297: HTTP Datagram в HTTP/3 = QUIC DATAGRAM с префиксом Quarter Stream ID (ID клиентского bidi-потока, делённый на 4; максимум 2^60−1). В HTTP/2 и HTTP/1.1 ненадёжной доставки нет — используется Capsule Protocol (TLV-капсулы, в т. ч. капсула DATAGRAM) внутри потока. Капсулы применимы и для надёжных control-сообщений, даже когда доступны HTTP/3 Datagrams [3].
- **[Факт]** RFC 9298 (CONNECT-UDP): при проксировании протокола с congestion control получаются минимум два вложенных контроллера; внешнее HTTP-соединение не должно отключать congestion control, если нет внеполосного знания, что внутренний трафик сам управляет перегрузкой [4].
- **[Факт]** RFC 9484 (CONNECT-IP): маршрутизаторы с IPv6 обязаны обеспечивать MTU туннельного линка не менее 1280 байт; если IPv6 идёт в QUIC DATAGRAM и MTU QUIC этого не позволяет, endpoint обязан прервать поток IP-proxying; слишком большой пакет следует отбросить и ответить ICMP Packet Too Big [5].
- **[Факт]** Текущие документы WG (статусы по выдаче поиска): CONNECT-UDP Bind (draft-ietf-masque-connect-udp-listen, -16, август 2026; подавался в IESG) [16]; CONNECT-ETHERNET (-18, октябрь 2026) [17]; QUIC-aware proxy (draft-ietf-masque-quic-proxy-08, март 2026, Experimental) [18]; DNS и PREF64 для CONNECT-IP (-06, апрель 2026) [19]; HTTP Datagram Compression (-00, июнь 2026) — уменьшает per-packet overhead CONNECT-IP [20]; ECN/DSCP для CONNECT-UDP (июль 2026) [21].
- **[Факт]** Cloudflare перевёл WARP на MASQUE (туннель поверх HTTP/3, мотивы: вид обычного HTTPS, стандартный порт, FIPS-совместимые наборы шифров) [33] и добавил TCP-fallback на HTTP/2 для сетей, где HTTP/3 блокируется [34]. **[Факт]** Apple документирует, что iCloud Private Relay использует QUIC на порту 443 с TLS 1.3 [35]; fallback на HTTP/2 описан только во вторичных источниках.
- **[Факт]** В многозвенных MASQUE-туннелях каждый DATAGRAM-кадр должен быть подтверждён, что создаёт ACK-overhead; предложен non-ack-eliciting DATAGRAM [43].

## 8. MTU, overhead и вложенные транспорты

### 8.1. Расчёт overhead (внешний Ethernet MTU 1500)

**[Вывод]** Размеры полей заголовков QUIC и TLS взяты из памяти (**[Не проверено]**, раздел 13); арифметика — авторская.

| Слой | QUIC DATAGRAM, свой протокол | MASQUE CONNECT-IP (HTTP/3) | TLS 1.3 / TCP |
|---|---|---|---|
| IP внешний | 20 (IPv4) / 40 (IPv6) | 20 / 40 | 20 / 40 |
| UDP / TCP | 8 | 8 | 20 (+12 с timestamps) |
| Заголовок | short header: 1 + DCID (0–20, далее 8) + PN (1–4) | то же | TLS record header 5 |
| Кадрирование | DATAGRAM type 1 (0x30, без Length) | 1 + Quarter Stream ID ≥1 + Context ID 1 | длина пакета 2 + content type 1 |
| AEAD tag | 16 | 16 | 16 |
| **Итого сверх IP-пакета (IPv4, худший PN)** | **58** | **60** | **64–76** на пакет, если запись = пакет |
| **Внутренний MTU при 1500** | **1442** (IPv4) / 1422 (IPv6) | 1440 / 1420 | не ограничен жёстко |

- **[Вывод]** При минимально гарантированном QUIC пути (UDP payload 1200) в DATAGRAM помещается внутренний пакет ≈ 1170 байт — **меньше 1280**. Значит, на путях, где проходит только 1200, IPv6 внутри туннеля по правилам RFC 9484 нести нельзя [5]. Чтобы нести 1280 байт, нужен UDP payload ≈ 1310–1312, то есть внешний IP-пакет ≈ 1340 (IPv4) / 1360 (IPv6).
- **[Вывод]** Практическая схема: tun MTU фиксировать консервативно (ориентир 1280–1380, точное значение — решение архитектора), DPLPMTUD на внешнем пути использовать как проверку «проходит ли нужный размер», а не для динамической смены MTU интерфейса; при провале — немедленный переход на TCP-транспорт, где жёсткого предела нет.
- **[Вывод]** MSS clamping для внутренних TCP SYN (MSS = tun MTU − 40 для IPv4, − 60 для IPv6) обязателен в обоих транспортах: ICMP PTB внутри туннеля часто не доходит до отправителя (PMTUD black hole) [6].
- **[Вывод]** В TCP-транспорте одна TLS-запись на IP-пакет проще и не добавляет задержки; объединение нескольких пакетов в запись экономит 22 байта на пакет, но усиливает HoL.

### 8.2. Вложенный congestion control и HoL

- **[Факт]** QUIC-в-QUIC (внутренний QUIC пользователя поверх DATAGRAM): два контроллера, повторных передач на внешнем уровне нет [4][2]. **[Вывод]** Это приемлемо: внешний контроллер лишь ограничивает скорость, потери внутренний транспорт видит напрямую.
- **[Факт]** TCP-в-TCP: вложены и контроллеры, и повторные передачи [41][4]. **[Вывод]** Смягчение: большие буферы не помогают; помогают ограничение очереди туннеля (drop-tail/AQM на входе в TCP-транспорт, чтобы внутренний TCP видел потери рано), `TCP_NODELAY`, BBR или иной контроллер, не завязанный на потери, — **[Предположение]**, требует измерений.
- **[Вывод]** Отключать congestion control на внешнем QUIC нельзя: туннель несёт и неконтролируемый трафик (UDP-флуд, DNS), а RFC 9298 прямо требует его сохранять без внеполосных гарантий [4].

## 9. Потери, смена сети, NAT — сводка

| Событие | QUIC/UDP | TLS/TCP |
|---|---|---|
| Потеря пакета | DATAGRAM теряется, внутренний транспорт восстанавливает сам [2] | внешний TCP ретранслирует, все пакеты ждут (HoL) [41] |
| NAT rebinding (смена порта) | path validation, CC можно сохранить [1] | **[Не проверено]** соединение рвётся |
| Wi‑Fi → LTE | миграция, CC и RTT сбрасываются [1] | **[Не проверено]** новое соединение + возобновление сессии |
| Простой | PING-keepalive; ориентир NAT 30 с [7] | **[Не проверено]** тайм-ауты NAT для TCP существенно длиннее |
| Блокировка UDP на пути | handshake не проходит → fallback [7] | работает |

**[Вывод]** Keepalive для UDP-транспорта: ориентир 15–25 с при активной сессии — **[Предположение]**, компромисс с расходом батареи; значение сделать настраиваемым и адаптивным.

## 10. Дизайн fallback UDP/QUIC → TCP

### 10.1. Как это делают существующие системы

- **[Факт] Happy Eyeballs v2 (RFC 8305):** Connection Attempt Delay — рекомендуемое значение 250 мс, рекомендуемый минимум 100 мс, жёсткий минимум 10 мс между попытками, рекомендуемый максимум 2 с; Resolution Delay 50 мс [9].
- **[Факт] Happy Eyeballs v3 (draft-ietf-happy-happyeyeballs-v3-04, 2026-07-02, Standards Track):** главное изменение — поддержка SVCB/HTTPS-записей (ALPN, ключи ECH, address hints); порядок запросов SVCB/HTTPS → AAAA → A; есть раздел про ALPN [10]. Детали гонки QUIC против TCP — раздел 13.
- **[Факт] Chromium:** при наличии QUIC-варианта основной (TCP) job блокируется, QUIC получает фору; задержка вычисляется из srtt и ограничена сверху (в найденном снимке кода `kMaxDelayTimeForMainJobSecs = 3`); TCP job возобновляется, когда QUIC job провалился или истекла задержка [37]. Альтернативный сервис, признанный сломанным, блокируется на 300 с с удвоением при повторных сбоях (сдвиг ограничен 18, порядка двух суток); при смене default network отметки «broken» сбрасываются [36].
- **[Факт] curl:** `--happy-eyeballs-timeout-ms` — жёсткий тайм-аут, после которого открывается TLS/TCP для HTTP/2 или HTTP/1.1; мягкий — половина, срабатывает, если от сервера по HTTP/3 не пришло вообще ничего; по умолчанию 200 мс и 100 мс [38]. В 8.20.0 была регрессия: при молча отбрасываемом UDP fallback происходил примерно через секунду, так как таймер не перевзводился, а `EAGAIN` считался «данные были» [39].
- **[Факт] Firefox:** есть открытые отчёты о зависаниях при блокировке UDP/443 и о том, что 0-RTT-соединение HTTP/3 при заблокированном UDP не откатывается корректно [40].
- **[Факт] Cloudflare WARP:** MASQUE-туннель откатывается на HTTP/2 (TCP), когда обнаружена блокировка HTTP/3 [34]; метод обнаружения в найденных источниках не раскрыт.
- **[Факт] RFC 9308:** приложение над QUIC должно либо принять отказ связи в сетях без UDP, либо откатиться на другой протокол; откат должен сохранять защиту уровня TLS 1.3, чтобы не стать downgrade-атакой [7].

### 10.2. Рекомендуемая схема для PHANTOM

**[Вывод]** Всё ниже — проектное предложение; числа — стартовые значения для измерений, не нормы.

1. **Гонка с форой, не последовательный тайм-аут.** Старт QUIC; TCP-попытка стартует через задержку `D`. Старт: `D = 250 мс` (значение RFC 8305 [9]), при известном RTT сети — `D ≈ max(100 мс, 2·srtt)`, потолок 2–3 с (по образцу Chromium [37]). Побеждает первый завершивший **аутентифицированный** handshake.
2. **Критерий «UDP недоступен» — отсутствие любого ответа, а не медленный ответ.** Мягкий/жёсткий тайм-ауты по образцу curl [38]: если от сервера пришёл хоть один валидный QUIC-пакет, TCP-фору продлить.
3. **Память по сети.** Результат («UDP работает» / «UDP сломан») кешировать по ключу сети (тип интерфейса + идентификатор сети/шлюза). «Сломан» — на 5 мин с удвоением до потолка (по образцу Chromium [36]; потолок для VPN разумно меньше — часы, не сутки). При смене сети отметку не применять.
4. **Black hole посреди сессии.** Отдельный от handshake случай: N подряд PTO без единого подтверждения при живом TCP-канале до того же сервера → переключение. Перед этим — проба уменьшенным размером пакета, чтобы отличить MTU black hole от блокировки UDP [6].
5. **Возврат на QUIC (upgrade) — только с гистерезисом.** Фоновая проба QUIC по backoff из п. 3; переключаться обратно после K успешных проб подряд и минимального времени пребывания на TCP (ориентир: десятки секунд). Переключение — make-before-break: новый транспорт поднят и проверен до снятия старого.
6. **Анти-flapping.** Лимит переключений в единицу времени; после превышения — закрепиться на TCP до смены сети. Ложные срабатывания от единичных потерь исключаются тем, что решение принимается по handshake/PTO-сериям, а не по потерям DATAGRAM.
7. **Единый сеанс над транспортами.** Идентификатор сессии и внутренние адреса должны переживать смену транспорта, иначе каждое переключение рвёт пользовательские соединения. Это требование к протоколу, не к транспорту.
8. **Безопасность.** Оба транспорта — одинаковая аутентификация и TLS 1.3 [7]; активный противник может принудить к TCP, блокируя UDP, — это снижение производительности, но не защиты. 0-RTT в гонке не использовать (ср. проблему Firefox [40]).
9. **MTU одинаков в обоих транспортах,** чтобы переключение не меняло MTU tun-интерфейса (раздел 8).

## 11. Зрелость и компромиссы — сводная таблица

| Технология | Статус стандарта | Роль в PHANTOM | Главный минус |
|---|---|---|---|
| TCP + TLS 1.3 | **[Не проверено]** RFC 9293 / RFC 8446 | fallback | TCP-over-TCP, HoL [41] |
| UDP (свой протокол) | — | не использовать | повторяет QUIC |
| QUIC v1 + DATAGRAM | RFC 9000 [1], RFC 9221 [2] | основной | CPU на приёме [27], UDP режут [25] |
| DPLPMTUD | RFC 8899 [6] | обязательно | — |
| Multipath QUIC | draft-21, в RFC Editor [11][12] | позже | не RFC, мало реализаций |
| 0-RTT | часть TLS 1.3 / QUIC | выключено | replay [8] |
| ECH | RFC 9849 [13] | опция | зависит от DNS |
| X25519MLKEM768 | RFC 10024 (август 2026); рамка — RFC 9954 [15] | включить через TLS-библиотеку | большой ClientHello |
| HTTP/3 + MASQUE CONNECT-IP | RFC 9297/9298/9484 [3][4][5] | образец формата | сложность стека HTTP/3 |
| HTTP/2 extended CONNECT / WebSocket | **[Не проверено]** RFC 8441 / RFC 6455 | вариант fallback-оболочки | лишний слой, атаки на HTTP/2 [45][46] |

## 12. Что стоит заимствовать для PHANTOM / что не подходит

**Заимствовать**

- QUIC DATAGRAM как data plane, потоки как control plane [2]; модель RFC 9297 «датаграммы, а при отсутствии ненадёжной доставки — капсулы в потоке» как единая абстракция над обоими транспортами [3].
- Правило RFC 9484 о минимальном MTU 1280 и реакции ICMP PTB на слишком большие пакеты [5].
- Сохранение congestion control на внешнем соединении [4]; редкие ACK [23][28].
- GSO/GRO и батчинг системных вызовов с первого дня [29][30].
- Гонку с форой, кеш «broken» с backoff и сброс при смене сети из Chromium [36][37]; мягкий/жёсткий тайм-аут из curl [38].
- Retry и anti-amplification-лимит на сервере [1].

**Не подходит / отложить**

- TCP как основной транспорт [41][42]; 0-RTT для данных [8]; Multipath QUIC в прототипе [11].
- Отключение congestion control на туннеле [4]; динамическая смена MTU tun при переключении транспорта.
- Собственный UDP-протокол вместо QUIC — пока измерения не покажут, что QUIC недостаточен.
- Server preferred address без явной необходимости [51].

**Открытые вопросы к архитектору**

1. Полный HTTP/3 + MASQUE (совместимость, маскировка под веб) или «голый» QUIC с собственным ALPN (проще, меньше кода)?
2. Оболочка fallback: чистый TLS/TCP, HTTP/2 extended CONNECT или WebSocket?
3. Значение tun MTU и поддержка IPv6 внутри туннеля на путях с малым MTU.
4. Какая библиотека QUIC: quinn, quiche/tokio-quiche, s2n-quic, noq [47][48][49][50]?
5. Нужен ли «горячий резерв» (оба транспорта подняты одновременно) ради быстрого переключения ценой удвоения соединений на сервере?

## 13. Не удалось проверить

- **Доступ к первоисточникам.** `datatracker.ietf.org` и `www.rfc-editor.org` недоступны из среды (блокировка сетевой политикой). Все статусы и цитаты — по выдаче поиска; актуальное состояние документов в datatracker на день проверки напрямую не подтверждено.
- **Текущий IESG/RFC Editor-статус** Multipath QUIC (есть ли уже номер RFC), CONNECT-UDP Bind, ack-frequency, connect-tcp, ecdhe-mlkem.
- **RFC 9000:** `max_idle_timeout`, `disable_active_migration`, preferred address, точные форматы short header; RFC 9001 — размер AEAD tag и правила 0-RTT; RFC 9002 — PTO.
- **RFC 8446:** число RTT handshake, формат записи, правила anti-replay (single-use tickets, ClientHello recording).
- **RFC 9113 / 9114 / 8441 / 9220 / 6455:** положения приведены по памяти.
- **RFC 9298 §6 и RFC 9484 §10:** полный текст разделов про MTU и ECN (в т. ч. требование о padding QUIC Initial).
- **Цифры:** оценка CPU-стоимости QUIC у Google (3,5×/2×); численные результаты Cloudflare по `sendmmsg`+GSO; актуальная (2025–2026) доля сетей, блокирующих UDP/QUIC; измерения тайм-аутов NAT новее 2010 г.; расход памяти на соединение QUIC против TCP.
- **Развёртывание:** ECH (браузеры, блокировки), X25519MLKEM768 (доля трафика, значения по умолчанию в rustls), поддержка миграции соединений серверами и библиотеками, QUIC-LB.
- **Поведение:** Happy Eyeballs v3 в части гонки QUIC/TCP; актуальные константы Chromium (найденные снимки кода не привязаны к версии); настройки Firefox; метод обнаружения блокировки в Cloudflare WARP; fallback iCloud Private Relay на HTTP/2 (только вторичные источники).
- **Все числовые параметры раздела 10.2** — предложения, измерениями не подтверждены.

## 14. Источники

Формат: [n] — что это — URL — дата проверки. Источники 2026-11-10 получены через выдачу веб-поиска.

- [1] RFC 9000, QUIC: A UDP-Based Multiplexed and Secure Transport — https://datatracker.ietf.org/doc/html/rfc9000 ; https://www.rfc-editor.org/rfc/rfc9000.pdf — проверено 2026-11-10
- [2] RFC 9221, An Unreliable Datagram Extension to QUIC — https://rfc-editor.org/rfc/rfc9221.html — проверено 2026-11-10
- [3] RFC 9297, HTTP Datagrams and the Capsule Protocol — https://rfc-editor.org/rfc/rfc9297.html — проверено 2026-11-10
- [4] RFC 9298, Proxying UDP in HTTP — https://datatracker.ietf.org/doc/rfc9298/ — проверено 2026-11-10
- [5] RFC 9484, Proxying IP in HTTP — https://www.rfc-editor.org/rfc/rfc9484.pdf — проверено 2026-11-10
- [6] RFC 8899, Packetization Layer Path MTU Discovery for Datagram Transports — https://www.rfc-editor.org/rfc/rfc8899 — проверено 2026-11-10
- [7] RFC 9308, Applicability of the QUIC Transport Protocol — https://www.rfc-editor.org/rfc/rfc9308.html — проверено 2026-11-10
- [8] RFC 8470, Using Early Data in HTTP — https://rfc-editor.org/rfc/rfc8470.html — проверено 2026-11-10
- [9] RFC 8305, Happy Eyeballs Version 2 — https://www.rfc-editor.org/rfc/rfc8305.html — проверено 2026-11-10
- [10] draft-ietf-happy-happyeyeballs-v3-04 — https://www.ietf.org/archive/id/draft-ietf-happy-happyeyeballs-v3-04.html — проверено 2026-11-10
- [11] draft-ietf-quic-multipath-21, Multiple Paths for QUIC — https://datatracker.ietf.org/doc/html/draft-ietf-quic-multipath-21 — проверено 2026-11-10
- [12] IANA, Status of IETF Internet Drafts for 2026 — https://www.iana.org/performance/ietf-draft-status/2026 — проверено 2026-11-10
- [13] RFC 9849, TLS Encrypted Client Hello — https://datatracker.ietf.org/doc/rfc9849/ — проверено 2026-11-10
- [14] draft-ietf-tls-ecdhe-mlkem-05 — https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-05 — проверено 2026-11-10
- [15] draft-ietf-tls-hybrid-design (стал RFC 9954) — https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/ — проверено 2026-11-10
- [16] draft-ietf-masque-connect-udp-listen — https://datatracker.ietf.org/doc/draft-ietf-masque-connect-udp-listen/ — проверено 2026-11-10
- [17] draft-ietf-masque-connect-ethernet-18 — https://www.ietf.org/archive/id/draft-ietf-masque-connect-ethernet-18.html — проверено 2026-11-10
- [18] draft-ietf-masque-quic-proxy-08 — https://datatracker.ietf.org/doc/html/draft-ietf-masque-quic-proxy-08 — проверено 2026-11-10
- [19] draft-ietf-masque-connect-ip-dns-06 — https://www.ietf.org/archive/id/draft-ietf-masque-connect-ip-dns-06.html — проверено 2026-11-10
- [20] draft-ietf-masque-http-datagram-compression-00 — https://datatracker.ietf.org/doc/html/draft-ietf-masque-http-datagram-compression-00 — проверено 2026-11-10
- [21] draft-ietf-masque-connect-udp-ecn-dscp — https://datatracker.ietf.org/doc/draft-ietf-masque-connect-udp-ecn-dscp/ — проверено 2026-11-10
- [22] draft-ietf-quic-reliable-stream-reset-10 — https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-10 — проверено 2026-11-10
- [23] QUIC WG, список документов (в т. ч. ack-frequency-14) — https://datatracker.ietf.org/wg/quic/documents/ — проверено 2026-11-10
- [24] draft-ietf-httpbis-connect-tcp — https://datatracker.ietf.org/doc/draft-ietf-httpbis-connect-tcp — проверено 2026-11-10
- [25] Langley et al., слайды SIGCOMM 2017 «QUIC Design and Internet-Scale Deployment» — https://conferences.sigcomm.org/sigcomm/2017/files/program/ts-5-1-QUIC.pdf — проверено 2026-11-10
- [26] Langley et al., The QUIC Transport Protocol: Design and Internet-Scale Deployment, SIGCOMM 2017 — https://dl.acm.org/doi/10.1145/3098822.3098842 — проверено 2026-11-10
- [27] Zhang et al., QUIC is not Quick Enough over Fast Internet, WWW 2024 — https://arxiv.org/pdf/2310.09423 — проверено 2026-11-10
- [28] Fastly (K. Oku, J. Iyengar), QUIC vs TCP: computational efficiency — https://www.fastly.com/blog/measuring-quic-vs-tcp-computational-efficiency — проверено 2026-11-10
- [29] Cloudflare, Accelerating UDP packet transmission for QUIC — https://blog.cloudflare.com/accelerating-udp-packet-transmission-for-quic/ — проверено 2026-11-10
- [30] Tailscale, Surpassing 10Gb/s over Tailscale — https://tailscale.com/blog/more-throughput — проверено 2026-11-10
- [31] Tailscale, Increasing QUIC and UDP throughput — https://tailscale.com/blog/quic-udp-throughput — проверено 2026-11-10
- [32] Linux netdev, [PATCH net-next v12] QUIC infrastructure — https://lore.kernel.ime.usp.br/netdev/20260603103924.643f1ea4@kernel.org/t/ ; доклад netdevconf 0x1A — https://netdevconf.org/0x1A/sessions/talk/linux-quic-bringing-a-modern-secure-transport-into-the-kernel.html — проверено 2026-11-10
- [33] Cloudflare, Zero Trust WARP: tunneling with a MASQUE — https://blog.cloudflare.com/zero-trust-warp-with-a-masque/ — проверено 2026-11-10
- [34] Cloudflare One Client changelog (TCP fallback для MASQUE) — https://developers.cloudflare.com/changelog/product/cloudflare-one-client/3/ — проверено 2026-11-10
- [35] Apple, Prepare your network or web server for iCloud Private Relay — https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/ — проверено 2026-11-10
- [36] Chromium, net/http/broken_alternative_services.cc — https://chromium.googlesource.com/chromium/src/net/+/refs/heads/main/http/broken_alternative_services.cc — проверено 2026-11-10
- [37] Chromium, net/http/http_stream_factory_job_controller.cc — https://chromium.googlesource.com/chromium/src/+/master/net/http/http_stream_factory_job_controller.cc — проверено 2026-11-10
- [38] curl, HTTP/3 with curl — https://curl.se/docs/http3.html — проверено 2026-11-10
- [39] curl PR #23238, fall back from HTTP/3 at the happy eyeballs timeouts — https://github.com/curl/curl/pull/23238 — проверено 2026-11-10
- [40] Mozilla Bugzilla 1982072 и 1997737 — https://bugzilla.mozilla.org/show_bug.cgi?id=1982072 ; https://bugzilla.mozilla.org/show_bug.cgi?id=1997737 — проверено 2026-11-10
- [41] Honda et al., Understanding TCP over TCP, SPIE ITCom 2005 — https://www.lsnl.jp/~ohsaki/papers/Honda05_ITCom.pdf — проверено 2026-11-10
- [42] O. Titz, Why TCP Over TCP Is A Bad Idea — https://wiretapped.mirrorservice.org/network-security/cipe/docs/tcp-tcp.html — проверено 2026-11-10
- [43] Elmenhorst et al., MASQUE cascading ACKs (RWTH Aachen, 2025) — https://www.comsys.rwth-aachen.de/publication/2025/2025_elmenhorst_masque-cascading-acks/2025_elmenhorst_masque-cascading-acks.pdf — проверено 2026-11-10
- [44] Cloudflare, Defending QUIC from acknowledgement-based DDoS attacks — https://blog.cloudflare.com/defending-quic-from-acknowledgement-based-ddos-attacks — проверено 2026-11-10
- [45] MadeYouReset (CVE-2025-8671) — https://thehackernews.com/2025/08/new-http2-madeyoureset-vulnerability.html ; https://openwall.com/lists/oss-security/2025/08/13/6 — проверено 2026-11-10
- [46] APNIC Blog, HTTP/2 Rapid Reset: deconstructing the record-breaking attack — https://blog.apnic.net/2024/01/11/http-2-rapid-reset-deconstructing-the-record-breaking-attack/ — проверено 2026-11-10
- [47] n0, noq — https://www.iroh.computer/blog/noq-announcement ; https://github.com/n0-computer/noq — проверено 2026-11-10
- [48] quinn, MtuDiscoveryConfig — https://docs.rs/quinn/latest/quinn/struct.MtuDiscoveryConfig.html — проверено 2026-11-10
- [49] Cloudflare, tokio-quiche is now open-source — https://blog.cloudflare.com/async-quic-and-http-3-made-easy-tokio-quiche-is-now-open-source/ — проверено 2026-11-10
- [50] AWS s2n-quic — https://github.com/aws/s2n-quic — проверено 2026-11-10
- [51] QUIC-Exfil: Exploiting QUIC's Server Preferred Address Feature — https://arxiv.org/pdf/2505.05292 — проверено 2026-11-10
- [52] QFAM: Mitigating QUIC Handshake Flooding Attacks Through Crypto Challenges — https://arxiv.org/pdf/2412.08936 — проверено 2026-11-10

## Поправки при сверке (Lead Architect, 2026-11-11)

- Статус `X25519MLKEM768`: в исходной редакции отчёта указан Internet-Draft -05. По выдаче поиска (страницы `rfc-editor.org/rfc/rfc10024.pdf` и `datatracker.ietf.org/doc/rfc10024/`) документ опубликован как RFC 10024 «Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3», Proposed Standard, август 2026. Резюме и таблица раздела 11 исправлены; раздел 5 и источник [14] описывают состояние черновика и оставлены как есть.
- Требование RFC 9484 о переносе 1280 байт для IPv6 и разрыве туннеля при невозможности (резюме, п. 3) при сверке подтвердить не удалось: поиск не вернул текст раздела об MTU. До чтения первичного текста считать **[Не проверено]**.
