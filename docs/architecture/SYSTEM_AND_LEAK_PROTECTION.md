# Системная часть и защита от утечек PROJECT PHANTOM

**Версия:** 0.1 (проект ТЗ, поток Y1). **Дата:** 2026-11-14. **Статус:** предложение к `ARCHITECTURE.md` §6, §8, §9, ADR-0008.
**Закрывает (предлагает решения):** V-04…V-08 (`reviews/REVERIFY_HIGH.md`), S-05…S-09, S-11, S-12, S-14, S-16, S-17, S-18, S-20 (`reviews/REVIEW_SECURITY.md`). Кода нет; всё ниже — нормативный текст и эскизы.

## 0. Метод, источники, границы

- Метки: **[Факт]** — источник прочитан (номер в разделе «Источники»); **[Вывод]**; **[Предположение]**; **[Не проверено]**.
- Прочитаны исходники ядра Linux (ветка `master` на GitHub, ноябрь 2026): `net/netfilter/nf_tables_api.c`, `net/netfilter/nfnetlink.c`, `net/core/sock.c`, `net/core/rtnetlink.c`, `drivers/net/tun.c` [1–5]; `wg-quick/linux.bash` из `wireguard-tools` [6]; `config/firewalld.conf` из `firewalld` [7]; локально — `nftables.service`, `/etc/nftables.conf`, `docker.service`, `network-pre.target`, `uapi/linux/netfilter/*.h` контейнера [8]. Веб-запросов: 7.
- man-страницы `capabilities(7)`, `systemd.unit(5)`, wiki nftables в среде отсутствуют; утверждения о них — по исходникам ядра или помечены. Исходник `libnftables` и Docker не читались.
- Наборы правил (§4) проверены только `nft -c -f` (nftables 1.0.9) в scratch-каталоге; в систему ничего не применялось. Поведение ядра на этих правилах **не проверено**.
- Нормативные слова: «ДОЛЖЕН», «НЕ ДОЛЖЕН», «СЛЕДУЕТ».

## 1. Часть 0. Жизненный цикл kill switch

### 1.1. Что сломано (V-06) и какие факты меняют решение

- [Факт, 8] Debian/Ubuntu `nftables.service`: `DefaultDependencies=no`, `Wants=`/`Before=network-pre.target`, `Before=shutdown.target`, `Conflicts=shutdown.target`, `ExecStart=`/`ExecReload=nft -f /etc/nftables.conf` (файл начинается с `flush ruleset`), `ExecStop=nft flush ruleset`, `WantedBy=sysinit.target`.
- [Факт, 8] `docker.service`: `After=network-online.target … firewalld.service`, `Restart=always`. Docker стартует после сети, то есть после нашего unit; таблиц других семейств он не удаляет — **[Не проверено]** (исходник Docker не читался).
- [Факт, 7] firewalld по умолчанию: `FirewallBackend=nftables`, `CleanupOnExit=yes`, `FlushAllOnReload=yes`, `NftablesTableOwner=yes` («the generated nftables rule set will be owned exclusively by firewalld»). Что именно удаляет firewalld при старте и `reload` (только свои таблицы или весь ruleset) — **[Не проверено]**.
- **[Факт, 1] Ключевое: флаги таблицы `owner` и `persist` в nf_tables.**
  - Таблица с `NFT_TABLE_F_OWNER` запоминает netlink `portid` создателя (`table->nlpid`). Поиск такой таблицы по имени из другого сокета возвращает ошибку (проверка `nft_table_has_owner(table) && nlpid && table->nlpid != nlpid`): чужой процесс не может ни изменить, ни удалить её.
  - `nft_flush()` (то есть `nft flush ruleset`) **пропускает** таблицы с владельцем, если `table->nlpid != ctx->portid`.
  - При закрытии сокета владельца таблица удаляется, **кроме** случая `NFT_TABLE_F_PERSIST`: тогда снимается только флаг владельца (`table->flags &= ~NFT_TABLE_F_OWNER`), таблица остаётся «сиротой».
  - Сироту можно «усыновить»: обновление флагов разрешает установить `OWNER`, если таблица `nft_table_is_orphan` (определение функции в заголовке не прочитано — **[Не проверено]**, по коду вызова — таблица с `PERSIST` без владельца **[Вывод]**). Флаг `PERSIST` менять после создания нельзя (`-EOPNOTSUPP`).
- [Факт, 8] Заголовок uapi в контейнере знает только `DORMANT` и `OWNER`; `nft` 1.0.9 принимает `flags owner`, но не `persist` (`unknown table option persist`, проверено `nft -c`). Минимальные версии ядра и nft с `persist` — **[Не проверено]** (ядро 6.18 контейнера флаг содержит, по исходнику master).

[Вывод] Владелец таблицы должен держать **свой** netlink-сокет всё время работы. Утилита `nft` закрывает сокет при выходе, поэтому владение через `nft -f` невозможно: все изменения таблицы должен отправлять сам процесс-владелец (собственный кодировщик пакета nfnetlink либо `libnftables` в процессе — у firewalld владение работает через библиотеку, исходник `libnftables` не прочитан, **[Предположение]**).

### 1.2. Сравнение вариантов

| Вариант | Устойчив к `flush ruleset` | Устойчив к падению процесса | Совместимость с ОС | Цена |
|---|---|---|---|---|
| A. Обычная таблица + unit `After=nftables.service` + слежение | нет (окно до восстановления; без демона — навсегда) | да | полная | низкая |
| B. Таблица `owner`+`persist`, удерживаемая сторожем `phantom-guard` | **да, пока сторож жив**; после падения сторожа — как A, до перезапуска | да (сирота остаётся) | нужны ядро и кодировщик с `persist` | средняя: свой кодировщик nfnetlink |
| C. Приложения в namespace, где единственный выход — TUN; физические интерфейсы в отдельном namespace | да (правила не нужны для запрета) | да (нет маршрута наружу вообще) | ломает NetworkManager, Wi-Fi, мосты ВМ, captive portal; нужен перенос `phy` | высокая, инвазивно |
| D. eBPF на cgroup (`cgroup/connect`, `cgroup_skb/egress`) | да к `flush ruleset`, нет к отсоединению программ root | зависит от закрепления в bpffs | только локальные процессы; не видит forward и мосты | высокая; другой стек проверки |

**Решение.** По умолчанию — **B с запасным A** (если ядро не поддерживает `persist`, сторож работает в режиме A и сообщает «защита от `flush ruleset` недоступна»). C — опциональный профиль «изолированный хост» (выделенная машина или маршрутизатор) после MVP. D отклонён: не покрывает транзит и мосты, дублирует механизм.

Обоснование C как не-умолчания [Вывод]: на рабочей станции физические интерфейсы управляются NetworkManager/wpa_supplicant в корневом namespace; перенос их (и `phy` Wi-Fi) в namespace `phantom-phys` требует запускать там всю сетевую обвязку, ломает мосты ВМ к `eth0`, проход captive portal и диагностику. Порядок загрузки C не устраняет: пока интерфейсы не перенесены, они в корневом namespace без запрета. Плюс C — полная независимость от чужих таблиц и L2-мостов к перенесённым интерфейсам.

### 1.3. Компоненты и unit-файлы (нормативно)

- `phantom-guard` — привилегированный сторож без кода разбора сети: владеет таблицами `inet phantom` и `bridge phantom_l2`, хранит состояние kill switch, исполняет закрытый перечень операций (§2.5). Ставится **как системная служба, независимая от демона туннеля**.
- `phantom-netd` — непривилегированный демон транспорта и криптографии.

```ini
# phantom-guard.service (эскиз)
[Unit]
Description=PHANTOM kill switch guard
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target nftables.service firewalld.service ufw.service shutdown.target
After=systemd-modules-load.service
RequiresMountsFor=/var/lib/phantom
Conflicts=shutdown.target
[Service]
Type=notify
ExecStart=/usr/libexec/phantom/phantom-guard
Restart=always
RestartSec=0
# ExecStop отсутствует: остановка НЕ снимает правила (persist)
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
[Install]
WantedBy=sysinit.target
```

Обоснование директив [Вывод из 1.1 и `systemd.special(7)` по V-06]:

1. `DefaultDependencies=no` — иначе unit неявно ждёт `basic.target`, то есть позже сетевых служб с ранним стартом.
2. `Wants=network-pre.target` — target пассивен; без `Wants=` порядок `Before=` может не действовать.
3. `Before=nftables.service firewalld.service ufw.service` — **сознательно до**, а не после (в отличие от рекомендации V-06 «After=»): таблица с владельцем переживает `flush ruleset` при старте этих служб, а при остановке (обратный порядок) сторож останавливается **после** `nftables.service`, поэтому `ExecStop=nft flush ruleset` выполняется при живом владельце и таблицу не трогает. `Before=` для отсутствующих unit-ов безвреден.
4. **Режим A** (без `persist`) использует другой порядок: `After=nftables.service firewalld.service ufw.service`, `Before=network-pre.target`. При остановке системы `nftables.service` тогда стирает таблицу после остановки сторожа; к этому моменту сетевые службы уже остановлены (они упорядочены после `network-pre.target`), но интерфейсы могут оставаться поднятыми — окно при выключении записывается в RR15.
5. `Conflicts=shutdown.target` и `Before=shutdown.target` — корректная остановка при `DefaultDependencies=no`; остановка не удаляет таблицу.
6. `RequiresMountsFor=` — файл состояния читается до загрузки правил; отдельный `/var` смонтирован.

### 1.4. Поведение (нормативно)

1. **Состояние** `off|enforcing` хранится в `/var/lib/phantom/killswitch.state` (атомарная запись: временный файл, `fsync`, `rename`, `fsync` каталога) вместе с полным текстом правил последнего `enforcing`. Переход `off → enforcing` ДОЛЖЕН сначала записать состояние, затем применить правила; `enforcing → off` — сначала удалить таблицы, затем записать `off` (при сбое между шагами остаётся `enforcing`, отказ в безопасную сторону).
2. **Загрузка.** Сторож читает состояние. `off` — ничего не ставит. `enforcing` — одной транзакцией создаёт таблицы. Файл повреждён или не проходит проверку — ставится **минимальная запретительная таблица** (разрешён только `lo`; DHCP/NDP не разрешены), ошибка видна в `status`. Правила используют только `iifname`/`oifname` (строки): TUN при загрузке ещё нет.
3. **Нет сохранённых правил для отсутствующих в конфигурации серверов**: адреса серверов берутся из сохранённого снимка, не из сети.
4. **Остановка сторожа, `kill -9`, падение.** Таблица с `persist` остаётся сиротой и продолжает действовать; systemd перезапускает сторож (`Restart=always`), он усыновляет таблицу и сверяет её с сохранённым текстом (§3.15, S-17). Если сторож не перезапустился, таблица действует, но не защищена от `flush ruleset`.
5. **Демон туннеля не запущен** (автозапуск выключен, ошибка конфигурации): сторож от него не зависит; правила стоят, трафик наружу запрещён. Это устраняет основной сценарий V-06.
6. **Слежение.** Сторож подписан на группу `NFNLGRP_NFTABLES` [Факт: группа есть в uapi, 8] и после любого события сверяет наличие и генерацию своих таблиц; в режиме A восстанавливает таблицу не позже 100 мс (стартовое значение) после события. Подписка требует `CAP_NET_ADMIN`: у ядра nfnetlink нет флага приёма для непривилегированных (`NL_CFG_F_NONROOT_RECV` не задан) [Факт, 2; вывод о проверке в `af_netlink` — **Не проверено**].
7. **Перезагрузка, сон, пробуждение.** Правила — состояние ядра; переживают сон без участия процессов. После пробуждения сторож выполняет сверку.
8. **Удаление пакета** ДОЛЖНО выполнить `phantom-client disconnect` (снятие таблиц и запись `off`) до удаления сторожа; при `purge` — то же.
9. **Единственный путь в `off`** — команда `disconnect` от администратора по управляющему сокету сторожа (§2.5). Демон туннеля перевести систему в `off` не может.
10. **Таблица `Disconnected` §7** (V-09): `Disconnected` означает «туннеля нет»; kill switch — отдельная ось. Строка §7 меняется на: «`Disconnected`: трафик — по состоянию kill switch: `off` — обычная сеть; `enforcing` — запрещён».

### 1.5. Какую гарантию G8 можно заявлять

> **G8 (предлагаемая формулировка).** Пока kill switch в `enforcing`, IP-трафик, порождаемый процессами корневого network namespace хоста, и IP-трафик, пересылаемый хостом (L3 forward и L2-мост), не выходит через нетуннельные интерфейсы, кроме: пакетов транспорта к адресам и портам сервера с меткой клиента; DHCP, NDP, MLD по §3.5; локальной сети, если она явно включена (§3.1). Это выполняется при падении любого процесса PHANTOM, при остановке демона туннеля, после перезагрузки начиная с момента запуска `phantom-guard`, и при `nft flush ruleset` сторонним ПО **пока жив `phantom-guard` и ядро поддерживает `persist`**.
> **Не покрывает:** окно загрузки до `phantom-guard` (initramfs, параметр ядра `ip=`, службы без `After=network-pre.target`) и окно выключения в режиме A (RR15); процессы с `CAP_NET_ADMIN` или `CAP_NET_RAW` (сокеты `AF_PACKET` минуют хуки `inet`; root может убить сторож и удалить сироту, поставить свою метку) (RR23); другие network namespaces с собственным выходом на физическую сеть (macvlan, ipvlan, SR-IOV VF, перенесённые физические интерфейсы); ядро без `persist` — тогда защита от `flush ruleset` только восстановлением с окном.

[Вывод] Слова «гарантия против root» не используются. Проверяемость — §5.

### 1.6. V-07: мост второго уровня и транзит

- **Решение.** В `enforcing` сторож ставит таблицу `bridge phantom_l2` с цепочкой `forward` (политика `drop`) — пересылка кадров между портами любых мостов запрещена. Конфигурация `bridge.allow_ports = ["vnet*", …]` разрешает пересылку **только между** перечисленными портами (ВМ ↔ ВМ), никогда — на порт, не входящий в список. Если загружен `br_netfilter` с `bridge-nf-call-*`, мостовой IP дополнительно проходит `inet forward` и отбрасывается там же [Предположение по устройству netfilter].
- **Транзит L3** (контейнеры, ВМ за NAT, namespaces): по умолчанию `forward` — `drop`. Опция `forward_via_tunnel = true` разрешает `iif != TUN → oif TUN` с маскарадингом на TUN (сервер принимает только адрес клиента, §4 cryptokey routing). Без опции — «отбрасывается» (исправляет несогласованность V-07).
- **Тест:** veth-пара в мосту с «физическим» veth, кадр из «ВМ» на внешний адрес — не виден на дальнем конце; положительный контроль при `off`.
- **Остаточный риск:** macvlan/ipvlan-интерфейсы поверх физического в других namespaces обходят мост и хуки корневого namespace [Вывод]; сторож при переходе в `enforcing` ДОЛЖЕН перечислить связи через netlink и предупреждать о macvlan/ipvlan с нижним физическим устройством.

### 1.7. V-08: ICMP-ошибки внешнего пути

- **Решение.** В `output` пакеты транспорта метятся `ct mark set meta mark`; в `input` принимаются `ct mark M ct state related` только типов IPv4 `destination-unreachable`, `time-exceeded` и ICMPv6 `destination-unreachable`, `packet-too-big`, `time-exceeded` [Вывод: ICMP-ошибка привязывается conntrack к исходной записи как `related` и несёт её метку — **Не проверено**, нужен тест].
- Защита от CVE-2019-14899 — в `prerouting` приоритета `raw` по образцу `wg-quick` (`iifname != TUN daddr <адрес туннеля> fib saddr type != local drop`) [Факт, 6], а не в `input`.
- **Остаточный риск:** поддельный PTB к соединению с сервером требует угадать порт; снижает PMTU и может перевести на T2 (RR5, S-10).

### 1.8. V-04, V-05: конфигурация, срок, часы, якорь доверия

1. **Подпись до разбора.** Конверт — фиксированный двоичный заголовок: `magic "PHANTOM-CFG\0"`, `u8 purpose` (клиентская конфигурация | список клиентов сервера | смена якоря), `key_id[16]` (первые 16 байт SHA-256 открытого ключа подписи), `u64 version`, `u64 min_version`, `i64 created_at`, `i64 not_after`, `recipient[32]`, `u32 payload_len`, payload, подпись Ed25519 по всему предыдущему. Подпись проверяется до разбора TOML; TOML разбирается из тех же байтов. Список клиентов сервера **подписывается** тем же механизмом (`purpose`), отзыв ключа распространяется на G15.
2. **Хранение.** `/var/lib/phantom/config/` содержит `v<N>.env` и `state` (`max_version`, `current`, `min_version`, `key_id`). Порядок: записать `v<N>.env` + `fsync`; затем атомарно заменить `state`. Точка фиксации — `rename` файла `state`. Сбой до неё — остаётся старая версия, файл `v<N>.env` удаляется при сверке.
3. **Утрата `state`** — обновления по сети НЕ принимаются; только ручная установка оператором (`phantom-client trust install`) вместе с якорем.
4. **Срок.** `not_after` проверяется при приёме. Для установленной версии: по истечении `not_after + grace` (по умолчанию 7 суток) **новые подключения не устанавливаются** (`Blocked`, причина «конфигурация истекла»), kill switch остаётся `enforcing`. Это единственное ограничение сценария «украденный ключ сервера + блокировка доставки обновлений», поэтому выбран отказ, а не предупреждение.
5. **Часы.** `created_at > now` не является ошибкой (иначе при отставании часов законное обновление отвергается). Часы в прошлом не опасны при сохранённом `state` (монотонность). Часы в будущем запирают узел по п. 4: выход — локальная команда администратора `phantom-client clock-override --until <дата>` (запись в журнал), NTP через туннель после подключения. Остаточный риск записывается в RR (новый): «ошибочные часы в будущем требуют ручного вмешательства».
6. **Откат.** `rollback` ставит `current = N−1`, **не уменьшает** `max_version`; следующий принимаемый номер > N; истёкшая `N−1` не ставится без `--force-expired`.
7. **Смена якоря.** Конверт `purpose = смена якоря` подписан текущим ключом и несёт новый открытый ключ; после принятия конверты со старым `key_id` отвергаются. Компрометация якоря и «сжигание» версии (`2^64−1`) исправляются только ручным `trust reset` на узле (RR21).

## 2. Часть 1. Повторная оценка механизмов

### 2.1. TUN против TAP

**Решение: TUN (L3).** [Вывод] Туннель переносит IP-пакеты; TAP добавил бы Ethernet-заголовки, ARP/NDP поверх туннеля, широковещательный домен между клиентами и необходимость фильтровать L2 на сервере — новые поверхности без выигрыша. TAP нужен только для мостового доступа к L2-сети (вне целей проекта).
[Факт, 5] Создание нового TUN (`TUNSETIFF` без существующего устройства) требует `CAP_NET_ADMIN` в user namespace сетевого namespace; к существующему persistent-устройству можно присоединиться без capability, если совпадают `owner`/`group` (`tun_permitted`). Решение: TUN создаёт сторож и передаёт fd по `SCM_RIGHTS` (не persistent: устройство исчезает с закрытием fd, трафик уходит в основную таблицу и запрещается).

### 2.2. Механизм запрета

| Механизм | За | Против | Решение |
|---|---|---|---|
| nftables, одна таблица `inet` + `bridge` | атомарные транзакции; IPv4/IPv6 в одной таблице; `owner`/`persist`; `fib`, `ct mark`, `socket` | чужой root может мешать | **основной** |
| iptables (`iptables-nft`/legacy) | привычен | две таблицы (v4/v6), нет `owner`, неатомарность между v4 и v6 | отклонён |
| отдельный namespace | не зависит от правил | инвазивен (§1.2) | профиль после MVP |
| eBPF/cgroup | не стирается `flush ruleset` | не видит forward/мосты; отдельный стек | отклонён |

[Вывод, не проверено первичным текстом] `drop` в любой базовой цепочке хука окончателен, `accept` одной таблицы не отменяет `drop` другой; поэтому правила Docker/firewalld не открывают обход, но **их** `drop` может отбросить наш разрешённый трафик (на сервере с Docker политика `FORWARD drop` отбросит транзит клиентов — оператору нужно правило в `DOCKER-USER` либо сервер без Docker; тест обязателен).

### 2.3. Policy routing по схеме wg-quick (точно по исходнику [6])

`add_default()` в `wg-quick/linux.bash`:

1. Номер таблицы `t`: если fwmark интерфейса не задан — с 51820 первый номер, в котором нет маршрутов IPv4 и IPv6; fwmark интерфейса ставится равным `t`.
2. `ip -4|-6 rule add not fwmark t table t` — всё без метки ищет маршрут в таблице `t`.
3. `ip -4|-6 rule add table main suppress_prefixlength 0` — основная таблица используется, кроме маршрутов с длиной префикса 0 (default), то есть более узкие маршруты main (подсети, полученные по DHCP/RA) действуют.
4. `ip route add <0.0.0.0/0 | ::/0> dev <iface> table t`.
5. nft-таблица `ip|ip6 wg-quick-<iface>`: `preraw` (prerouting, приоритет −300): `iifname != iface daddr <адрес интерфейса> fib saddr type != local drop`; `premangle` (prerouting −150): `meta l4proto udp meta mark set ct mark`; `postmangle` (postrouting −150): `meta l4proto udp mark t ct mark set mark`.
6. `sysctl net.ipv4.conf.all.src_valid_mark=1`, если не 1 (только для IPv4) — чтобы reverse-path проверка учитывала восстановленную метку.
7. Очистка: удаляет правила `lookup t` и `suppress_prefixlength 0`, пока они есть, и таблицы nft с суффиксом `wg-quick-<iface>`.

**Отличия PHANTOM (нормативно):** метка `0x50480001` и таблица по тому же правилу выбора номера; метку получают только сокеты транспорта (через сторож, §2.5); `ct mark` сохраняется для TCP и UDP; одна таблица `inet` вместо `ip`/`ip6`; п. 3 сохраняется (с ним выборочный отказ по маршрутам из DHCP/option 121 — остаточный риск S-09), firewall всё равно запрещает выход мимо TUN.

### 2.4. DNS: systemd-resolved и работа без него

**Решение (S-06).** Режим определяется при старте: (а) `/etc/resolv.conf` — symlink на stub resolved и resolved отвечает по D-Bus → `SetLinkDNS`, `SetLinkDomains("~.")`, `SetLinkDefaultRoute(true)` на TUN, `RevertLink` при снятии [по отчёту 06 §3.6]; (б) обычный файл без менеджера → сторож атомарно заменяет `/etc/resolv.conf` (резервная копия в `/var/lib/phantom`, восстановление при `disconnect`); (в) иное (NetworkManager без resolved пишет файл сам, `resolvconf`) → **отказ подключения** с ошибкой «неподдерживаемая конфигурация DNS» либо явная опция `dns.mode = "file-force"`. Утечку в любом режиме закрывает firewall (§4); режим влияет на работоспособность, не на G9. Права D-Bus resolved для root — **[Не проверено]**.

### 2.5. Привилегии

[Факт] `SO_MARK` требует `CAP_NET_RAW` **или** `CAP_NET_ADMIN` в user namespace сетевого namespace сокета [3]; `SO_BINDTODEVICE` на ещё не привязанном сокете capability не требует (проверка `CAP_NET_RAW` только при перепривязке) [3]; изменяющие запросы rtnetlink требуют `CAP_NET_ADMIN` (`kind != RTNL_KIND_GET && !netlink_net_capable(skb, CAP_NET_ADMIN)`) [4]; любые запросы nfnetlink (nf_tables, ctnetlink) — `CAP_NET_ADMIN` [2]; создание TUN — `CAP_NET_ADMIN` [5]. Привязка к порту < 1024 — `CAP_NET_BIND_SERVICE` (граница `ip_unprivileged_port_start` = 1024 в контейнере) [Факт, 8].

**Решение (S-07): отдельный сторож.** Один процесс со сбросом прав неосуществим: метка нужна каждому новому сокету, правила меняются после старта, а `CAP_NET_RAW` у разборщика дал бы `AF_PACKET` — обход хуков `inet`. Схема:

- `phantom-guard` (root или пользователь с `CAP_NET_ADMIN`; `panic = abort`; без сетевых сокетов, кроме netlink и unix). Закрытый перечень операций для `phantom-netd`: `OpenTransportSocket{family, proto, server_index}` → fd с `SO_MARK` (адрес берётся из подписанной конфигурации по индексу, произвольный адрес передать нельзя); `OpenTun` → fd; `TunnelUp{config_digest}` → маршруты и адреса из **локальной** подписанной конфигурации; `Config` от сервера только сверяется (несовпадение — закрытие соединения); `SetDns`, `ReportState`. Операции `off`/`disconnect` для `phantom-netd` нет.
- Управляющий канал: `/run/phantom/guard.sock` (`0660`, группа `phantom-net`, только для `phantom-netd`) и `/run/phantom/control.sock` (`0660`, группа `phantom-admin`). Проверка вызывающего по `SO_PEERCRED`: `disconnect`, `portal`, `clock-override`, `trust *` — только uid 0 или члены `phantom-admin`; `status` — также группа `phantom`. Сообщения — фиксированные бинарные структуры с ограничением длины (≤ 4 КиБ).
- Альтернатива метке — сопоставление `socket cgroupv2` в правилах — отклонена: путь cgroup разрешается при загрузке правил, а при загрузке системы cgroup службы ещё нет [Предположение].

## 3. Часть 2. Решения по замечаниям

Формат: **решение → норма → тест → остаточный риск.**

### 3.1. S-05 — локальная сеть
- Решение: LAN по умолчанию закрыта. При `allow_lan = true` разрешены только **пересечение** подсетей, напрямую подключённых к нетуннельным интерфейсам, с фиксированным списком: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `fe80::/10`, `fc00::/7`. Префикс шире /16 (IPv4) или /48 (IPv6) после пересечения отвергается. Набор `@lan4/@lan6` пересчитывается сторожем при смене адресов (netlink) одной транзакцией.
- Норма: правило запрета `53, 853, 5353, 5355` (TCP/UDP) мимо TUN стоит **раньше** разрешения LAN; групповые адреса `224.0.0.251`, `ff02::fb`, `224.0.0.252`, `ff02::1:3` не входят в LAN.
- Тест: DHCP выдаёт `/1` публичный префикс — пакет на публичный адрес не выходит; mDNS/LLMNR при `allow_lan` не видны на дальнем конце.
- Остаток: при `allow_lan` устройства LAN видят трафик к себе и метаданные (ARP, NDP); SSDP/NetBIOS к разрешённым адресам LAN выходят.

### 3.2. S-06 — имя сервера и DNS
- Решение: в MVP адрес сервера — IP. Имя допускается только как `server_name` с разрешением **в состоянии `off` при команде `connect`**, системным резолвером, до перехода в `enforcing`; результат сохраняется в снимок правил. В `enforcing`/`Reconnecting` используются только сохранённые адреса. Работа без resolved — §2.4.
- Тест: в `enforcing` ни одного пакета на порт 53 мимо TUN за весь цикл переподключений.
- Остаток: однократный видимый запрос имени при первом подключении; G9 делится на «firewall» (проверяемо в контейнере) и «настройка резолвера» (нужен стенд с systemd).

### 3.3. S-07 — сброс прав, `Config`, управляющий канал — §2.5
- Тест: `phantom-netd` без capabilities (`CapEff=0`) — `setsockopt(SO_MARK)` → `EPERM`; запрос `OpenTransportSocket` с индексом вне списка — отказ; клиент из чужой группы на `control.sock` — отказ; скомпрометированный `phantom-netd` (тестовый двойник) не может вызвать `off`.
- Остаток: компрометация сторожа = компрометация хоста; локальный администратор снимает защиту.

### 3.4. S-08 — captive portal
- Решение: сторонних проверок нет. Клиент сообщает наблюдение «есть шлюз, сервер не отвечает ни по одному транспорту». Команда администратора `phantom-client portal --minutes 5` добавляет в `output` временное правило **только для процессов uid системного пользователя `phantom-portal`** (`meta skuid`): UDP/TCP 53 к резолверам из DHCP, TCP 80/443 к любым адресам; срок — элемент набора с `timeout`, снимается ядром. Браузер запускается от этого пользователя (`phantom-client portal-browser`). Весь остальной трафик остаётся запрещённым.
- Тест: во время окна пакет от uid ≠ `phantom-portal` не выходит; после истечения — правило исчезает без участия процессов.
- Остаток: в окне портальный браузер раскрывает DNS-запросы и посещения портала; браузер может посетить иные сайты — ответственность пользователя. После MVP — по решению владельца; до этого `disconnect` остаётся единственным способом (явно в документации).

### 3.5. S-09 — DHCP, NDP, RA, ICMP
- Норма `output` (мимо TUN): DHCPv4 `udp sport 68 dport 67`; DHCPv6 `ip6 saddr fe80::/10 daddr ff02::1:2 udp 546→547`; ICMPv6 RS, NS, NA с `hoplimit 255`; MLD-отчёты с `hoplimit 1`. Порты 68 и 546 привилегированные — непривилегированный процесс не может отправить с них [Вывод из `ip_unprivileged_port_start`], сырой сокет требует `CAP_NET_RAW`.
- Норма `input`: DHCPv4 `67→68`; DHCPv6 `fe80::/10 547→546`; ICMPv6 NS, NA, RA с `hoplimit 255`; MLD-запросы с `fe80::/10`, `hoplimit 1`; **Redirect запрещён**; ICMP-ошибки — только `related` к соединению с сервером (§1.7); echo-request мимо TUN — `drop`.
- DHCP option 121 и RA с маршрутами: принимаются ядром/клиентом DHCP (вне PHANTOM); firewall не даёт утечки, но маршруты main с `suppress_prefixlength 0` уводят выбранные адреса в main — пакет отбрасывается. Опция `routes.ignore_dhcp_specific = true` (после MVP) — отдельно.
- Многие клиенты DHCPv4 используют `AF_PACKET` и минуют хуки `inet` целиком [Предположение]; поэтому DHCP работает и при более строгом наборе, а правило `68→67` нужно для продления по unicast.
- Тест: подставной DHCP с option 121 на `0.0.0.0/1` и `128.0.0.0/1` — наружу ничего; поддельный RA с маршрутом — наружу ничего; ICMPv6 Redirect не меняет маршрут к серверу.
- Остаток: выборочный отказ по адресам назначения и наблюдаемость попыток (RR14); привилегированный процесс может выводить данные через DHCP.

### 3.6. S-11 — фильтр назначения на сервере
- Норма (§4.2): `forward` с политикой `drop`; запрещены назначения: `0/8, 10/8, 100.64/10, 127/8, 169.254/16` (включая metadata `169.254.169.254`), `172.16/12, 192.0.0/24, 192.168/16, 198.18/15, 224/4, 240/4`; IPv6 `::/127, ::ffff:0:0/96, 100::/64, fc00::/7` (включая `fd00:ec2::254`), `fe80::/10, ff00::/8`; собственные адреса сервера; префиксы сети хостинга из конфигурации. Клиент ↔ клиент (`iif TUN, oif TUN`) — `drop`; дополнительно в процессе: пакет с назначением во внутреннем диапазоне не уходит в другое соединение.
- `input` с TUN: только `established,related`, DNS-резолвер туннеля на адрес шлюза, echo-request с лимитом; остальное — `drop` (SSH и панели сервера с туннеля недоступны).
- IPv6: **NAT66 из ULA `/64`** (маскарадинг). Маршрутизируемый префикс отклонён: статический глобальный адрес клиента — постоянный идентификатор для T8, нужны правила входящих.
- Проверка пакета в процессе: версия, длина заголовка, `total length == длина кадра`, фрагменты IPv4/IPv6 принимаются (ядро соберёт), источник = адрес ключа.
- Тест: из клиента к `169.254.169.254`, к адресу сервера, к другому клиенту, к `ff02::1` — нет доставки (захват в namespace «сервер-хостинг»).
- Остаток: обращения к публичным адресам от имени сервера (жалобы на абьюз).

### 3.7. S-12 — лимиты после аутентификации; критерий G13
- Норма: conntrack на клиента ≤ 4096 новых записей (`add @clim { ip saddr ct count over 4096 } drop`); один двунаправленный поток QUIC на соединение (остальные — закрытие); управляющее сообщение ≤ 512 байт; очередь к клиенту ≤ 256 КиБ (переполнение — drop хвоста); `Hello` ≤ 5 с после рукопожатия; ≤ 2 соединения-кандидата на ключ (V-03); лимит по источнику до аутентификации — по `/32` и по `/64` для IPv6, порог 16 одновременных рукопожатий; общий лимит рукопожатий ≤ 256; T2 — SYN cookies ядра, тайм-аут рукопожатия 10 с.
- **Критерий G13** (стартовые числа): при 10 000 неаутентифицированных попыток в секунду с 1000 адресов на эталонной ВМ (2 vCPU, 2 ГиБ) легитимный клиент подключается с p95 ≤ 3× от времени без нагрузки, RSS сервера ≤ 512 МиБ, ни одного отказа уже подключённым клиентам. Под нагрузкой одного аутентифицированного клиента (полная таблица conntrack клиента) другой клиент открывает новые соединения.
- Остаток: объёмная атака на канал (RR12); соседи за общим NAT делят квоту по источнику.

### 3.8. S-14 — журнал сервера
- Решение (A9 переформулирована): «журналы содержат только поля из белого списка». По умолчанию: агрегированные счётчики за час (число подключений, ошибок по причинам); события по клиенту — **только ошибки** (отказ аутентификации, отозванный ключ, превышение лимита) с меткой клиента, заданной оператором, временем с точностью до минуты, кодом причины. Успешные подключения/отключения по клиенту — только при `log.client_events = true` (видно в `check`). Адрес клиента — только уровень отладки. Адресов назначения, DNS, объёмов по клиенту — нет никогда.
- Норма: `LogNamespace=phantom` с собственным сроком хранения (**[Не проверено]** на стенде); `LimitCORE=0`, `prctl(PR_SET_DUMPABLE, 0)`; hook паники печатает только место, не содержимое; экспорт ключей TLS (`KeyLog`) не включается сборкой (проверка `cargo tree`/feature в CI).
- Тест G14 (усиленный): прогон с известными долговременными ключами и тестовым экспортом сеансовых секретов (только в тестовой сборке); поиск в журнале, stderr, файлах состояния в кодировках raw, hex (оба регистра), base64, base64url, PEM, десятичный массив; все уровни, включая `trace` сторонних библиотек; паника внутри обработчика; ошибка разбора TOML с ключом в файле. Тест белого списка: каждая запись JSON проверяется по схеме, лишнее поле — провал.
- Остаток: conntrack (адреса назначения в памяти ядра на время жизни записи), journald вне `LogNamespace`, учёт хостинга, swap.

### 3.9. S-16 — разбор недоверенного ввода
- Границы: (1) TLS/QUIC и сертификат/raw key клиента — библиотеки (fuzz сторонних целей и следование advisories); (2) кадры и управляющие сообщения; (3) IP-заголовок из TUN на сервере; (4) заголовок конверта конфигурации (фиксированный размер, до подписи); (5) TOML — только после подписи; (6) сообщения управляющих сокетов; (7) ответы netlink и D-Bus (доверенные, но с проверкой длин).
- Норма: в модулях (2)–(6) запрещены `unwrap`, `expect`, индексация без проверки и неявная арифметика (`clippy::unwrap_used`, `expect_used`, `indexing_slicing`, `arithmetic_side_effects` = deny); длины проверяются до выделения; `phantom-netd` — `panic = unwind`, задача соединения изолирована, общее состояние без «отравляемых» блокировок; `phantom-guard` — `panic = abort` (состояние в ядре, перезапуск systemd).
- Тест: fuzz-цели (2)–(6) не менее N часов в CI-ночь (N — этап 9); proptest «любой вход → ошибка или значение, без паники».
- Остаток: ошибки сторонних разборщиков; G12 — «проверена в объёме N часов fuzz».

### 3.10. S-17 — генерация и применение правил
- Решение: правила генерируются из типизированной модели (адреса — `IpAddr`, порты — `u16`, имена интерфейсов — тип с проверкой `^[a-z][a-z0-9_-]{0,14}$`, всегда в кавычках, длина ≤ 15 = `IFNAMSIZ − 1`); не более 8 адресов сервера; в режиме B кодируются сторожем в пакет nfnetlink на сокете владельца; в режиме A и для `check` — текст в `/usr/sbin/nft -f -` (абсолютный путь, `env_clear()`, argv без оболочки).
- Атомарность: каждая замена — **одна транзакция**: в режиме A `destroy table` + полное определение в одном файле; в режиме B `flush table` + новые наборы и правила в одном пакете (цепочки с `policy drop` не исчезают). Netlink-маршруты неатомарны с правилами: включение — таблицы nft → маршруты → DNS; выключение — DNS → маршруты → таблицы последними.
- Очистка: при старте сторож сверяет таблицы (`phantom*`), правила `fwmark` и таблицу маршрутов с ожидаемыми; лишнее удаляет, недостающее ставит; идемпотентно.
- Тест: имя интерфейса с `"`/`;`/16 символов — отказ на уровне типа; `kill -9` сторожа на каждом шаге — повторный старт приводит к ожидаемому состоянию; смена адресов сервера под потоком пакетов — ни одного пакета мимо TUN.

### 3.11. S-18 — модель угроз
Добавить активы: состояние firewall клиента; входящая доступность устройства из LAN; локальное состояние и журнал клиента (включая память по сетям); якорь доверия и `state` конфигурации; управляющие сокеты. G8 — формулировка §1.5 (все процессы корневого namespace, включая T6 без `CAP_NET_*`; транзит; исключения). Убрать «исключения маршрутизации» из §5 модели. G10 — допущение «ядро обрабатывает RA» и способ блокировки (reject). Новые гарантии: G11b изоляция клиентов и фильтр назначения (§3.6); G17 минимальность журналов (§3.8). G16 — только T1. B5 — граница «сторож ↔ демон» (§2.5).

### 3.12. S-20 — прочее
Время жизни соединения — с равномерным разбросом ±20 % (стартовое значение). Сервер на порту 443: сокет открывает сторож сервера (или systemd socket activation) и передаёт fd; `CAP_NET_BIND_SERVICE` демону не выдаётся.

## 4. Эскиз наборов правил nftables

Синтаксис проверен `nft -c -f` (nftables 1.0.9); адреса — документационные; `phantom0`/`phantom-s0` — TUN, `eth0` — внешний интерфейс сервера; метка `0x50480001`. В режиме B к таблице добавляются флаги `owner, persist` (nft 1.0.9 `persist` не знает).

### 4.1. Клиент (`enforcing`, туннель поднят)

```
destroy table inet phantom
table inet phantom {
  set server4 { type ipv4_addr . inet_proto . inet_service
                elements = { 192.0.2.10 . udp . 443, 192.0.2.10 . tcp . 443 } }
  set server6 { type ipv6_addr . inet_proto . inet_service
                elements = { 2001:db8::10 . udp . 443, 2001:db8::10 . tcp . 443 } }
  set lan4 { type ipv4_addr; flags interval; }        # пусто, если allow_lan = false
  set lan6 { type ipv6_addr; flags interval; }
  chain preraw {      # CVE-2019-14899: адрес туннеля — только с TUN
    type filter hook prerouting priority raw; policy accept;
    iifname != "phantom0" ip daddr 10.66.0.2 fib saddr type != local drop
    iifname != "phantom0" ip6 daddr fd66::2 fib saddr type != local drop }
  chain premangle {   # метка ответов для reverse-path (как wg-quick)
    type filter hook prerouting priority mangle; policy accept;
    ct mark 0x50480001 meta mark set ct mark }
  chain input {
    type filter hook input priority filter - 10; policy drop;
    iifname "lo" accept
    iifname "phantom0" ct state established,related accept
    ct mark 0x50480001 ct state established accept
    ct mark 0x50480001 ct state related meta l4proto icmp
        icmp type { destination-unreachable, time-exceeded } accept
    ct mark 0x50480001 ct state related meta l4proto ipv6-icmp
        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded } accept
    iifname != "phantom0" udp sport 67 udp dport 68 accept
    iifname != "phantom0" ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
    iifname != "phantom0" ip6 hoplimit 255
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
    iifname != "phantom0" ip6 saddr fe80::/10 ip6 hoplimit 1 icmpv6 type mld-listener-query accept
    ip saddr @lan4 ct state established accept
    ip6 saddr @lan6 ct state established accept }
  chain output {
    type filter hook output priority filter - 10; policy drop;
    oifname "lo" accept
    oifname "phantom0" accept
    meta l4proto { tcp, udp } th dport { 53, 853, 5353, 5355 } reject with icmpx admin-prohibited
    meta mark 0x50480001 ip daddr . meta l4proto . th dport @server4 ct mark set meta mark accept
    meta mark 0x50480001 ip6 daddr . meta l4proto . th dport @server6 ct mark set meta mark accept
    udp sport 68 udp dport 67 accept
    ip6 saddr fe80::/10 ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept
    ip6 hoplimit 255 icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
    ip6 hoplimit 1 icmpv6 type { mld-listener-report, mld2-listener-report } accept
    ip daddr @lan4 accept
    ip6 daddr @lan6 accept
    meta l4proto tcp reject with tcp reset          # быстрый локальный отказ (S-09)
    reject with icmpx admin-prohibited }
  chain forward {     # транзит только при forward_via_tunnel = true; иначе — пустая цепочка с drop
    type filter hook forward priority filter - 10; policy drop;
    iifname != "phantom0" oifname "phantom0" accept
    iifname "phantom0" oifname != "phantom0" ct state established,related accept }
  chain postnat {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "phantom0" ip saddr != 10.66.0.2 masquerade
    oifname "phantom0" ip6 saddr != fd66::2 masquerade }
  chain mss {
    type filter hook forward priority mangle; policy accept;
    oifname "phantom0" tcp flags syn tcp option maxseg size set rt mtu
    iifname "phantom0" tcp flags syn tcp option maxseg size set rt mtu }
}
destroy table bridge phantom_l2
table bridge phantom_l2 {
  chain forward { type filter hook forward priority filter - 10; policy drop; } }
```

Пояснения: (1) набор не называет физических интерфейсов — смена сети, Wi-Fi ↔ Ethernet и пробуждение не требуют замены правил; (2) при загрузке (TUN нет) ставится тот же набор — правила по `oifname "phantom0"` просто не совпадают; (3) `reject` в `output` даёт локальную ошибку приложению, наружу пакет не уходит; (4) без IPv6 в туннеле элементы `fd66::2` отсутствуют, весь IPv6 мимо TUN отвергается; (5) минимальная запретительная таблица (повреждённое состояние) — только цепочки `input`/`output`/`forward` с `policy drop` и `lo accept`; (6) policy routing: `rule not fwmark 0x50480001 table T`, `rule table main suppress_prefixlength 0`, `default dev phantom0 table T` (§2.3).

### 4.2. Сервер

```
destroy table inet phantom_srv
table inet phantom_srv {
  set deny4 { type ipv4_addr; flags interval; elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10,
      127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15,
      224.0.0.0/4, 240.0.0.0/4 } }                       # + префиксы хостинга из конфигурации
  set deny6 { type ipv6_addr; flags interval; elements = { ::/127, ::ffff:0:0/96, 64:ff9b:1::/48,
      100::/64, fc00::/7, fe80::/10, ff00::/8 } }
  set self4 { type ipv4_addr; elements = { 198.51.100.7 } }   # собственные адреса сервера
  set self6 { type ipv6_addr; elements = { 2001:db8:1::7 } }
  set clim4 { type ipv4_addr; size 65535; flags dynamic; }
  set clim6 { type ipv6_addr; size 65535; flags dynamic; }
  chain preraw {
    type filter hook prerouting priority raw; policy accept;
    iifname "phantom-s0" ip saddr != 10.66.0.0/24 drop       # глубина обороны к cryptokey routing
    iifname "phantom-s0" ip6 saddr != fd66::/64 drop
    iifname != "phantom-s0" ip saddr 10.66.0.0/24 fib saddr type != local drop
    iifname != "phantom-s0" ip6 saddr fd66::/64 fib saddr type != local drop }
  chain input {       # хост-firewall сервера — забота оператора; здесь только TUN
    type filter hook input priority filter - 10; policy accept;
    iifname "phantom-s0" ct state established,related accept
    iifname "phantom-s0" ip daddr 10.66.0.1 meta l4proto { tcp, udp } th dport 53 accept
    iifname "phantom-s0" ip6 daddr fd66::1 meta l4proto { tcp, udp } th dport 53 accept
    iifname "phantom-s0" icmp type echo-request limit rate 10/second accept
    iifname "phantom-s0" counter drop }
  chain forward {
    type filter hook forward priority filter - 10; policy drop;
    iifname "phantom-s0" oifname "phantom-s0" drop           # изоляция клиентов
    iifname "phantom-s0" ip daddr @deny4 drop
    iifname "phantom-s0" ip6 daddr @deny6 drop
    iifname "phantom-s0" ip daddr @self4 drop
    iifname "phantom-s0" ip6 daddr @self6 drop
    iifname "phantom-s0" ct state new add @clim4 { ip saddr ct count over 4096 } drop
    iifname "phantom-s0" ct state new add @clim6 { ip6 saddr ct count over 4096 } drop
    iifname "phantom-s0" oifname "eth0" accept
    iifname "eth0" oifname "phantom-s0" ct state established,related accept }
  chain mss {
    type filter hook forward priority mangle; policy accept;
    iifname "phantom-s0" tcp flags syn tcp option maxseg size set rt mtu
    oifname "phantom-s0" tcp flags syn tcp option maxseg size set rt mtu }
  chain postnat {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "eth0" ip saddr 10.66.0.0/24 masquerade
    oifname "eth0" ip6 saddr fd66::/64 masquerade }
}
```

Пояснения: (1) `counter` — без адресов, только число; (2) на сервере таблица без `persist`: при остановке службы транзит должен прекращаться; (3) имя внешнего интерфейса — из конфигурации с проверкой типа; (4) с Docker на сервере его `FORWARD drop` отбросит транзит (§2.2) — `check` ДОЛЖЕН это обнаруживать.

## 5. Часть 3. План защиты от утечек

Обозначения проверки в текущем контейнере: **К** — можно (root, `CAP_NET_ADMIN`, `/dev/net/tun`, `nft`, `unshare`, veth/мост через netlink из тестового кода; захват — собственный слушатель на `AF_PACKET` в namespace «сеть»); **Ч** — частично; **С** — нужен стенд (systemd, реальная сеть). Каждый отрицательный тест — с положительным контролем при `off` (S-19).

| Канал | Механизм | Тест | Где |
|---|---|---|---|
| DNS (53/853, mDNS, LLMNR) | `output`: TUN accept → запрет DNS-портов → LAN; резолвер на TUN | запрос к резолверу «сети», к `224.0.0.251:5353` — не виден | К (firewall); С (resolved) |
| IPv6 | без IPv6 в туннеле весь IPv6 мимо TUN — `reject` | TCP/UDP на глобальный и link-local IPv6 — не виден | К |
| RA/DHCP (option 121, RA-маршруты) | firewall, а не маршруты; `suppress_prefixlength 0` | подставные маршруты `0/1`, `128/1`, RA с маршрутом — наружу ничего | К (статические маршруты через netlink); С (реальный клиент DHCP) |
| ICMPv6 Redirect | `input` не принимает | Redirect на шлюз «сети» — маршрут не меняется | К |
| Локальная сеть | закрыта; при `allow_lan` — пересечение со списком частных | публичный префикс от «DHCP» — наружу ничего | К |
| Вход на адрес туннеля из LAN | `preraw` | SYN/ACK/RST на `10.66.0.2` с «физического» veth — нет ответа | К |
| Forward L3 | `forward drop`; опция NAT в TUN | вложенный namespace за мостом/NAT — наружу только через TUN | К |
| L2-мост | `bridge phantom_l2` `drop` | veth «ВМ» в мосту с «физическим» veth — кадр не виден | К |
| macvlan/ipvlan, AF_PACKET | вне G8; предупреждение сторожа | macvlan в namespace — фиксируем утечку как известную | К (macvlan есть, ipvlan в ядре нет) |
| `SO_BINDTODEVICE` | `output` по `oifname`, не по маршруту | непривилегированный сокет, привязанный к veth, — не виден | К |
| Уже открытые соединения | нет общего `established accept` на физических; сброс conntrack через ctnetlink | TCP-поток до `enforcing` — после ни одного пакета | К |
| Загрузка | `phantom-guard` до `nftables.service` и `network-pre.target` | перезагрузка в `enforcing` с выключенным `phantom-netd`; оба порядка unit-ов | С |
| Выключение | сторож переживает `ExecStop` nftables (B) | захват при `poweroff` | С |
| `nft flush ruleset`, firewalld/ufw/docker | `owner`+`persist`; слежение (A) | `flush ruleset` при живом сторожe — таблица на месте; при мёртвом — сирота и затем восстановление | К (без systemd: запуск сторожа вручную); С (службы) |
| Сон/пробуждение | правила в ядре; сверка после пробуждения | — | С |
| Смена сети | набор без имён физических интерфейсов | замена «физического» veth на другой — правила не меняются, утечки нет | К |
| Падение `phantom-netd` | TUN исчезает, `default` в таблице T пропадает, main → `drop` | `kill -9` под потоком | К |
| Падение сторожа | `persist`: сирота; `Restart=always`; усыновление | `kill -9` сторожа под потоком | К (persist в ядре 6.18 по исходнику) |
| Обновление правил | одна транзакция | смена адресов сервера/LAN под потоком — ни одного пакета мимо | К |
| Другие namespaces с выходом через хост | `forward drop` | процесс в namespace без маршрута через хост | К |
| Captive portal | окно по `skuid` с `timeout` | пакет uid ≠ portal — не виден | К |

Не проверяется в контейнере: порядок unit-ов и `Conflicts=shutdown.target`, resolved, реальный DHCP/NetworkManager, сон, PMTUD на реальном пути, правила Docker/firewalld в действии, отличия ядер дистрибутивов (наличие `persist`).

## 6. Часть 4. Кроссплатформенные границы

Специфично для Linux: TUN через `/dev/net/tun`, netlink, nftables (`owner`/`persist`, `bridge`), fwmark и policy routing, systemd (unit-ы, `LogNamespace`), resolved, `SO_PEERCRED`, `SCM_RIGHTS`.

Trait-ы `phantom-network` (эскиз, без привязки к API):

| Trait | Назначение | Linux | Android | iOS/macOS | Windows |
|---|---|---|---|---|---|
| `TunDevice` | чтение/запись IP-пакетов, MTU | fd TUN от сторожа | fd из `VpnService.Builder.establish()` | `NEPacketTunnelFlow` | Wintun |
| `KillSwitch` | `enforce(snapshot)`, `release()`, `state()`, `verify()` | `phantom-guard` + nftables | «Always-on VPN» + «Block connections without VPN» — системные настройки, приложение управляет ими не полностью [Предположение] | `includeAllNetworks` в `NETunnelProviderProtocol` [Не проверено] | WFP-фильтры с постоянной сессией [Не проверено] |
| `ProtectedSocketFactory` | сокет транспорта вне туннеля | `SO_MARK` через сторож | `VpnService.protect()` | сокеты расширения вне туннеля | привязка к интерфейсу + разрешение WFP |
| `RouteManager` | маршруты в туннель | rtnetlink + rules | `addRoute` | `NEIPv4Settings` | `CreateIpForwardEntry2` [Не проверено] |
| `DnsConfigurator` | резолвер туннеля | resolved / файл | `addDnsServer` | `NEDNSSettings` | NRPT/интерфейс [Не проверено] |
| `NetworkMonitor` | смена сети, сон | netlink, logind | `ConnectivityManager` | `NWPathMonitor` | `NotifyIpInterfaceChange` |
| `ControlChannel` | CLI/UI → демон, проверка вызывающего | unix + `SO_PEERCRED` | Binder внутри приложения | XPC | named pipe с ACL |
| `PrivilegeBoundary` | закрытый перечень привилегированных операций | сторож | нет (песочница ОС) | нет | служба Windows |

Норма: `phantom-core` и `phantom-transport` зависят только от trait-ов; гарантия G8 формулируется **на платформу** — на мобильных ОС kill switch обеспечивает ОС, и G8 там слабее или иная.

## 7. Сводка решений и открытые вопросы

| ID | Решение | Статус |
|---|---|---|
| V-06 | `phantom-guard`: таблица `owner`+`persist`, `Before=nftables.service firewalld.service network-pre.target`, `Wants=network-pre.target`, `DefaultDependencies=no`; запасной режим A с `After=`; G8 §1.5 | предлагается High → закрыть после теста на стенде |
| V-07 | `bridge phantom_l2` drop; NAT в TUN опционально | предлагается |
| V-08 | `ct mark` + `related` ICMP-ошибки; `preraw` | предлагается |
| V-04/V-05 | §1.8 | предлагается |
| S-05…S-20 | §3 | предлагается |
| Привилегии | отдельный сторож (вопрос №5 §13 закрыт) | предлагается |

Открытые вопросы к владельцу: (1) минимальные версии ядра и nft для `persist` (дистрибутивы MVP); (2) свой кодировщик nfnetlink в стороже или `libnftables` (C в доверенной базе); (3) captive portal в MVP или только `disconnect`; (4) `allow_lan` и `forward_via_tunnel` нужны ли в MVP; (5) срок `grace` для истёкшей конфигурации.

## Источники

1. Linux, `net/netfilter/nf_tables_api.c` (master): `nft_flush`, `nf_tables_updtable`, `nf_tables_newtable`, обработчик закрытия сокета — https://github.com/torvalds/linux/blob/master/net/netfilter/nf_tables_api.c (прочитан 2026-11-14).
2. Linux, `net/netfilter/nfnetlink.c`: проверка `CAP_NET_ADMIN`, `nfnetlink_bind`, конфигурация сокета ядра — https://github.com/torvalds/linux/blob/master/net/netfilter/nfnetlink.c.
3. Linux, `net/core/sock.c`: `SO_MARK`, `sock_bindtoindex_locked` — https://github.com/torvalds/linux/blob/master/net/core/sock.c.
4. Linux, `net/core/rtnetlink.c`: `rtnetlink_rcv_msg` — https://github.com/torvalds/linux/blob/master/net/core/rtnetlink.c.
5. Linux, `drivers/net/tun.c`: `tun_permitted`, `tun_set_iff` — https://github.com/torvalds/linux/blob/master/drivers/net/tun.c.
6. WireGuard, `wireguard-tools/src/wg-quick/linux.bash`: `add_default`, `del_if`, `remove_firewall` — https://github.com/WireGuard/wireguard-tools/blob/master/src/wg-quick/linux.bash.
7. firewalld, `config/firewalld.conf` — https://github.com/firewalld/firewalld/blob/main/config/firewalld.conf.
8. Локальные файлы контейнера: `/lib/systemd/system/nftables.service`, `/etc/nftables.conf`, `/lib/systemd/system/docker.service`, `/lib/systemd/system/network-pre.target`, `/usr/include/linux/netfilter/{nf_tables,nfnetlink}.h`, `/proc/sys/net/ipv4/ip_unprivileged_port_start`, конфигурация ядра 6.18; `nft -c -f` (nftables 1.0.9).
9. `docs/architecture/reviews/REVERIFY_HIGH.md` (V-04…V-09, `systemd.special(7)` по цитате V3), `REVIEW_SECURITY.md` (S-01…S-20), `docs/research/06-rust-stack.md` §3.6–3.10.
