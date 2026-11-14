# Клиент PHANTOM для Windows 10/11 x64 — черновик архитектуры

**Версия:** 0.1-черновик (поток «сеть Windows», фаза 0). **Дата:** 2026-11-14.
**Статус:** черновик для Lead Architect; не нормативен до принятия ADR.
**Кода нет. Ничего из описанного ниже не запускалось на Windows.**

Метки: **[Факт: источник]** — источник прочитан (путь файла или страница из §17);
**[Вывод]**; **[Предположение]**; **[Не проверено]**.

> Документ заполняется по разделам. Раздел с пометкой «(в работе)» ещё не написан.

## 0. Итог и рекомендуемый стек
(в работе)

## 1. Wintun

### 1.1. Версия, лицензия, распространение

- [Факт: `github.com/WireGuard/wintun`, `git ls-remote --tags`] Последний тег —
  **0.14.1**. После него в `master` есть исправления драйвера 2026 года (например
  `dd05092` «driver: fix race condition at Ring->Head», `ec0a6b9` «driver: fix
  missed-wakeup race in ring buffer Alertable signaling», 2026-03-18) — **без
  нового тега**. [Вывод] Выпущенная подписанная сборка, вероятно, всё ещё 0.14.1;
  содержит ли она эти исправления — **[Не проверено]** (`wintun.net` из среды
  недоступен: прокси 403).
- [Факт: Firezone `rust/libs/bin-shared/src/wintun/README.md`] Firezone поставляет
  `wintun-0.14.1.zip` с `wintun.net/builds`, SHA-256
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
  (сумма — по их README, мной не пересчитана).
- [Факт: `wintun/COPYING`, `README.md`] Исходники — **GPLv2**; готовые бинарники
  с `wintun.net` — отдельная «Prebuilt Binaries License»
  (`prebuilt-binaries-license.txt`): распространять `wintun.dll` можно **только
  вместе с ПО, которое использует его через API `wintun.h`** (п. 3d), без
  модификации и реверса (3a, 3b), без использования имён WireGuard/Wintun для
  продвижения (3e); WireGuard LLC оставляет право менять условия (п. 8).
- [Факт: `README.md`] «Do not distribute drivers or files named "Wintun"… Instead
  distribute `wintun.dll` as downloaded from wintun.net». [Вывод] Собственная
  сборка драйвера потребовала бы своей подписи драйвера (EV + портал
  Microsoft Hardware) — **не делать**; поставлять неизменённый `wintun.dll`.
- **Подпись драйвера.** DLL содержит драйвер и устанавливает его при первом
  `WintunCreateAdapter` [Факт: `api/` — установка через SwDevice,
  `api/adapter.c`, `SwDeviceCreate`]. Коммит `2195863` «downlevelshim: remove in
  preparation for full WHQL» (2021) указывает на WHQL-подпись [Предположение;
  сертификат выпущенной DLL не проверялся]. Для PHANTOM важно: **своя подпись
  драйвера не нужна**.
- **Права на драйвер.** [Факт: `driver/wintun.c`, строка 185] Регистрация колец
  разрешена дескриптором `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NWNRNX;;;HI)` —
  только SYSTEM и Администраторы с высоким уровнем целостности. Создание
  адаптера (установка устройства) тоже требует администратора [Вывод].
  Следствие: служба ДОЛЖНА работать как LocalSystem (см. §5).

### 1.2. API (по `README.md` и `api/wintun.h`)

| Функция | Назначение для PHANTOM |
|---|---|
| `WintunCreateAdapter(Name, TunnelType, RequestedGUID)` | Создать адаптер **с фиксированным GUID** — «influences NLA generation deterministically», иначе Windows создаёт новый профиль сети при каждом подключении [Факт: README]. GUID PHANTOM — константа сборки. |
| `WintunOpenAdapter(Name)` | Найти оставшийся адаптер после падения |
| `WintunCloseAdapter` | «if adapter was created with WintunCreateAdapter, removes adapter» [Факт] |
| `WintunDeleteDriver()` | «Deletes the Wintun driver if there are no more adapters in use» — вызывать при деинсталляции [Факт] |
| `WintunGetAdapterLuid` | LUID для WFP (`IP_LOCAL_INTERFACE`), маршрутов, DNS |
| `WintunStartSession(Adapter, Capacity)` | Кольца 128 КиБ…64 МиБ, степень двойки [Факт: `WINTUN_MIN/MAX_RING_CAPACITY`] |
| `WintunReceivePacket`/`ReleaseReceivePacket`, `WintunAllocateSendPacket`/`SendPacket`, `WintunGetReadWaitEvent` | Чтение/запись L3-пакетов; ожидание события при `ERROR_NO_MORE_ITEMS`; `ERROR_BUFFER_OVERFLOW` — кольцо полно (пакет отбрасывается) |
| `WintunGetRunningDriverVersion` | Диагностика |
| `WintunSetLogger` | Журнал драйвера в журнал службы (без секретов) |

- **MTU.** Wintun не задаёт MTU; MTU — свойство IP-интерфейса:
  `MIB_IPINTERFACE_ROW.NlMtu` через `SetIpInterfaceEntry`, для IPv4 и IPv6 отдельно
  [Факт: wireguard-windows `tunnel/addressconfig.go` (`ipif.NLMTU`), Firezone
  `tun_device_manager/windows.rs` (`try_set_mtu`)]. PHANTOM: `NlMtu = 1280` для обоих
  семейств (TRANSPORT §4.1, M1). Wintun принимает пакеты до `0xFFFF` байт
  [Факт: `WINTUN_MAX_IP_PACKET_SIZE`] — проверка длины ≤ 1280 на стороне службы
  перед отправкой в туннель обязательна (M5: больше MTU_TUN в туннель не попадает
  — на Windows это обеспечивает стек по `NlMtu` [Предположение], проверка в коде
  — страховка).
- **Прочие настройки интерфейса** по образцу WireGuard (`addressconfig.go`):
  `RouterDiscoveryBehavior = Disabled`, `DadTransmits = 0`,
  `ManagedAddressConfigurationSupported = false`,
  `OtherStatefulConfigurationSupported = false` [Факт].

### 1.3. Поведение при падении службы

- [Факт: `driver/wintun.c`, `TunProcessNotification`] Драйвер подписан на
  завершение процессов (`PsSetCreateProcessNotifyRoutine`) и при смерти процесса,
  зарегистрировавшего кольца (`OwningProcessId`), принудительно снимает
  регистрацию колец. Пакеты в туннель после этого не читаются.
- Удаляется ли сам адаптер при аварийном завершении процесса (SwDevice-хэндл
  закрывается ОС) — **[Предположение: да]**, подтверждение — эксперимент W-2
  (§14). Firezone проверяет обратное свойство тестом `tunnel_drop.rs` (50 циклов
  создания/удаления адаптера без утечки).
- [Вывод] В любом случае утечки нет: весь трафик мимо Wintun запрещён
  WFP-фильтрами, которые переживают падение (§2.3), а разрешение «интерфейс
  Wintun» без живой сессии ничего не пропускает наружу.
- После перезапуска служба: `WintunOpenAdapter` → если есть — `WintunCloseAdapter`
  (удалить «осиротевший»), затем `WintunCreateAdapter` с тем же GUID и именем
  (wireguard-windows делает до 15 повторов создания при старте во время загрузки —
  `tunnel/service.go`).

### 1.4. Крейт для Rust

| Вариант | Сопровождение | Особенности | Кто использует |
|---|---|---|---|
| `wintun` 0.5.1 (MIT, `nulldotblack/wintun`) | последний коммит 2025-01-28; `windows-sys 0.52` | `load_from_path`, `libloading` | Firezone (`tun_device_manager/windows.rs`: `wintun::load_from_path`) [Факт] |
| `wintun-bindings` 0.7.40 (MIT, `tun2proxy/wintun-bindings`) | коммит 2026-08-17; `windows-sys 0.61.2` | feature `verify_binary_signature` — проверка Authenticode DLL и издателя «WireGuard LLC» перед загрузкой (`src/lib.rs`); опции `async` | Mullvad (`talpid-tunnel/Cargo.toml`: `wintun-bindings = "0.7.39"`) [Факт] |
| Прямой FFI (`LoadLibraryExW` + `GetProcAddress` по `wintun.h`, ~15 функций) | сами | полный контроль, нет транзитивных зависимостей | — |

**Рекомендация (черновик):** `wintun-bindings` с `verify_binary_signature`,
версия закреплена в `Cargo.lock`; DLL загружается **только по абсолютному пути**
из каталога установки (`%ProgramFiles%\PHANTOM\`, ACL — только запись
Администраторов/SYSTEM) — защита от подмены DLL [Вывод]. Запасной вариант —
прямой FFI в отдельном модуле `phantom-network::windows::wintun` (≈300 строк
`unsafe` под отдельный аудит). Критерий выбора — эксперимент W-1.

### 1.5. Почему Wintun, а не wireguard-nt или TAP

- **wireguard-nt** — реализация протокола WireGuard в ядре
  (wireguard-windows сейчас использует именно её: `tunnel/service.go` —
  `driver.CreateAdapter`, журнал «Using WireGuardNT») [Факт]. Шифрование и
  кадрирование PHANTOM (TLS 1.3/QUIC в пространстве пользователя) в неё не
  встраиваются; нужен голый L3-интерфейс [Вывод].
- **TAP-Windows6** — L2 (Ethernet), лишний ARP/широковещательный домен; SYSTEM
  §2.1 уже выбирает TUN (L3).
- **Wintun** — L3, кольца в общей памяти, используется Firezone и Mullvad (через
  крейты выше), есть готовая подписанная сборка.

## 2. WFP — защита от утечек

### 2.1. Факты о платформе

- [Факт: MS-FWP `object-management.md`] Четыре времени жизни объектов WFP:
  **dynamic** — объект добавлен в динамической сессии (`FWPM_SESSION_FLAG_DYNAMIC`),
  живёт до удаления или конца сессии (в том числе при завершении процесса — «RPC
  rundown»); **static** — по умолчанию, живёт до удаления, остановки BFE или
  выключения системы; **persistent** (`FWPM_*_FLAG_PERSISTENT`) — до удаления;
  **built-in**. Фильтры уровней ядра можно пометить boot-time: «добавляются, когда
  стартует драйвер TCP/IP, и удаляются, когда BFE закончит инициализацию»;
  persistent-объекты добавляются при старте BFE.
- [Факт: там же] «At service start, BFE only adds persistent objects to the system if
  they are not associated with a provider, or the associated provider has no Windows
  service name, or the associated Windows service is set to auto-start.»
- [Факт: там же] Объект не может ссылаться на объект с более коротким временем
  жизни: static не ссылается на dynamic; persistent не ссылается на dynamic, static
  и на persistent другого провайдера.
- [Факт: там же] Транзакции ACID; одна транзакция на сессию; ожидание блокировки —
  `txnWaitTimeoutInMSec`, по умолчанию 15 с; для user-mode транзакция принудительно
  прерывается через 1 час.
- [Факт: sdk-api `ns-fwpmtypes-fwpm_filter0.md`] `FWPM_FILTER_FLAG_PERSISTENT` —
  «survives across BFE stop/start»; `FWPM_FILTER_FLAG_BOOTTIME` — «enforced at
  boot-time, even before BFE starts»; эти два флага несовместимы в одном фильтре.
- [Факт: MS-FWP `filter-arbitration.md`] Подслои обходятся от большего веса к
  меньшему, **все** подслои оцениваются; внутри подслоя побеждает первый
  совпавший фильтр по убыванию веса. Между подслоями: «Block overrides Permit»,
  Block окончателен. Умолчания: permit фильтра — **soft**, block фильтра — **hard**.
  Hard permit (снят `FWPS_RIGHT_ACTION_WRITE`, в user-mode —
  `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`) может отменить только **Veto** callout-а;
  «In order to silently override "Hard Permit" filters a firewall has to add its
  filters within a higher priority sub-layer.» Межслойного арбитража нет.
- [Факт: MS-FWP `filter-weight-assignment.md`] Вес фильтра `FWP_UINT8` 0…15 задаёт
  старшие 4 бита (16 диапазонов), младшие 60 бит BFE назначает сам.
- [Факт: sdk-api `ns-fwpmtypes-fwpm_sublayer0.md`] «Higher-weighted sublayers are
  invoked first» (вес подслоя `UINT16`).
- [Факт: MS-FWP `ale-layers.md`] `ALE_AUTH_CONNECT_V{4,6}` — TCP `connect()`, первый
  UDP-пакет к уникальной паре адрес/порт, первое исходящее не-error ICMP;
  `ALE_AUTH_RECV_ACCEPT_V{4,6}` — входящие аналоги. Сырые сокеты обрабатываются
  «как UDP».
- [Факт: MS-FWP `ale-re-authorization.md`] Добавление или удаление фильтра на слое
  ALE вызывает **переавторизацию** уже разрешённых потоков на первом же пакете —
  уже открытые соединения не «проскакивают» после включения запрета.
- [Факт: MS-FWP `best-practices.md`] Microsoft рекомендует динамические сессии,
  собственный подслой, связь объектов с провайдером, явные транзакции.

### 2.2. Как сделано у других

**wireguard-windows** (MIT; `tunnel/firewall/blocker.go`, `rules.go`, `helpers.go`,
коммит `6ece77b`, 2026-09-22):

- [Факт] Сессия `FWPM_SESSION_FLAG_DYNAMIC`, `txnWaitTimeoutInMSec = INFINITE`;
  провайдер и подслой с **случайными** GUID на каждый запуск, вес подслоя
  `0xFFFF` (`blocker.go`, `createWfpSession`, `registerBaseObjects`).
- [Факт] Фильтры (вес-диапазон в скобках): разрешение процессу туннельной службы
  (15) — условия `ALE_APP_ID` (путь exe) **и** `ALE_USER_ID` с дескриптором
  безопасности, выдающим `FWP_ACTRL_MATCH_FILTER` только **SID службы**
  (`S-1-5-80-…`, найден в токене процесса; `helpers.go`,
  `getCurrentProcessSecurityDescriptor`), флаг `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`
  (hard permit), на всех четырёх слоях ALE; блок DNS-порта 53 (14) кроме
  туннельных DNS (15); loopback (13); интерфейс туннеля по LUID (12); DHCPv4,
  DHCPv6, NDP (12); `blockAll` (0) на `ALE_AUTH_CONNECT/RECV_ACCEPT_V4/V6`.
- [Факт] Разрешение службе не ограничено адресом сервера: любой адрес и порт.
- [Факт] Фильтры ставятся только если в единственном peer есть `0.0.0.0/0` или
  `::/0` (`tunnel/addressconfig.go`, `enableFirewall`).
- [Вывод] Модель WireGuard — **fail-open при падении**: динамическая сессия
  исчезает вместе с процессом туннельной службы, фильтры удаляются BFE. Для
  PHANTOM это противоречит SYSTEM §1.4 п. 4 («падение не меняет правил»).

**Mullvad** (GPL-3.0-or-later; `talpid-winfw/src/*`, `talpid-core/src/firewall/windows/mod.rs`,
коммит `e8fd32f`, 2026-11-13; крейт `wfp = "0.3.0"` в корневом `Cargo.toml`):

- [Факт] Сессия **не** динамическая (`context.rs`, `open_engine` без `.dynamic()`):
  объекты — static. Провайдер и два подслоя с **фиксированными** GUID
  (`guids.rs`): «baseline» вес `u16::MAX` и «DNS» вес `u16::MAX − 1`
  (`objects.rs`). Весь DNS (порт 53) «поднимается» из baseline разрешением и
  ограничивается в DNS-подслое (`README.md`).
- [Факт] При старте — `purge_all` всех объектов своих провайдеров одной
  транзакцией, затем база; каждая смена политики — откат к контрольной точке и
  новая политика в **одной транзакции** (`context.rs`, `session.rs`).
- [Факт] Разрешение к серверу — `ALE_AUTH_CONNECT`, адрес **и** порт **и**
  протокол сервера, опционально только для перечня exe (`rules.rs`,
  `install_permit_endpoint`, `app_id_conditions`).
- [Факт] При остановке демона в состоянии «blocked» (`CleanupPolicy::BlockingPersistent`)
  static-объекты в одной транзакции заменяются на **persistent** провайдер,
  persistent подслой (`u16::MAX`) и block-all фильтры в двух наборах —
  `FilterLifetime::Boottime` и `FilterLifetime::Persistent` — «Both are needed to
  keep traffic blocked across a reboot» (`persistent.rs`). В остальных состояниях
  при штатной остановке — `purge` (`lib.rs`, `deinitialize`).
- [Факт] Ранний старт: `mullvad-daemon/src/early_boot_firewall.rs` ставит
  политику `Blocked`.
- [Факт] Hyper-V: отдельные правила брандмауэра Hyper-V через WMI
  (`talpid-core/src/firewall/windows/hyperv.rs`) с предупреждением об утечке, если
  не удалось.
- [Факт] Флаг `CLEAR_ACTION_RIGHT` в `talpid-winfw/src/rules.rs` не встречается
  (поиск по `flag`/`clear`).
- [Факт] Фильтры уровня IP-пересылки (`IPFORWARD`) в `talpid-winfw` не найдены.
- [Вывод] Модель Mullvad — **fail-closed при падении**: static-фильтры переживают
  смерть процесса, но не перезагрузку; persistent/boot-time ставятся только при
  **штатной** остановке (в `Drop`). Падение процесса и затем перезагрузка дают
  окно без защиты до старта демона.
- Лицензия: GPL-3.0 — код Mullvad **не копировать**; использовать как
  справочник архитектуры. `wfp` 0.3.0 — отдельный крейт; его лицензия и
  сопровождение **[Не проверено]**.

### 2.3. Сравнение вариантов для PHANTOM

| Вариант | Падение службы | Перезапуск службы | Перезагрузка | Обновление (замена exe) | Риск |
|---|---|---|---|---|---|
| A. Динамическая сессия (как WireGuard) | фильтры исчезают → **утечка** | окно до переустановки | нет защиты до старта службы | окно | нарушает SYSTEM §1.4 п. 4 |
| B. Static-фильтры (как Mullvad в работе) | остаются | новая служба вычищает и ставит заново одной транзакцией | static исчезают при выключении → окно до старта службы | остаются, если exe-условие не мешает (см. §9) | окно загрузки |
| C. B + persistent block-all + boot-time block-all **с момента `enforcing`** | остаются | как B | boot-time до BFE, persistent после → **нет окна**, пока служба не поставит разрешения | остаются | «кирпич» при сломанной деинсталляции — см. ниже |
| D. Только persistent-фильтры для всего | остаются | как B | остаются в том числе разрешения | остаются | разрешения с путями exe и LUID устаревают; сложная сверка |

**Решение (черновик): вариант C.** [Вывод]

1. Свой провайдер `PHANTOM` и свой подслой `PHANTOM baseline` с **фиксированными**
   GUID, оба `FWPM_PROVIDER_FLAG_PERSISTENT`/`FWPM_SUBLAYER_FLAG_PERSISTENT`;
   вес подслоя `0xFFFF` (как у обоих эталонов). Провайдер связан с именем службы
   (`serviceName = "PhantomService"`), чтобы BFE не применял persistent-объекты,
   если служба удалена или не auto-start [Факт: `object-management.md`; поле
   `serviceName` — «allows BFE to detect that a provider has been disabled»,
   sdk-api `ns-fwpmtypes-fwpm_provider0.md`]. Это предохранитель от «кирпича»
   при сломанной деинсталляции; цена — администратор, отключивший службу,
   отключает и persistent-запрет (он и так может всё) [Вывод]. Влияет ли
   `serviceName` на **boot-time** фильтры — **[Не проверено]**.
2. **Persistent** block-all (вес 0) и **boot-time** block-all на четырёх слоях ALE
   ставятся в той же транзакции, что и переход `off → enforcing`, и снимаются
   только при `enforcing → off`.
3. Разрешения — **static**-фильтры в **том же** подслое с весами 1…15. Это
   принципиально: block в другом подслое — hard и отменил бы разрешения (Block
   overrides Permit). Static-фильтр может ссылаться на persistent-подслой (правило
   «не ссылаться на объект с более коротким временем жизни») [Вывод;
   **Не проверено** запуском — эксперимент W-3, §14].
4. Каждое изменение — одна транзакция: удалить все static-объекты провайдера,
   поставить новые. Перед первой транзакцией после старта — сверка: перечислить
   объекты провайдера (`FwpmFilterEnum0` по провайдеру), удалить лишние.
5. Сессия BFE службы — обычная (не динамическая), `txnWaitTimeoutInMSec` конечный
   (например 5 с, стартовое значение) с понятной ошибкой «другая программа
   держит блокировку WFP» и перечнем процессов с открытыми сессиями (подход
   `sessions.rs` Mullvad) — чтобы служба не зависала навсегда из-за чужой
   программы.

### 2.4. Набор фильтров PHANTOM (`enforcing`)

Слои: `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`, `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`.
Вес — диапазон 0…15 внутри подслоя PHANTOM.

| Вес | Действие | Условия | Слои | Время жизни | Зачем |
|---|---|---|---|---|---|
| 15 | permit, `CLEAR_ACTION_RIGHT` | `ALE_APP_ID` = exe службы **и** `ALE_USER_ID` = SD с SID службы **и** `IP_REMOTE_ADDRESS` ∈ адреса сервера из подписанной конфигурации **и** `IP_REMOTE_PORT` = порт **и** `IP_PROTOCOL` ∈ {UDP для T1, TCP для T2} | CONNECT v4/v6 | static | транспорт к серверу; уже Mullvad (адрес+порт), строже WireGuard (без адреса) |
| 14 | block | `IP_REMOTE_PORT` ∈ {53, 853}, TCP/UDP, `IP_LOCAL_INTERFACE` ≠ Wintun | CONNECT v4/v6 | static | DNS и DoT мимо туннеля — до разрешения LAN; закрывает и опцию `allow_lan` |
| 14 | block | `IP_REMOTE_ADDRESS` ∈ {224.0.0.251, ff02::fb (mDNS), 224.0.0.252, ff02::1:3 (LLMNR)}, порт 137/138 (NetBIOS) | CONNECT v4/v6 | static | многоадресное разрешение имён мимо туннеля |
| 13 | permit | `FWP_CONDITION_FLAG_IS_LOOPBACK` | все 4 | static | loopback |
| 12 | permit | `IP_LOCAL_INTERFACE` = LUID Wintun | все 4 | static | весь трафик в туннеле |
| 12 | permit | DHCPv4 `udp 68→67` (CONNECT) и `67→68` (RECV_ACCEPT); DHCPv6 `fe80::/10:546 → ff02::1:2:547` и обратно | v4/v6 | static | аренда адреса физического интерфейса (по образцу `permitDHCPIPv4/IPv6` WireGuard) |
| 12 | permit | ICMPv6 RS(133)/RA(134)/NS(135)/NA(136) по образцу `permitNdp` WireGuard; **Redirect (137) — нет** | v6 | static | NDP; SYSTEM §3.5 |
| 10 | permit | `allow_lan`: адреса LAN по SYSTEM §3.1 | все 4 | static | только если включено |
| 0 | block | — (всё) | все 4 | **persistent** + **boot-time** | запрет по умолчанию, переживает падение и перезагрузку |

Замечания:

- **IPv6.** Если сервер выдаёт IPv6 (ULA + NAT66, SYSTEM §3.6), он идёт через
  Wintun (вес 12). Если нет — весь IPv6 мимо Wintun блокируется весом 0; на
  Wintun IPv6-адрес не назначается, поэтому приложения получают ошибку, а не
  утечку [Вывод].
- **ICMP-ошибки** внешнего пути к сокету транспорта приходят в рамках ALE-потока
  службы (разрешён весом 15) [Вывод из `ale-re-authorization.md`: поток включает
  пакеты обоих направлений; **Не проверено** для ICMP-ошибок].
- **`ALE_APP_ID` и обновление.** Условие пути exe ломается при переносе exe;
  путь установки фиксирован (`%ProgramFiles%\PHANTOM\phantom-service.exe`),
  обновление заменяет файл на месте (см. §9, §10). `ALE_USER_ID` с SID службы
  (`NT SERVICE\PhantomService`) не зависит от пути и не допускает чужой процесс
  с тем же exe — подход WireGuard (`helpers.go`). Для SID службы она ДОЛЖНА иметь
  `SERVICE_SID_TYPE_UNRESTRICTED` (как `manager/install.go` WireGuard, строка 173).
- **Пересылка (ICS, «мобильный хот-спот»).** ALE пересылаемые пакеты не
  авторизует [Вывод: ALE — уровень сокетов]; для запрета транзита нужны фильтры
  `FWPM_LAYER_IPFORWARD_V4/V6` (block для интерфейсов ≠ Wintun). Ни WireGuard, ни
  Mullvad их не ставят (по прочитанным файлам). Предложение: в MVP ставить block на
  IPFORWARD v4/v6, исключение — только Wintun→Wintun нет (запрещено). **[Не проверено]**
  совместимость с ICS.
- **Hyper-V / WSL2.** Трафик ВМ через виртуальный коммутатор Hyper-V может идти
  мимо ALE хоста (Mullvad ставит отдельные правила брандмауэра Hyper-V через WMI,
  `hyperv.rs`; WireGuard держит `permitHyperV` закомментированным с пометкой
  «layer 2»). В MVP — **остаточный риск**, предупреждение в диагностике; после
  MVP — правила Hyper-V по образцу Mullvad. **[Не проверено]**
- **Сырые кадры NDIS** (драйверы вроде Npcap) минуют стек TCP/IP и ALE —
  аналог `AF_PACKET` на Linux, вне гарантии (требует администратора для установки
  драйвера) [Вывод].

### 2.5. Брандмауэр Windows и чужие WFP-фильтры

- Брандмауэр Windows (MPSSVC) — тоже провайдер WFP со своими подслоями (в
  перечне MS есть, например, `FWPM_SUBLAYER_MPSSVC_WSH`) [Факт:
  `management-filtering-sublayer-identifiers.md`]. Наши block — hard; любой
  разрешающий фильтр брандмауэра в другом подслое **не открывает** обход
  («Block overrides Permit») [Вывод из `filter-arbitration.md`].
- Обратная сторона: block брандмауэра или чужого продукта в любом подслое
  блокирует и наш транспорт. Hard permit (`CLEAR_ACTION_RIGHT`) на разрешении
  службы защищает только от block в **подслоях с меньшим весом**; в подслое с
  большим весом (или того же `0xFFFF` с неопределённым порядком —
  **[Не проверено]**) чужой block победит. Это наблюдаемо: диагностика
  «транспорт к серверу отклонён локальным фильтром» по событию сброса WFP
  (`FWPM_NET_EVENT`, подписка — после MVP) [Предположение].
- Чужой процесс с правами администратора может удалить наши фильтры. Защита —
  DACL объектов (`FwpmFilterSetSecurityInfoByKey0`, пример MS
  `hindering-filter-deletion.md`) **не** даёт гарантии против администратора
  (владелец всегда имеет `WRITE_DAC`, обладатель `SeTakeOwnershipPrivilege` —
  `WRITE_OWNER`) [Факт: комментарии в примере MS]. Решение: DACL не ставить
  (усложняет собственную очистку), а **следить**: подписка
  `FwpmFilterSubscribeChanges0` на объекты нашего провайдера и сверка с
  восстановлением одной транзакцией (аналог слежения SYSTEM §1.4 п. 6)
  [Факт: `FwpmFilterSubscribeChanges0` — «request the delivery of notifications
  regarding changes in a particular filter», sdk-api `nf-fwpmu-fwpmfiltersubscribechanges0.md`;
  есть и `FwpmSubLayerSubscribeChanges0`, `FwpmProviderSubscribeChanges0`; задержка
  восстановления — **Не проверено**].
- Другой VPN-клиент (WireGuard, Mullvad, корпоративный) ставит свой block-all в
  подслое веса `0xFFFF`. Два block-all несовместимы: каждый блокирует чужой
  туннель. Это ожидаемо и должно **диагностироваться**, а не обходиться
  (см. §10, сценарий «другой VPN»).

## 3. DNS
(в работе)

## 4. Маршрутизация IPv4/IPv6
(в работе)

## 5. Служба Windows (SCM)
(в работе)

## 6. Взаимодействие GUI ↔ служба
(в работе)

## 7. Хранение секретов
(в работе)

## 8. Технология интерфейса
(в работе)

## 9. Установщик и обновление
(в работе)

## 10. Сценарии
(в работе)

## 11. Проверяемость на GitHub Actions
(в работе)

## 12. `phantom-network` и интерфейсы платформы
(в работе)

## 13. Требования к защите от утечек на Windows (нормативный черновик)
(в работе)

## 14. Эксперименты фазы 1 на GitHub Actions Windows
(в работе)

## 15. Открытые вопросы владельцу
(в работе)

## 16. Не проверено
(в работе)

## 17. Источники
(в работе)
