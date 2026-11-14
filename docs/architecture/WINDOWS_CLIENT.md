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

### 3.1. Факты

- [Факт: sdk-api `nf-netioapi-setinterfacednssettings.md`] `SetInterfaceDnsSettings(GUID, DNS_INTERFACE_SETTINGS*)`
  задаёт DNS интерфейса; минимальная версия клиента — **Windows 10 Build 19041**
  (2004). Флаги `DNS_SETTING_NAMESERVER` (0x2), `DNS_SETTING_IPV6` (0x1, иначе
  настройка относится только к IPv4), `DNS_SETTING_SEARCHLIST` (0x4),
  `DNS_SETTING_REGISTRATION_ENABLED` (0x8) и др.; поле `EnableLLMNR` — «TRUE to
  enable mDNS and LLMNR on the given interface» [Факт: `ns-netioapi-dns_interface_settings.md`];
  какой флаг включает применение `EnableLLMNR`, в документе не указан —
  **[Не проверено]**. Версия 3 структуры (Build 19645+) добавляет DoH-настройки
  (`DNS_SETTING_DOH` 0x1000).
- [Факт] wireguard-windows: `SetInterfaceDnsSettings`, для Windows < 1809 —
  запись `NameServer`/`SearchList` в реестр `Tcpip(6)\Parameters\Interfaces\{GUID}`
  (`tunnel/winipcfg/luid.go`, `SetDNS`); DNS-порт 53 мимо туннеля закрыт WFP
  (`blockDNS`).
- [Факт] Mullvad: `SetInterfaceDnsSettings` (`talpid-dns/src/windows/iphlpapi.rs`),
  запасной путь через реестр с `EnableMulticast = 0` (отключение LLMNR,
  `tcpip.rs`), сброс кэша; **NRPT не используется** (поиск `nrpt`/`DnsPolicyConfig`
  в `talpid-dns`, `talpid-core` — пусто); весь DNS ограничен отдельным
  подслоем WFP (§2.2).
- [Факт] Firezone: **только NRPT** — правило для всех имён в
  `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{GUID}`,
  при наличии ключа групповой политики — дублирование туда же, потому что «If
  this key exists, our local NRPT rules are ignored» (`dns_control/windows.rs`);
  плюс DNS на интерфейсе «so `ipconfig` and WSL will notice them». Тест
  `dns_control_windows.rs` с комментарием «Passes in CI but not locally».
  Известная проблема (там же): браузер держит открытое QUIC/HTTP-соединение и не
  разрешает имя заново.

### 3.2. Решение (черновик)

1. **Утечку DNS закрывает WFP, а не настройка резолвера** (как SYSTEM §2.4 для
   Linux): фильтры §2.4 запрещают 53/853 TCP/UDP мимо Wintun и многоадресные
   5353/5355, 137/138 [Вывод]. Это верно при любой настройке DNS, при Smart
   Multi-Homed Name Resolution, при чужом NRPT и при ручной смене DNS
   пользователем.
2. **Работоспособность** — `SetInterfaceDnsSettings` на Wintun (IPv4 и IPv6
   отдельными вызовами), адреса резолвера туннеля из подписанной конфигурации;
   метрика Wintun 0 (§4) — чтобы клиент DNS Windows выбирал резолвер туннеля
   первым [Предположение о порядке выбора по метрике — первоисточник не прочитан].
   Сброс кэша после смены. Минимальная версия ОС для MVP — Windows 10 2004
   (Build 19041) — следует из этого API; ветку реестра для старых версий не
   делать.
3. **NRPT «.» → DNS туннеля — не в MVP по умолчанию**, а как кандидат по итогам
   эксперимента W-6. Причины: (а) не нужен для отсутствия утечки (п. 1);
   (б) оставляет состояние в реестре, которое после падения и выключения
   kill switch ломает DNS пользователя; (в) локальные правила NRPT
   игнорируются при наличии групповой политики (по Firezone). Если без NRPT
   разрешение имён медленное или ненадёжное (параллельные запросы к
   заблокированным резолверам физических интерфейсов) — включить NRPT с
   обязательной очисткой в `disconnect`, при старте службы (сверка) и в
   деинсталляторе.
4. **Smart Multi-Homed Name Resolution / параллельные запросы.** Как именно
   Windows рассылает запросы по интерфейсам, по первоисточнику не прочитано
   **[Не проверено]**. Для PHANTOM это вопрос задержки, не утечки (п. 1):
   запросы к резолверам физических интерфейсов блокируются WFP. Проверка — тест
   T-DNS-1 (§13) с захватом на физическом адаптере.
5. **LLMNR, mDNS, NetBIOS.** На Wintun — `EnableLLMNR = FALSE` (и/или
   `EnableMulticast = 0` по образцу Mullvad); мимо туннеля — WFP-блок по портам
   и групповым адресам. NetBIOS over TCP/IP на Wintun — отключить через
   `NetbiosOptions` интерфейса **[Не проверено: способ и необходимость]**.
6. **DoH браузеров.** Браузер с включённым DoH ходит к своему провайдеру DoH по
   443 — **через туннель** (весь трафик туннелирован), поэтому это не утечка мимо
   туннеля; но имена видит провайдер DoH, а не резолвер PHANTOM. Запретить DoH
   браузерам надёжно нельзя (это обычный HTTPS) — **не обещаем**; в диагностике
   можно сообщать «DNS браузера может идти не через резолвер PHANTOM». Windows
   DoH (`DNS_SETTING_DOH` на физическом интерфейсе) — запросы идут по маршруту в
   туннель или блокируются WFP [Вывод].
7. **Имя сервера** — в MVP IP-адрес (SYSTEM §3.2); имя разрешается только в
   `off` при `connect`.


## 4. Маршрутизация IPv4 и IPv6

### 4.1. Факты

- [Факт: wireguard-windows `tunnel/addressconfig.go`] При `0.0.0.0/0` или `::/0`
  в AllowedIPs: маршрут с `Metric = 0` на интерфейс туннеля, у IP-интерфейса
  `UseAutomaticMetric = false`, `Metric = 0`; маршруты ставятся
  `SetRoutesForFamily`; при старте во время загрузки — повторы до 15 раз на
  `ERROR_NOT_FOUND`.
- [Факт: wireguard-windows `tunnel/pitfalls.go`, `pitfallWeakHostSend`]
  Предупреждение: если на интерфейсе, через который лежит маршрут к endpoint,
  включены Forwarding/WeakHostSend, а итоговый маршрут к endpoint ведёт в
  туннель, — «will cause routing loops». [Вывод] WireGuard не ставит отдельный
  маршрут к серверу, а полагается на привязку сокета к физическому интерфейсу.
- [Факт: Mullvad `talpid-wireguard/src/lib.rs`, `get_endpoint_route`] На
  не-Linux ставится маршрут хоста к endpoint через `NetNode::DefaultNode`
  (лучший маршрут по умолчанию физической сети); `talpid-routing/src/windows/route_manager.rs`
  при смене лучшего default **удаляет и заново добавляет** такие маршруты;
  монитор — `NotifyRouteChange2`, `NotifyIpInterfaceChange`,
  `NotifyUnicastIpAddressChange` (`default_route_monitor.rs`), с защитой от
  всплесков событий.
- [Факт: MS `ipproto-ip-socket-options.md`, `ipproto-ipv6-socket-options.md`]
  `IP_UNICAST_IF` — «Gets or sets the outgoing interface for sending IPv4
  traffic. This option does not change the default interface for receiving»;
  значение — индекс интерфейса **в сетевом порядке байт**. `IPV6_UNICAST_IF` —
  индекс **в порядке байт хоста**. Ошибка порядка байт — типичная ловушка.
- [Факт: sdk-api `netioapi`] `NotifyRouteChange2` — изменения маршрутов;
  `NotifyIpInterfaceChange` — изменения IP-интерфейсов;
  `NotifyUnicastIpAddressChange` — изменения unicast-адресов.
- [Факт: Firezone `network_changes/windows.rs`] Ручные замеры задержки
  обнаружения смены сети (Wi-Fi ↔ хот-спот, подключение Ethernet и т. д.) и
  случаи, которые **не** обнаруживаются (например, «On Ethernet and Wi-Fi,
  disconnect Ethernet, not detected»). Их числа к PHANTOM не переносятся.

### 4.2. Решение (черновик)

1. **Маршрут по умолчанию**: `0.0.0.0/0` и `::/0` на Wintun с метрикой маршрута 0
   и метрикой интерфейса 0 (`UseAutomaticMetric = false`) — как WireGuard.
   Альтернатива `0.0.0.0/1 + 128.0.0.0/1` (`::/1 + 8000::/1`) побеждает любой
   `/0` без сравнения метрик, но (а) не помогает против более узких маршрутов
   (option 121), (б) влияет на определение «есть Интернет» в Windows
   **[Не проверено]**. Выбор — эксперимент W-5; **утечку в обоих вариантах
   закрывает WFP**, маршрутизация влияет только на работоспособность.
2. **IPv6**: если сервер выдаёт IPv6 — `::/0` в туннель; если нет — IPv6-адреса и
   маршрута на Wintun нет, весь IPv6 мимо туннеля блокирует WFP (вес 0).
3. **Сокеты транспорта (T1 UDP, T2 TCP)**: перед `connect`/первой отправкой —
   `IP_UNICAST_IF`/`IPV6_UNICAST_IF` на индекс выбранного физического интерфейса.
   Отдельный маршрут хоста к серверу **не ставится** (нет системного состояния,
   которое нужно чистить после падения). Если W-5 покажет, что привязки
   недостаточно (например, выбор следующего узла всё равно идёт по `/0` туннеля),
   — запасной вариант Mullvad: маршрут хоста `/32` (`/128`) к каждому адресу
   сервера через шлюз лучшего физического default, пересоздаваемый по событиям.
4. **Выбор физического интерфейса**: лучший default-маршрут без Wintun
   (`GetIpForwardTable2`, минимум «метрика маршрута + метрика интерфейса», только
   интерфейсы в `IfOperStatusUp`) — логика как в `pitfallWeakHostSend` и
   `get_best_default_route.rs`. Пересчёт по трём уведомлениям с подавлением
   всплесков (например, 500 мс — стартовое значение). Смена интерфейса →
   событие `NetworkChanged` в автомат клиента (TRANSPORT §7.2: T1 — rebind +
   SizeProbe, T2 — новое соединение).
5. **Проверка WeakHostSend/Forwarding** физических интерфейсов — предупреждение в
   диагностике (как `pitfalls.go`).
6. **TunnelVision-подобные атаки (DHCP option 121, маршруты из RA).** Windows
   ставит бесклассовые маршруты DHCP в таблицу маршрутов; они уже `/0` туннеля
   и уводят выбранные префиксы на физический интерфейс [Вывод из правила
   наибольшего совпадения префикса]. **Утечки нет**: ALE-фильтры разрешают
   мимо Wintun только процесс службы к адресу сервера; остальное — block (вес 0).
   Остаток: выборочный **отказ** в доступе к этим префиксам и наблюдаемость
   попыток (аналог SYSTEM §3.5, RR14). Служба при каждом `NotifyRouteChange2`
   ищет маршруты не через Wintun, которые перекрывают адреса вне LAN, и
   сообщает наблюдение «сеть объявила маршруты в обход туннеля; трафик к ним
   запрещён». Удалять чужие маршруты не следует (их вернёт DHCP-клиент).
7. **MTU** — §1.2.


## 5. Служба Windows (SCM)

### 5.1. Минимальные права — что требуется

- **WFP**: DACL движка по умолчанию — `GENERIC_ALL` Администраторам,
  `GRGWGX` группе Network Configuration Operators и SID нескольких системных
  служб (MpsSvc, PolicyAgent и др.); всем — только `OPEN` и `CLASSIFY`
  [Факт: MS-FWP `access-control.md`]. LocalService (минимальные привилегии,
  анонимен в сети [Факт: `localservice-account.md`]) и виртуальная учётная
  запись службы не входят в эти группы → **не могут** добавлять фильтры
  [Вывод].
- **Wintun**: регистрация колец — только `SY` и `BA` с высоким уровнем
  целостности (§1.1); создание адаптера — установка устройства [Вывод].
- Изменение маршрутов, адресов, `SetIpInterfaceEntry`, DNS — права
  администратора [Предположение: страницы API не говорят явно; на практике
  WireGuard, Mullvad, Firezone выполняют их из службы LocalSystem].
- **Вывод:** минимально возможная учётная запись для привилегированной части —
  **LocalSystem**. Сужение — через SCM:
  - `SERVICE_SID_TYPE_UNRESTRICTED` — SID службы `NT SERVICE\PhantomService` в
    токене с `SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER` [Факт:
    `ns-winsvc-service_sid_info.md`]; нужен для WFP-условия `ALE_USER_ID` (§2.4)
    и ACL файлов/канала.
  - `SERVICE_REQUIRED_PRIVILEGES_INFO` — SCM удаляет из токена всё, что не
    перечислено («It is best to analyze your service and use the minimum set of
    privileges required») [Факт: `ns-winsvc-service_required_privileges_infow.md`].
    Точный минимальный набор (вероятно `SeLoadDriverPrivilege` для первой
    установки драйвера Wintun — WireGuard сохраняет именно его,
    `elevate/privileges.go`, `DropAllPrivileges(retainDriverLoading)`) —
    **[Не проверено]**, эксперимент W-2.
  - Сброс прочих привилегий после инициализации — `AdjustTokenPrivileges` с
    `SE_PRIVILEGE_REMOVED` (подход WireGuard) [Факт: `elevate/privileges.go`].

### 5.2. Разделение процессов (отличие от Linux, ADR-0014)

На Linux сторож с привилегиями не разбирает сеть, демон туннеля без привилегий
(SYSTEM §2.5). На Windows прямой перенос дорог: кольца Wintun может
регистрировать только SYSTEM/Администратор, поэтому непривилегированный
процесс не может читать и писать пакеты — их пришлось бы пересылать между
процессами (общая память или канал) с лишним копированием. Все три
рассмотренных продукта (WireGuard: туннельная служба LocalSystem со сбросом
привилегий; Mullvad: демон; Firezone: «tunnel service») держат разбор сети в
привилегированном процессе [Факт: прочитанные файлы §2.2, §1.4; для Firezone —
наличие `windows-service` в `rust/Cargo.toml` и тест «Tunnel service rejects a
non-allowlisted GUI» в `_tauri.yml`].

Варианты для решения Lead Architect (нужен ADR):

| Вариант | Безопасность | Цена |
|---|---|---|
| W-A. Один процесс `phantom-service` (LocalSystem, сокращённые привилегии, SID службы) | компрометация разборщика TLS/QUIC = SYSTEM | минимальная; как у эталонов |
| W-B. `phantom-service` (сторож: WFP, Wintun, маршруты, DNS) + `phantom-netd` — вторая служба с виртуальной учётной записью `NT SERVICE\PhantomNetd` (без админ-прав); пакеты через общую память; сокеты транспорта открывает `phantom-netd`, WFP-разрешение по его SID | граница как на Linux | копирование пакетов (не измерено), сложность, второй сервис |

**Рекомендация (черновик): W-A для MVP** с правилами SYSTEM §3.9 (без `unwrap`/
`panic` в разборе, fuzz) и явной записью отступления от ADR-0014 в ADR; W-B —
после измерения стоимости копирования (стенд C). [Вывод]

### 5.3. Конфигурация службы

| Параметр | Значение | Обоснование |
|---|---|---|
| Тип | `SERVICE_WIN32_OWN_PROCESS` | как WireGuard (`manager/install.go`) |
| Запуск | `SERVICE_AUTO_START` (не delayed) | persistent-объекты провайдера применяются BFE, только если служба провайдера «set to auto-start» (§2.1); считается ли delayed auto-start — **[Не проверено]** |
| Зависимости | `BFE`, `Nsi`, `TcpIp` | WireGuard: `Nsi`, `TcpIp`; `BFE` — наш [Вывод] |
| Учётная запись | LocalSystem | §5.1 |
| SID службы | `SERVICE_SID_TYPE_UNRESTRICTED` | §5.1 |
| Привилегии | `SERVICE_REQUIRED_PRIVILEGES_INFO` — минимум | §5.1 |
| Recovery | рестарт через 0 с, 1 с, 5 с; сброс счётчика через 1 сутки; `fFailureActionsOnNonCrashFailures = TRUE` («failure actions are queued if the service process terminates without reporting SERVICE_STOPPED or … dwWin32ExitCode is not ERROR_SUCCESS») [Факт: `ns-winsvc-service_failure_actions_flag.md`] | падение = рестарт; ненулевой код выхода тоже |
| Принимаемые команды | `STOP`, `PRESHUTDOWN` (или `SHUTDOWN`), `POWEREVENT` | ниже |
| Путь exe | `%ProgramFiles%\PHANTOM\phantom-service.exe`, ACL каталога — запись только SYSTEM и Администраторам | `ALE_APP_ID`, защита DLL (§1.4) |

Крейт **`windows-service`** 0.8.1 (MIT OR Apache-2.0, сопровождает Mullvad,
обновлён 2026-05-08; используют Firezone `rust/Cargo.toml` и Mullvad) —
поддерживает `ServiceControl::PowerEvent(PowerEventParam::{Suspend,
ResumeAutomatic, ResumeSuspend, …})`, `Preshutdown`, `ServiceSidType`,
`set_failure_actions_on_non_crash_failures` [Факт: `windows-service-rs/src/service.rs`].
Обязательные привилегии (`SERVICE_REQUIRED_PRIVILEGES_INFO`) в крейте не найдены
поиском — вызвать `ChangeServiceConfig2W` через `windows-sys` **[Не проверено]**.

### 5.4. Поведение (нормативный черновик)

1. **Остановка службы командой `STOP`** (в том числе обновлением) **не снимает**
   kill switch: static-разрешения удаляются, persistent/boot-time block-all
   остаются, если состояние `enforcing` (аналог SYSTEM §1.4 п. 4 и
   `CleanupPolicy::BlockingPersistent` Mullvad, но persistent-запрет стоит с
   момента `enforcing`, а не только при остановке).
2. **Падение** — фильтры остаются (static + persistent), Wintun-кольца снимает
   драйвер (§1.3), SCM перезапускает службу; новая служба сверяет объекты WFP
   (§2.3 п. 4), пересоздаёт адаптер, восстанавливает соединение.
3. **Сон и пробуждение**: `SERVICE_ACCEPT_POWEREVENT`; на `PBT_APMSUSPEND` —
   ничего не снимать (фильтры — состояние BFE); на `PBT_APMRESUMEAUTOMATIC` —
   событие `Resumed` в автомат (TRANSPORT §7.4: проба живости + SizeProbe).
   Firezone выбирает именно `PBT_APMRESUMEAUTOMATIC`, потому что
   `PBT_APMRESUMESUSPEND` приходит только при присутствии пользователя
   [Факт: `power/windows.rs`]. Дополнительно — признак по скачку времени
   (TRANSPORT §7.4).
4. **Смена сети** — §4.2 п. 4.
5. **Перезагрузка в `enforcing`**: boot-time block-all до старта BFE,
   persistent block-all после; служба стартует автоматически, ставит
   разрешения. Окно без защиты отсутствует **по документации** (§2.1);
   подтверждение — только ручной чек-лист владельца (перезагрузка на GitHub
   Actions невозможна, §11).
6. **Состояние** `off|enforcing` — файл в `%ProgramData%\PHANTOM\state\`
   (ACL: SYSTEM и SID службы — полный доступ, Администраторы — чтение), запись
   атомарно (`ReplaceFileW` или запись во временный + `MoveFileExW(…,
   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`) [API — **Не проверено**
   по документации]. Источник истины для WFP — сами объекты BFE; файл нужен для
   сверки после перезапуска.


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
