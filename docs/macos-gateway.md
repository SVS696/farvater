# Экспериментальный системный и LAN VPN-шлюз macOS

Этот режим делает Mac отдельным IPv4-узлом цепочки: собственный трафик Mac и
трафик выделенной клиентской LAN проходят через TUN к следующему серверу
Shadowsocks 2022. Код подготовлен; реальная приёмка ядра macOS, PF, launchd,
перезагрузки и физической LAN пока **не выполнена**. Тесты с имитацией системных
команд и успешный `sing-box check` этого не заменяют. На рабочем Mac режим не
применялся. Для обычной локальной панели и непривилегированного узла см.
[macos.md](macos.md).

## Точный объём

1. Нужны два разных активных физических интерфейса `enN`: upstream с IPv4 и
   отдельная RFC1918 клиентская LAN с уже назначенным адресом и маской.
   Одноинтерфейсная схема, Internet Sharing, уже включённая маршрутизация и
   пересекающийся VPN не поддерживаются.
2. Следующий узел принимает `shadowsocks`, метод
   `2022-blake3-aes-128-gcm`, один base64 ключ из 16 байт, фиксированный IPv4 и
   порт. TCP и UDP проходят через этот зашифрованный транспорт. На следующем
   узле должен работать UDP этого же порта. Plain SOCKS, произвольные core
   конфигурации и внешние сертификаты/файлы в root-конфигурации не принимаются.
3. LAN и локальный Mac получают DNS через собственный sing-box: TCP resolver
   также отправляется через Shadowsocks. Есть listener на LAN IPv4:53 и
   `127.0.0.1:53`. Helper меняет DNS только явно выбранного upstream network
   service и сохраняет/восстанавливает прежний список, включая автоматический
   выбор `Empty`. Другие network services не меняются.
4. Режим IPv4. IPv6 на клиентской LAN должен быть отключён заранее; обнаруженный
   `inet6` вызывает отказ. PF блокирует весь исходящий IPv6 Mac, а также IPv6
   входящий с LAN. Поддержка IPv6, IPv6 DNS и IPv6 acceptance не заявлены.
5. Это весь IPv4-трафик, кроме явных management exclusions, endpoint следующего
   узла и служебных адресов. Management exclusions имеют прямой доступ к сети;
   выбирайте их узко. На LAN нет DHCP-сервера, NAT или DNS redirect/rdr. Адрес,
   DHCP и шлюз клиентов настраивает администратор существующей сети.
6. Helper строит фиксированную защищённую конфигурацию из ограниченных settings.
   Он не импортирует пользовательский Python и не исполняет web UI от root.
   Этот режим не переносит целиком Linux policy/compiler: исходный LAN IP не
   передаётся следующему proxy hop. Правила по клиентским IP на следующем узле
   не эквивалентны правилам исходного Linux-шлюза.

## Защищённая граница

В `/Library/Application Support/Farvater/Gateway` с root:0700 находятся копии
stdlib helper, pinned core, manifest, ограниченный config, PF rules, root
receipt и private logs. Все предки helper/core должны принадлежать root и не
быть доступны на запись другим пользователям. Постоянная служба использует
`/usr/bin/python3 -I`; реализация совместима с синтаксисом Python 3.9. Требуется
доступная системная Python 3; helper не устанавливает интерпретатор или пакеты.

Setup сам проверяет SHA-256 оригинального архива sing-box **1.14.1** до
извлечения в protected runtime. Пользовательский manifest не является
доказательством подлинности для root. Из архива извлекается только обычный
файл `sing-box`; ссылки и произвольные пути не используются.

| Darwin архив | SHA-256 |
|---|---|
| arm64 | `b9024642ef7b4848252df5469b7f60ef3c18bb5e217a16a0934f0174f8ad11b4` |
| amd64 | `b34381b047106fe84895df14f7aaae06f3182130b728006944deb0d59d8590c3` |

Администратор вызывает CLI через обычный `sudo`; широкого sudoers-разрешения и
root HTTP API нет. Web UI остаётся непривилегированным и не применяет gateway
settings. Пароль поступает только из private JSON, не из argv и не печатается.
Receipt содержит settings с секретом; его нельзя публиковать или прикладывать
к issue.

## Подготовка на изолированном Mac

Дальнейшие команды предназначены для административной установки на отдельном
тестовом Mac. Сначала подготовьте второй сетевой адаптер и клиентскую LAN.
Проверку с реальными клиентами и физической консолью нельзя пропускать.

1. Получите официальный `.tar.gz` из
   [release sing-box 1.14.1](https://github.com/SagerNet/sing-box/releases/tag/v1.14.1):
   `sing-box-1.14.1-darwin-arm64.tar.gz` для Apple Silicon или
   `sing-box-1.14.1-darwin-amd64.tar.gz` для Intel. Сохраните локально; helper
   проверит встроенный digest. Проверьте читаемый исходник перед bootstrap.
2. В существующих main PF filter rules первым действующим filter rule должен
   быть `anchor "com.apple/*" all`. Helper отказывается работать, если этого
   нет, если собственный anchor занят, другие Apple child anchors содержат
   filter rules или уже существуют PF states. Он не переписывает main PF rules
   и не очищает чужие states. Такие строгие ограничения предназначены для
   выделенного тестового шлюза.
3. Установите защищённую копию helper и watchdog. Замените пути фактическими
   абсолютными путями вашего checkout и архива:

   ```sh
   sudo /usr/bin/python3 -I /absolute/farvater/tools/mac_gateway.py setup \
     --archive /absolute/private/sing-box-1.14.1-darwin-arm64.tar.gz
   ```

   Setup не меняет PF, forwarding, DNS или маршруты. При частичной ошибке он
   сохраняет файлы для административного разбора и не запускает VPN. Повторный
   setup поверх существующей установки запрещён; это не автоматический upgrade.
4. Создайте private JSON `gateway-settings.json`, принадлежащий текущему
   администратору или root, с правами `0600`. Вставьте настоящий ключ в редакторе,
   не в shell argument или публичный пример:

   ```json
   {
     "lan_interface": "en7",
     "upstream_interface": "en0",
     "lan_cidr": "192.168.77.0/24",
     "lan_address": "192.168.77.1",
     "management_cidrs": ["192.168.1.1/32"],
     "upstream": {
       "type": "shadowsocks",
       "method": "2022-blake3-aes-128-gcm",
       "server": "192.168.1.20",
       "server_port": 8388,
       "password": "REPLACE_PRIVATE_BASE64_16_BYTE_KEY"
     },
     "dns_server": "1.1.1.1",
     "system_dns_service": "Wi-Fi",
     "tun_interface": "utun231",
     "tun_address": "198.18.231.1/30"
   }
   ```

   Значения — пример. `en7`, LAN адрес/маска, `en0`, service `Wi-Fi`, endpoint и
   свободный `utun231` должны соответствовать вашему Mac. Server может быть
   публичным либо RFC1918 IPv4 вне клиентской LAN; IPv6, loopback, link-local и
   benchmark endpoints запрещены. Management — RFC1918 CIDR или точный IPv4 /32.

## Check, apply и подтверждение

Все команды после setup исполняют только защищённую копию:

```sh
sudo /usr/bin/python3 -I "/Library/Application Support/Farvater/Gateway/mac_gateway.py" check \
  --settings /absolute/private/gateway-settings.json
sudo /usr/bin/python3 -I "/Library/Application Support/Farvater/Gateway/mac_gateway.py" apply \
  --settings /absolute/private/gateway-settings.json --seconds 120
```

Check проверяет topology и снимаемость прежнего состояния; это не packet
acceptance. Apply дополнительно выполняет native `sing-box check`, PF dry parse
и проверяет регистрацию независимого watchdog **до** networking writes. Потом
он сохраняет прежние маршруты, PF/main rules, состояние PF и forwarding,
прежний native DNS, boot identity и журнал намерений. Он последовательно ставит
fail-closed filter, получает собственный PF enable reference, запускает
защищённую core job, добавляет собственные маршруты, переключает DNS и последним
включает IPv4 forwarding.

TUN использует `auto_route: false`. Helper вычисляет CIDR complement выбранных
exclusions и добавляет только отсутствующие destinations. Default route не
меняется, существующие маршруты не заменяются. Весь выбранный TUN /30 и каждый
планируемый destination проходят проверку коллизий, включая существующие более
точные маршруты и host routes внутри покрываемых диапазонов. Явные exclusions
и более широкие маршруты, которые уступают новым TUN prefixes, сохраняются. Core job хранится в runtime,
а не в autoload `LaunchDaemons`: после reboot она не активируется сама.

PF anchor `com.apple/farvater` запрещает direct LAN-source → WAN и весь
остальной исходящий трафик, кроме точного зашифрованного TCP/UDP endpoint:port,
явных management exclusions, своего TUN, loopback и своей LAN. Поэтому смерть
TUN не открывает общий WAN fallback для Mac. Явные исключения остаются прямыми
по определению. `strict_route` не используется как macOS failsafe.

1. В течение confirmation window настройте отдельного клиента: gateway и DNS
   `192.168.77.1`. Проверьте TCP, UDP, DNS TCP/UDP, внешний адрес и management
   доступ с Mac и клиента, затем проверку отсутствия direct WAN и IPv6 обхода.
   Клиент не должен иметь другого активного шлюза или IPv6-router.
2. Только после фактической проверки подтвердите lease:

   ```sh
   sudo /usr/bin/python3 -I "/Library/Application Support/Farvater/Gateway/mac_gateway.py" confirm
   ```

   Confirm фиксирует решение администратора, не выполняет удалённую packet
   приёмку вместо него. Watchdog продолжает следить за core identity.
3. Статус и ручной откат:

   ```sh
   sudo /usr/bin/python3 -I "/Library/Application Support/Farvater/Gateway/mac_gateway.py" status
   sudo /usr/bin/python3 -I "/Library/Application Support/Farvater/Gateway/mac_gateway.py" rollback
   ```

## Откат и восстановление

Watchdog — отдельная root launchd job с `RunAtLoad` и интервалом 5 секунд;
закрытие UI/терминала её не отменяет. Он обнаруживает неподтверждённый deadline,
смерть/смену core, незавершённое применение и смену boot identity. Networking
операции CLI сериализованы root lock; каждая команда имеет timeout 15 секунд.
Во время apply deadline проверяется перед следующей route mutation, после
выбора DNS непосредственно перед forwarding и после системного вызова forwarding.
Истечение lease вызывает собственный rollback, даже если операция DNS или
forwarding была медленной. Это не обещание нулевой задержки rollback.

Откат сначала выключает принадлежащее lease forwarding, затем останавливает
только собственную protected launchd core job с проверкой PID birth/executable
и core SHA, удаляет только destinations с own TUN interface, восстанавливает
native DNS, очищает только собственный PF anchor и освобождает только свой
PF `-E` token через `-X`. `pfctl -f /etc/pf.conf`, `-F all` и `-d` не используются.
PF enable output журналируется отдельно, чтобы восстановить token после
смерти вызывающего процесса между системным вызовом и записью receipt.

Повторный manual rollback receipt в состоянии `rolled-back` ничего не меняет
и не повторяет системные вызовы; более поздние изменения администратора
сохраняются. После reboot unfinished/confirmed lease сначала возвращается в состояние
`rolled-back`; автоматического VPN restart нет. Изменённый PID, замена маршрута,
повреждённый receipt или protected core/config/job требуют административного
разбора. Helper не убивает произвольный PID и не угадывает старую конфигурацию.
При несовпадении ownership он оставляет PF filter и сообщает отказ. Проверяйте
private receipt/logs на физической консоли, сохраняйте прежние файлы; не
публикуйте секретные settings и не применяйте глобальный PF reset.

## Что проверено и что осталось

Проверено без административной сетевой записи: синтаксис Python 3.9,
29 tests с имитацией OS commands (отказ до mutation, route collisions, IPv6,
PF states, timer registration failure, повреждённый receipt, чужой PID, scoped
rollback, deadline/core-death/reboot, старт до сохранения PID и token journal, повторный rollback, более точные чужие маршруты, deadline
внутри операций DNS/forwarding),
а также настоящий `sing-box 1.14.1 check` для построенной SS2022 конфигурации.

Открытая обязательная приёмка: protected install через системный Python,
настоящие launchd/PF parse+anchor semantics, TUN и manual routes, native DNS,
TCP/UDP/IPv6 packet captures Mac+физический LAN клиент, закрытие UI, истечение
lease, смерть core и reboot pending, проверка полного восстановления прежних
настроек. До этой приёмки публичный статус — **experimental / unverified kernel
and LAN**, не готовый принятый macOS VPN appliance. Существующий Linux сервер
этой реализацией не меняется.

Простота: stdlib helper и два точных launchd задания нужны для защищённой
границы и независимого восстановления; отдельные root web/API, sudoers wildcard,
оркестратор и импорт всего пользовательского compiler не добавлены.

## Первичные основания

1. [Pinned TUN configuration](https://github.com/SagerNet/sing-box/blob/v1.14.1/docs/configuration/inbound/tun.md)
   и [Darwin route implementation](https://github.com/SagerNet/sing-tun/blob/v0.9.3/tun_darwin.go):
   Darwin route add может заменить existing route при `EEXIST`; close не
   восстанавливает заменённый предшествующий route. Это основание manual routes
   с отказом на коллизии. Darwin CLI очищает DNS cache, а не выбирает native
   system resolver; helper отдельно сохраняет и меняет выбранный service.
2. [Apple TN3165: Packet Filter is not API](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api):
   PF используется здесь административным инструментом для выделенного шлюза,
   не обещанием стабильной API массового продукта.
3. [Shadowsocks 2022 specification](https://shadowsocks.org/doc/sip022.html):
   выбранный fixed-endpoint шифрованный транспорт поддерживает TCP и UDP;
   UDP следующего узла должен быть реально проверен, не принят наличием config.
