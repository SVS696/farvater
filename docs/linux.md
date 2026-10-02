# Установка Фарватера на Linux amd64

Это путь для **нового отдельного Linux-узла** с systemd. Публичный комплект содержит ядро sing-box, клиент и входящий endpoint TrustTunnel, панель и независимое восстановление. Подключения, ключи и домашние сети создаются после установки. AmneziaWG и ocserv добавляются отдельно из проверенных сборок; базовой установке они не нужны.

На новой пустой изолированной Ubuntu 24.04 amd64 VM проверены первая установка без ручных исправлений, вход в панель и rescue по HTTPS, DNS, SOCKS→HTTP и автозапуск после перезагрузки. Это не доказывает работу на каждом дистрибутиве. Инсталлятор проверяет возможности хоста и отказывает при несовместимости или существующей установке; он не выбирает пакетный менеджер и не меняет готовую сеть автоматически.

## Подготовка хоста

Нужны Linux amd64, systemd с каталогом `/usr/local/lib/systemd/system`, `/usr/bin/python3` версии 3.11+, модуль `venv`, `/usr/bin/age` и `age-keygen`, `/usr/bin/caddy`, `/usr/bin/curl`, `/usr/bin/sudo`, `visudo`, `ip`, `nft`, `openssl`, `systemd-sysusers`, `systemd-tmpfiles`, `systemd-analyze`, `systemd-run`, а также `dpkg-query`, `rpm` или `pacman` для инвентаря пакетов. Для установки Python-зависимостей нужен доступ к проверенному PyPI-зеркалу. Утилиты и сертификат устанавливает администратор до запуска инсталлятора.

На **выделенной** Ubuntu 24.04 VM проверялась установка пакетов `python3-venv age caddy curl sudo iproute2 nftables`. На других apt/dnf/pacman-системах названия пакетов и поведение служб могут отличаться; сначала установите перечисленные возможности своим пакетным менеджером и выполните `check`. Рецепты для Fedora и Arch пока не прошли чистую приёмку. Если пакетная `caddy.service` уже обслуживает другие сайты, не отключайте её ради этого рецепта: `check` остановится, потребуется отдельный план интеграции с существующим HTTPS proxy.

До установки получите обычный сертификат для выбранного HTTPS-имени: `fullchain.pem` и `privkey.pem` должны быть ссылками из `/etc/letsencrypt/live/<имя>/` на закрытые файлы в `/etc/letsencrypt/archive/`. Укажите административные CIDR, которые могут открывать панель, и добавьте `127.0.0.1/32` для локальной проверки. Выберите DNS-сервер, доступный этому узлу. Для двух HTTP health URL нужен стабильный ответ 200 **до и во время** временного восстановления; основная панель в pending недоступна, поэтому её `/overview` не подходит. Если используете `https://<имя>/recovery/login`, заранее обеспечьте разрешение имени и прохождение административного CIDR с самого сервера. Эти probes проверяют доступ, а DNS и клиентский трафик проверяйте отдельно.

## Собрать и проверить комплект

Команды ниже выполняются из публичного checkout. Подставьте своё HTTPS-имя, сети и адреса; примеры не содержат готовой домашней топологии. Приватный каталог и stage должны быть доступны только root.

```sh
python3 install/download_engines.py
sudo install -d -m 0700 /var/lib/farvater-setup
sudo /usr/bin/python3 install/build_current.py --destination /var/lib/farvater-setup/stage
sudo sha256sum /var/lib/farvater-setup/stage/manifest.json
```

Сохраните напечатанный SHA-256 manifest и сверьте его с источником выпуска или с собственной контролируемой сборкой. Сборщик проверяет SHA официальных архивов и создаёт staging без секретов; он ещё ничего не устанавливает. Для AmneziaWG/ocserv передайте `--amnezia-engine`, `--ocserv-engine` и точную версию пакета ocserv только после отдельной проверки их manifest. Встроенный ocserv-движок из этого workflow проверен для Ubuntu 24.04 amd64; другой Linux он не объявляет совместимым.

`provision_current.py` использует текущий policy compiler и поэтому требует Python-зависимости в отдельном подготовительном venv. Пароль администратора вводится скрыто; не передавайте его через аргумент команды и не сохраняйте overlay в Git.

```sh
sudo /usr/bin/python3 -m venv /var/lib/farvater-setup/prep-venv
sudo /var/lib/farvater-setup/prep-venv/bin/python -m pip install --require-hashes \
  -r install/requirements-linux-amd64-py311.lock
sudo /var/lib/farvater-setup/prep-venv/bin/python -B install/provision_current.py \
  --source /var/lib/farvater-setup/stage/rootfs/opt/farvater/app \
  --destination /var/lib/farvater-setup/private \
  --username ADMIN --dns DNS_IP --host vpn.example.org \
  --before-url https://vpn.example.org/recovery/login \
  --after-url https://vpn.example.org/recovery/login \
  --tls-chain /etc/letsencrypt/live/vpn.example.org/fullchain.pem \
  --tls-key /etc/letsencrypt/live/vpn.example.org/privkey.pem
```

Из корня checkout тот же venv запускает тесты установочного комплекта без изменения `PYTHONPATH`: `sudo /var/lib/farvater-setup/prep-venv/bin/python -B -m unittest discover -s install -q`.

Private overlay содержит хеш пароля, новые ключи подписи и age, токен ядра, настройки и независимый rescue-secret. Он остаётся только на целевом хосте. Сохраните age recovery key и публичный trust export **отдельно** от зашифрованного backup; не публикуйте overlay, `.env` или готовый stage с добавленными приватными файлами. После первого проверенного backup и внешнего сохранения ключа уберите подготовительный каталог с дубликатами секретов вручную, проверив точный путь; инсталлятор его автоматически не удаляет.

## Проверить без установки, затем применить

В `PIN` вставьте SHA-256, полученный и проверенный на предыдущем шаге. `check` читает stage, overlay, сертификат, capabilities, свободный HTTPS-порт и целевые пути. Он не копирует файлы, не создаёт пользователей и не запускает службы. `apply` повторяет проверки и откажется перезаписывать существующее состояние.

```sh
PIN='проверенный-64-символьный-sha256'
sudo /usr/bin/python3 -B install/linux_install.py check \
  --stage /var/lib/farvater-setup/stage \
  --overlay /var/lib/farvater-setup/private \
  --manifest-sha256 "$PIN" \
  --owner-network 127.0.0.1/32 --owner-network ADMIN_CIDR --https-port 443
sudo /usr/bin/python3 -B install/linux_install.py apply \
  --stage /var/lib/farvater-setup/stage \
  --overlay /var/lib/farvater-setup/private \
  --manifest-sha256 "$PIN" \
  --owner-network 127.0.0.1/32 --owner-network ADMIN_CIDR --https-port 443
```

Инсталлятор копирует только проверенные файлы в пустые пути, создаёт `okopy-panel` и отдельного `okopy-recovery`, два hash-locked venv, root-owned recovery/TLS state, защищённый Caddyfile и certbot renewal hook. Hook обновляет полную TLS-пару и перезапускает только защищённый HTTPS unit; сертификат должен оставаться в certbot `live/archive`. Проверки unit, sudo, sing-box и Caddy выполняются **до** включения четырёх служб: ядра, панели, rescue и независимого HTTPS. Если установка остановилась между копированием и включением, ничего автоматически не удаляйте и не запускайте повторно поверх частичного состояния: посмотрите сообщение, файлы и статус systemd, затем устраните конкретную причину на этом хосте. Рецепт предназначен для чистого узла, не для обновления существующей установки.

После установки проверьте `systemctl is-active okopy-candidate.service okopy-panel.service infrastructure-recovery-ui.service infrastructure-recovery-https.service`, вход по HTTPS с разрешённой сети и отдельный `/recovery/login`. Проверьте DNS на `127.0.0.1:5301` и SOCKS на `127.0.0.1:2081` через известный тестовый HTTP-адрес. Затем выполните контролируемую резервную копию и восстановление в своём изолированном стенде; наличие работающей панели само по себе не подтверждает recovery.

## Роль узла и связи с Mac

Этот Linux-узел может работать сам по себе либо как один из нескольких узлов цепочки. Он не является обязательным центральным контроллером других машин. Локальная Mac mini может иметь собственный движок и политику; если ей нужен Linux-выход как следующий хоп, используйте уже существующий SOCKS/HTTP outbound или аутентифицированное SSH-перенаправление **только loopback-порта** Linux-узла, например `ssh -N -L 127.0.0.1:12081:127.0.0.1:2081 user@linux-host`, после проверки ключа хоста. Клиенты с SOCKS5h передают DNS через туннель; остальные приложения требуют отдельной DNS-настройки. Инсталлятор не меняет автоматически системные маршруты, LAN или политику Mac.
