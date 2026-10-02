# Фарватер · Farvater

Панель управления сетью: маршрутизация по доменам и устройствам, DNS, фильтрация
AdGuard, резервные выходы, VPN-клиенты, мониторинг и защищённое восстановление.

Farvater is a self-hosted network control panel. Each machine can run its own node and send traffic through other nodes.
Portable proxy/DNS nodes run on macOS and Linux. A full Linux gateway uses
systemd; macOS TUN/LAN gateway support has separate privileged setup and validation. All per-host
credentials and network configuration are created locally and kept outside Git.

> Первый релиз — **alpha**. Полный macOS VPN/LAN gateway реализован в отдельном
> экспериментальном режиме; реальная kernel/LAN приёмка ещё открыта.

## Платформы

| Сценарий | Требования | Граница |
|---|---|---|
| Linux — сервер и панель | systemd, x86_64/amd64, Python 3.11+, Linux network tools | [Установка сервера](docs/linux.md) |
| macOS — локальный узел / Mac mini | Python 3.11+, pinned Darwin sing-box | [Локальный узел и VPN-шлюз](docs/macos.md) |
| Linux — локальная панель | Python 3.11+, SSH-доступ к Linux backend | Тот же переносимый launcher |
| Windows | Поддержка не заявлена | Используйте браузер для доступа к Linux-панели |

Дистрибутив выбирается по наличию необходимых инструментов, а не названию Ubuntu.
Архитектуры и дистрибутивы, на которых release фактически проверен, перечислены
в [матрице проверок](docs/validation.md). Каждый узел имеет собственные входы, политику и выходы. Узлы можно соединять
защищёнными туннелями и использовать следующий узел как выход; обязательного
центрального Linux-сервера нет. Системный и LAN-шлюз на Mac использует Darwin TUN
и отдельную административную настройку. Его фактическая kernel/LAN приёмка
отмечается отдельно от проверки локальных DNS/proxy.

## Быстрый запуск локальной панели

```sh
git clone https://github.com/SVS696/farvater.git
cd farvater
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python tools/run_panel.py --help
```

Следуйте [инструкции первого запуска](docs/macos.md), чтобы создать локального
администратора и настроить проверенный SSH-доступ. Панель слушает только loopback.
Пароли вводятся интерактивно и не передаются в аргументах команды.

## Linux backend

1. Подготовьте зависимости и административный HTTPS-доступ по [Linux guide](docs/linux.md).
2. Получите фиксированные движки: `python install/download_engines.py`.
3. Создайте проверяемый stage и отдельное приватное состояние нового хоста.
4. Выполните read-only preflight установщика, затем явную установку.
5. Проверьте вход, службы, DNS/HTTP и recovery access до настройки клиентского трафика.

Временное применение правил требует подтверждения. Если срок истёк, прежнее
состояние возвращается независимой защитой. Резервные копии шифруются для вашего
age key и подписываются ключом установки. Предварительная проверка архива не
заменяет фактическую проверку восстановления на отдельном стенде.

## Разработка

```sh
.venv/bin/python -m unittest discover -s src -p 'test_*.py'
.venv/bin/python -m unittest discover -s install -p 'test_*.py'
.venv/bin/python -m unittest discover -s tools -p 'test_*.py'
```

Некоторые проверки требуют Linux/root/systemd и пропускаются на Mac. Прохождение
unit tests не означает поддержку каждого native-протокола на каждой платформе.
CI запускает переносимый набор на Linux и macOS. [Карта кода](docs/architecture.md)
показывает основные границы и содержит ссылки на Graphify-проекцию.

## Лицензия и безопасность

Собственный код: [Apache-2.0](LICENSE). Происхождение отдельных файлов и лицензии
движков: [NOTICE](NOTICE) и [dependencies](docs/dependencies.md).
Реквизиты, состояния, сертификаты и backup-архивы не входят в репозиторий.
Инструкции по административной границе и сообщениям об уязвимостях: [SECURITY.md](SECURITY.md).
