# Проверки v0.1.0-alpha.1

| Проверка | Среда | Результат |
|---|---|---|
| Полный application suite | macOS arm64, Python 3.11 | 1185 OK, 45 платформенных пропусков |
| Installation suite | macOS и изолированная Ubuntu 24.04 amd64 | 14 OK |
| Portable tools | macOS arm64, Darwin sing-box 1.14.1 | 42 OK, включая настоящий core, DNS, proxy и цепочку узлов |
| Чистая установка | Новая Ubuntu 24.04 amd64 с systemd, без host mounts | Первый check/apply без ручного исправления; четыре службы, доверенный main/recovery HTTPS, DNS UDP/TCP, SOCKS HTTP и reboot |
| Цепочка узлов | Mac → проверенный SSH forward → Linux core | DNS/HTTP проходят; после разрыва новые DNS/SOCKS запросы отказывают без наблюдаемого прямого обхода |
| Защищённый Mac gateway | Python 3.9 syntax, 29 mocked OS tests, native Darwin config check | Код проверен; реальная kernel/LAN/PF/reboot приёмка не выполнена |

Linux установщик выбирает среду по capabilities — systemd и необходимым tools —
а не имени Ubuntu. Ubuntu 24.04 amd64 является фактически проверенным full backend.
Fedora, Arch, Debian и Linux arm64 этим прогоном не подтверждены. Portable loader
имеет фиксированные официальные Darwin/Linux arm64/amd64 inputs; наличие архива
не заменяет проверку соответствующей платформы.

Полный Mac IPv4 TCP/UDP gateway реализован как отдельный экспериментальный режим.
Для фактической приёмки нужен выделенный Mac с двумя сетевыми интерфейсами и
LAN-клиентом: TUN, системный DNS, TCP/UDP, scoped PF, отказ и возврат после reboot.
Рабочая сеть текущего Mac не использовалась для такого теста. Первый релиз поэтому
публикуется как prerelease.

Независимый Codex review защищённого Mac helper нашёл три воспроизводимых дефекта.
Они исправлены; повторный bounded review чистый. Это не заменяет actual gateway
acceptance. Полный public tree/history secret scan и CI выполняются отдельно
перед публикацией и после неё. Physical touch и полный screen reader не проверены.
