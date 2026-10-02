# Зависимости и происхождение

Python>=3.11. `requirements.txt` использует фиксированный lock с hashes для
Flask, Waitress, Paramiko, cryptography и их зависимостей. Lock первоначально
разрешён для Linux amd64; фактические установки на других платформах проверяются
отдельно и указаны в validation matrix. Название lock не заменяет такую проверку.

| Компонент | Версия | Upstream | Лицензия |
|---|---|---|---|
| sing-box | 1.14.1 Linux amd64 | [SagerNet/sing-box](https://github.com/SagerNet/sing-box/releases/tag/v1.14.1) | GPL-3.0-or-later |
| TrustTunnel endpoint | 1.0.33 Linux x86_64 | [TrustTunnel](https://github.com/TrustTunnel/TrustTunnel/releases/tag/v1.0.33) | Apache-2.0 |
| TrustTunnel client | 1.1.7 Linux x86_64 | [TrustTunnelClient](https://github.com/TrustTunnel/TrustTunnelClient/releases/tag/v1.1.7) | Apache-2.0 |

Это фиксированные совместно проверяемые версии; они не объявлены последними
upstream версиями. `install/download_engines.py` получает точные официальные
архивы и сверяет SHA-256. Builder сохраняет оригинальные LICENSE каждого движка.
Архивы и исполняемые движки исключены из source history.

AmneziaWG и ocserv подключаются отдельно через verified manifests. Их исходные
проекты, package/build inputs и LICENSE должны сохраняться вместе с такими
дополнительными движками; отсутствие optional engine не выдаётся за native acceptance.

`src/trusttunnel_deeplink_encode.py` и `src/trusttunnel_deeplink_decode.py`
адаптированы из TrustTunnel v1.0.33. Оригинальная Apache-2.0 лицензия Adguard
Software Ltd сохранена в `src/LICENSE-TrustTunnel`; см. NOTICE.
