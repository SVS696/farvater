# Реестр сценариев панели

Реестр построен по текущим обработчикам публичного выпуска. Ссылка в таблице указывает руководство по функции. Сверены подготовка, действия, область изменений, проверка результата и возврат по обработчикам и формам. Этот реестр не является отчётом о проверке VPN или восстановления на реальном оборудовании.

| Метод и путь | Обработчик / действия | Руководство |
|---|---|---|
| `ROUTE /login` | `login` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /logout` | `logout` | [panel-rules-dns.md](panel-rules-dns.md) |
| `GET /` | `index` | [panel-rules-dns.md](panel-rules-dns.md) |
| `GET /<name>` | `page` | [panel-rules-dns.md](panel-rules-dns.md) |
| `GET /server/access` | `server_access` | [panel-monitoring.md](panel-monitoring.md) |
| `POST /server/access` | `server_access_save` | [panel-monitoring.md](panel-monitoring.md) |
| `POST /backups/create` | `backup_create` | [panel-backups.md](panel-backups.md) |
| `POST /backups/upload` | `backup_upload` | [panel-backups.md](panel-backups.md) |
| `POST /backups/<value>/download` | `backup_download` | [panel-backups.md](panel-backups.md) |
| `POST /backups/<value>/delete` | `backup_delete` | [panel-backups.md](panel-backups.md) |
| `GET /configuration` | `policy_configuration` | [panel-backups.md](panel-backups.md) |
| `POST /configuration/export` | `policy_export` | [panel-backups.md](panel-backups.md) |
| `POST /configuration/import` | `policy_import` | [panel-backups.md](panel-backups.md) |
| `POST /configuration/confirm` | `policy_import_confirm` | [panel-backups.md](panel-backups.md) |
| `GET /configuration/<group>/<identifier>/delete` | `entity_delete_preview` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /configuration/<group>/<identifier>/delete` | `entity_delete` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /lan/save` | `lan_save` | [panel-devices.md](panel-devices.md) |
| `POST /vpn-ingress/save` | `vpn_ingress_save` | [panel-devices.md](panel-devices.md) |
| `POST /filtering/save` | `filtering_save` | [panel-rules-dns.md](panel-rules-dns.md) |
| `GET /health/settings` | `monitor_settings` | [panel-monitoring.md](panel-monitoring.md) |
| `GET /health/settings/<identifier>` | `monitor_settings` | [panel-monitoring.md](panel-monitoring.md) |
| `POST /health/dashboard` | `monitor_dashboard` | [panel-monitoring.md](panel-monitoring.md) |
| `GET /health/settings/new` | `monitor_new` | [panel-monitoring.md](panel-monitoring.md) |
| `POST /health/settings/new` | `monitor_add` | [panel-monitoring.md](panel-monitoring.md) |
| `POST /health/settings/<identifier>/remove` | `monitor_remove` | [panel-monitoring.md](panel-monitoring.md) |
| `POST /health/settings/<identifier>` | `monitor_save` | [panel-monitoring.md](panel-monitoring.md) |
| `GET /health/switches` | `routing_history` | [panel-monitoring.md](panel-monitoring.md) |
| `POST /failover/control` | `routing_save` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /failover/probes` | `probe_save` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /candidate/<action>` | `candidate_action` — apply, confirm, rollback | [panel-rules-dns.md](panel-rules-dns.md) |
| `GET /rules/default` | `default_rule_form` | [panel-rules-dns.md](panel-rules-dns.md) |
| `GET /rules/new` | `rule_form` | [panel-rules-dns.md](panel-rules-dns.md) |
| `GET /rules/<identifier>/edit` | `rule_form` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /rules/save` | `rule_save` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /rules/reorder` | `rule_reorder` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /rules/<identifier>/move` | `rule_move` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /rules/<identifier>/delete` | `rule_delete` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /failover/timing` | `failover_timing` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /failover/save` | `failover_save` | [panel-rules-dns.md](panel-rules-dns.md) |
| `GET /dns/new` | `dns_form` | [panel-rules-dns.md](panel-rules-dns.md) |
| `GET /dns/<identifier>/edit` | `dns_form` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /dns/<identifier>/hosts-export` | `dns_hosts_export` | [panel-rules-dns.md](panel-rules-dns.md) |
| `POST /dns/save` | `dns_save` | [panel-rules-dns.md](panel-rules-dns.md) |
| `GET /connections/new` | `connection_new` | [panel-connections.md](panel-connections.md) |
| `GET /tunnels/new` | `tunnel_form` | [panel-connections.md](panel-connections.md) |
| `GET /tunnels/<identifier>/edit` | `tunnel_form` | [panel-connections.md](panel-connections.md) |
| `GET /trusttunnel-new` | `trusttunnel_new` | [panel-connections.md](panel-connections.md) |
| `POST /trusttunnel-create` | `trusttunnel_create` | [panel-connections.md](panel-connections.md) |
| `POST /trusttunnel-complete/<identifier>` | `trusttunnel_create` | [panel-connections.md](panel-connections.md) |
| `POST /trusttunnel/<identifier>/<action>` | `trusttunnel_action` — apply, check, confirm, disable, discard, enable, export, import, rollback, save, start, stop | [panel-connections.md](panel-connections.md) |
| `POST /openconnect/<identifier>/<action>` | `openconnect_action` — apply, check, confirm, disable, discard, enable, export, import, rollback, save, start, stop | [panel-connections.md](panel-connections.md) |
| `GET /openvpn-new` | `openvpn_new` | [panel-connections.md](panel-connections.md) |
| `POST /openvpn/<action>` | `openvpn_action` — export, import, save | [panel-connections.md](panel-connections.md) |
| `GET /shadowsocks-import` | `shadowsocks_import_form` | [panel-connections.md](panel-connections.md) |
| `POST /shadowsocks-import` | `shadowsocks_import` | [panel-connections.md](panel-connections.md) |
| `POST /tunnels/<identifier>/export-ss` | `shadowsocks_export` | [panel-connections.md](panel-connections.md) |
| `POST /vless-import` | `vless_import` | [panel-connections.md](panel-connections.md) |
| `POST /tunnels/<identifier>/export-vless` | `vless_export` | [panel-connections.md](panel-connections.md) |
| `POST /connections/import-native` | `outbound_import_native` | [panel-connections.md](panel-connections.md) |
| `POST /openconnect-import` | `embedded_openconnect_import` | [panel-connections.md](panel-connections.md) |
| `POST /tunnels/<identifier>/export-native` | `outbound_export_native` | [panel-connections.md](panel-connections.md) |
| `POST /tunnels/save` | `tunnel_save` | [panel-connections.md](panel-connections.md) |
| `GET /devices/trusttunnel` | `tt_clients_page` | [panel-devices.md](panel-devices.md) |
| `POST /devices/trusttunnel/<server_id>/<action>` | `tt_clients_action` — delete, export, import, recover, save, settings | [panel-devices.md](panel-devices.md) |
| `GET /devices` | `clients_page` | [panel-devices.md](panel-devices.md) |
| `POST /devices/add` | `clients_add` | [panel-devices.md](panel-devices.md) |
| `POST /devices/<client_id>/<action>` | `clients_toggle` — disable, enable | [panel-devices.md](panel-devices.md) |
| `POST /devices/finish` | `clients_finish` | [panel-devices.md](panel-devices.md) |
| `POST /devices/settings` | `clients_settings` | [panel-devices.md](panel-devices.md) |
| `POST /devices/<client_id>/rename` | `clients_rename` | [panel-devices.md](panel-devices.md) |
| `POST /devices/<client_id>/import` | `clients_import` | [panel-devices.md](panel-devices.md) |
| `POST /devices/<client_id>/export` | `clients_export` | [panel-devices.md](panel-devices.md) |
| `GET /amnezia-new` | `amnezia_new` | [panel-connections.md](panel-connections.md) |
| `POST /amnezia/create` | `amnezia_create` | [panel-connections.md](panel-connections.md) |
| `POST /amnezia/<profile>/register` | `amnezia_register` | [panel-connections.md](panel-connections.md) |
| `GET /wireguard-new` | `wireguard_new` | [panel-connections.md](panel-connections.md) |
| `POST /wireguard/create` | `wireguard_create` | [panel-connections.md](panel-connections.md) |
| `GET /amnezia` | `wireguard_page` | [panel-connections.md](panel-connections.md) |
| `GET /amnezia/<profile>` | `wireguard_page` | [panel-connections.md](panel-connections.md) |
| `GET /wireguard` | `wireguard_page` | [panel-connections.md](panel-connections.md) |
| `GET /wireguard/<profile>` | `wireguard_page` | [panel-connections.md](panel-connections.md) |
| `POST /amnezia/<profile>/<action>` | `wireguard_save` — abandon, apply, check, confirm, disable, discard, enable, export, import, rollback, save, start, stop | [panel-connections.md](panel-connections.md) |
| `POST /wireguard/<profile>/<action>` | `wireguard_save` — abandon, apply, check, confirm, disable, discard, enable, export, import, rollback, save, start, stop | [panel-connections.md](panel-connections.md) |
| `GET /devices/incoming` | `incoming_page` | [panel-devices.md](panel-devices.md) |
| `GET /devices/incoming/new` | `incoming_edit` | [panel-devices.md](panel-devices.md) |
| `GET /devices/incoming/<identifier>/edit` | `incoming_edit` | [panel-devices.md](panel-devices.md) |
| `POST /devices/incoming/save` | `incoming_save` | [panel-devices.md](panel-devices.md) |
| `POST /devices/incoming/<identifier>/delete` | `incoming_delete` | [panel-devices.md](panel-devices.md) |
| `POST /devices/incoming/<identifier>/import` | `incoming_import` | [panel-devices.md](panel-devices.md) |
| `POST /devices/incoming/<identifier>/import-client` | `incoming_import_client` | [panel-devices.md](panel-devices.md) |
| `POST /devices/incoming/<identifier>/export` | `incoming_export` | [panel-devices.md](panel-devices.md) |
| `POST /backups/trust/export` | `backup_trust_export` | [panel-backups.md](panel-backups.md) |
| `GET /backups/<value>/restore/status` | `backup_restore_status` | [panel-backups.md](panel-backups.md) |
| `GET /backups/restore/<job_id>` | `backup_restore_page` | [panel-backups.md](panel-backups.md) |
| `GET /backups/recovery/help` | `recovery_runbook` | [panel-backups.md](panel-backups.md) |
| `POST /backups/<value>/restore/<action>` | `backup_restore_action` — confirm, prepare, rollback, start | [panel-backups.md](panel-backups.md) |
| `ROUTE /recovery/login` | `recovery_login` | [panel-backups.md](panel-backups.md) |
| `GET /recovery/access-check` | `recovery_access_check` | [panel-backups.md](panel-backups.md) |
| `GET /recovery/<job>` | `recovery_state` | [panel-backups.md](panel-backups.md) |
| `POST /recovery/<job>/<action>` | `recovery_action` — confirm, rollback, start | [panel-backups.md](panel-backups.md) |

Машиночитаемый реестр с файлами, строками, хешами и состоянием проверки: [scenario-coverage.json](scenario-coverage.json).

Динамический `/<name>` включает обзор, мониторинг, правила, подключения, DNS, устройства/LAN, изменения, копии, помощь и фильтрацию; `/failover` перенаправляет к автоматике правил. Типы протоколов и режимы форм сверяются отдельно с каталогом и редакторами.
