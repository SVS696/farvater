# Linux amd64 installation

The [Linux guide](../docs/linux.md) covers prerequisites, secret-free staging, private provisioning, read-only `check`, explicit `apply`, and post-install verification.

`download_engines.py` fetches the three pinned upstream inputs. `build_current.py` produces a verifiable public stage; `provision_current.py` creates a separate root-only overlay with fresh secrets. `linux_install.py check` reads both and refuses an existing installation. Only `linux_install.py apply` writes to `/` and enables services. The baseline includes sing-box and TrustTunnel; AWG and ocserv require separately verified build manifests. The corrected kit passed a clean-host Ubuntu 24.04 amd64 installation and reboot check; other distributions need their own acceptance checks.
