# Official engine inputs

Run `python install/download_engines.py` from the repository root. The downloader
uses fixed official GitHub release URLs, verifies the SHA-256 values in
`install/build_current.py` and refuses modified existing inputs. These archives
are local build inputs and excluded from Git.

1. sing-box v1.14.1, Linux amd64 — GPL-3.0-or-later.
2. TrustTunnel endpoint v1.0.33, Linux x86_64 — Apache-2.0.
3. TrustTunnel client v1.1.7, Linux x86_64 — Apache-2.0.

The builder retains each upstream LICENSE file. A macOS remote panel does not
need these Linux binaries. AWG and ocserv are optional separate artifacts with
verified manifests; see the Linux deployment guide for their preparation.
