# Third-party components

## TrustTunnel deep-link codec

`trusttunnel_deeplink_decode.py` and `trusttunnel_deeplink_encode.py` are unchanged copies of `scripts/deeplink_to_config.py` and `scripts/config_to_deeplink.py` from TrustTunnel v1.0.33. Source: https://github.com/TrustTunnel/TrustTunnel/tree/v1.0.33/scripts . License: `LICENSE-TrustTunnel`. They use only the Python standard library. `trusttunnel_link.py` adds bounded input validation and lossless native/client field-name conversion.
