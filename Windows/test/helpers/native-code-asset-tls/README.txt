Synthetic self-signed TLS certificate and key for owned loopback unit tests only.
The fixture certificate uses the pinned origin name so the tests retain real
hostname verification. Only the test VM trusts this certificate; production
uses the ordinary operating-system/Node CA store and has no CA override.
