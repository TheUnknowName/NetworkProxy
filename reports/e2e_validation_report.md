# NetworkProxy E2E Validation Report

- generated_at: 2026-04-01 02:53:59
- config: config/proxy_e2e.yaml
- scope: TCP + UDP + CONNECT + certificate generation + TLS MITM plaintext patch

## Results
- TCP: PASS
- UDP: PASS
- CONNECT: SKIP: tls handshake failed after openssl install
- TLS_MITM_PATCH: SKIP: tls handshake failed after openssl install
- LEAF_CERT: SKIP: tls handshake failed after openssl install
