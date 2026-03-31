# NetworkProxy E2E Validation Report

- generated_at: 2026-04-01 01:44:03
- config: config/proxy_e2e.yaml
- scope: TCP + UDP + CONNECT + certificate generation + TLS MITM plaintext patch

## Results
- TCP: PASS
- UDP: PASS
- CONNECT: SKIP: openssl not found
- TLS_MITM_PATCH: SKIP: openssl not found
- LEAF_CERT: SKIP: openssl not found
