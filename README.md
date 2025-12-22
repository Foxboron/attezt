attezt
======

`attezt` is an remote attestation server.

This entire project is a WIP, unsure how feature complete it will be.

## Usage

`attezt` needs a small CA chain. Create this with `attezt`.

```
λ » attezt -create-certs
```

`atteztd` runs the attestation server. Note that this will sign any certificates that are capable of solving the challenge.
```
λ » atteztd
2025/12/22 23:13:31 HTTP server listening on :8080
```

To use this service with `step ca certificate` you can run something similar to the below thing.

```
λ » step ca certificate \
  --attestation-uri 'tpmkms:name=device-key' \
  --attestation-ca-url 'http://127.0.0.1:8080' \
  --provisioner acme-da test device device.crt
```
