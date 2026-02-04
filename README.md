attezt
======

`attezt` is an remote attestation server.

This entire project is a WIP, unsure how feature complete it will be.

## Usage

`attezt` needs a small CA chain. Create this with `attezt`.

```
λ » attezt ca create
```

`atteztd` runs the attestation server. Note that this will sign any certificates that are capable of solving the challenge.
```
λ » atteztd
2025/12/22 23:13:31 HTTP server listening on :8080
```

Add the provider into `step-ca`.

```
λ ~ » curl -O http://127.0.0.1:8080/root.pem
λ ~ » step ca provisioner add acme-da \
   --type ACME \
   --challenge device-attest-01 \
   --attestation-format tpm \
   --attestation-roots ./root.pem
```

To use this service with `step ca certificate` you can run something similar to the below thing.

```
# Create an attestation certificate
λ ~ » step ca certificate \
  --attestation-ca-url 'http://127.0.0.1:8080' \
  --attestation-uri 'tpmkms:name=ak;ak=true' \
  --provisioner acme-da device-ak device-ak.key akcrt

# Device certificate attested by ak
λ » step ca certificate \
  --attestation-ca-url 'http://127.0.0.1:8080' \
  --attestation-uri 'tpmkms:name=device-key;attest-by=ak' \
  --provisioner acme-da device device device.crt
```

You can also renew a device certificate.

```
λ » step ca renew --force --kms "tpmkms" ./device 'tpmkms:name=device'
```
