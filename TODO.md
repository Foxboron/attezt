- Figure out component seperation
- server needs a config *or* a cli (atteztctl?)
- Does atteztctl control the local client cert *and* the server deployment?
- Don't want to expose admin over HTTP/REST, should be local only (varlink?)

# Attestation format/smallstep comments
- SAN fields are wrong? Should be UTF8String, but is PrintableString.
- Should pass EK TPMTPublic, not the serialzied crypto.PublicKey
