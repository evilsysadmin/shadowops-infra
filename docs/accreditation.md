# Chronicles release admission and accreditation

The pure admission policy validates a *claimed* origin, allowed service, SHA, digest and staging-only target. **It does not authenticate the sender.** In particular, a repository_dispatch event received by infra may identify the token owner rather than the source repository. Never populate actorRepository from an untrusted client_payload field.

Before wiring any live dispatch receiver, establish trusted GitHub App identity and independently query the exact source repository and successful workflow run, verify image attestation and digest/SHA linkage, and require staging smoke-test evidence. Production promotion must use an independently stored accredited digest, not the dispatch payload.

No deployment workflow or production authority is granted by this policy alone. This PR does not modify Chess Studio.
