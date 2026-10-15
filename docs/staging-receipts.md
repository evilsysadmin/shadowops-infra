# Staging receipt contract

A staging receipt must refer to the exact Chronicles SHA and immutable digest, successful health and smoke checks, and the source workflow run. Production promotion must match the receipt identity byte-for-byte.

This module validates **structure only**. It does not create trustworthy receipts, prove health tests actually ran, store tamper-evident records, or authorize production. A privileged staging deploy workflow must generate and sign or otherwise protect the receipt from its own verified results; production must retrieve it from trusted storage and recheck identity and freshness. Do not accept receipt JSON supplied by an untrusted caller.

No production deploy is enabled; Chess Studio untouched.
