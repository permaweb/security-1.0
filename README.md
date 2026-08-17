# security

HyperBEAM package for `security@1.0`.

## templates

`security@1.0` validates authority by selecting a template for the requested
security key.

template selection:

* explicit: set `<key>-template`
* default for `set-authority`: if any static key exists, use
  `static-signer-set` -- otherwise use `supply-threshold-owner`
* default for everything else: `static-signer-set`

current templates:

* `static-signer-set`: classic signer policy. uses `<key>`,
  `<key>-required`, and `<key>-match`. empty static `set-authority` config
  fails closed.
* `supply-threshold-owner`: dynamic `set-authority`. only valid for
  `set-authority`. it checks one caller, validates the address, reads the
  caller's canonical balance, and compares it to `total-supply`. default
  threshold is `10000` bps (the caller must own 100% of supply)

mixing static `set-authority` keys with `supply-threshold-owner` is rejected

## delegated process actions

Messages with `from-process` must satisfy both the `authority` signer policy and the `authority-actions` action allowlist. The allowlist must be a non-empty list of non-empty binaries and compares actions case-insensitively. A missing or malformed policy fails closed.

This policy only applies to process-delegated identity. Direct wallet messages derive `from` from their verified signers and do not require `authority-actions`.

## build

```sh
rebar3 compile
```

## package

```sh
rebar3 device package --device-src=src,_build/default/lib/hb/src/preloaded/token
rebar3 device verify --device-src=src,_build/default/lib/hb/src/preloaded/token
```

## published package

```bash
Published device: security@1.0; 

Specification ID: ZP5JuNeAUF9Ccec-kKEPEgcgVNcOIHzT5n-hUgOucmY;

Implementation ID: JAVhxFEKwCFbHu6aU9ihh6g-tr6cxCAFMgZQ5e2jsb0;

Signer: vZY2XY1RD9HIfWi8ift-1_DnHLDadZMWrufSh-_rKF0
```

## test

```sh
rebar3 device test
rebar3 eunit-all
```

## local node

```sh
rebar3 device local
```

## publish

```sh
rebar3 device publish --device-src=src,_build/default/lib/hb/src/preloaded/token --key wallet.json
```

## license
this pakcage is licensed under the [MIT License](./LICENSE)
