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

## build

```sh
rebar3 compile
```

## package

```sh
rebar3 device package
rebar3 device verify
```

## published package

```bash
device publish: security@1.0 

spec=qtC0Ae3Yt78mN8jqWG2dH14grcUK9CKhAtd3dsJ-ft0 

impl=cfKDo4KvBzje-teLrwcLn98LY7DeecFdX1r7HgEcGtI 

signer=vZY2XY1RD9HIfWi8ift-1_DnHLDadZMWrufSh-_rKF0
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
rebar3 device publish --key wallet.json
```

## license
this pakcage is licensed under the [MIT License](./LICENSE)