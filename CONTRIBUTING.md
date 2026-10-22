# Contributing to Apk on Mac

Thanks for helping.

## Report how an app runs

[Open an issue](https://github.com/totktonado96/apk-on-mac/issues/new) with:

- the Apk on Mac version and your macOS version,
- the app, its version, and where you got it,
- what happened, and
- the app's log from `~/Library/Logs/macapk/`. Look it over before posting: it records
  touch positions and on-screen messages (typed text is redacted).

Updates to the [compatibility list](COMPATIBILITY.md) are welcome the same way. You can
also reach the maintainer on Telegram: https://t.me/baha_kabulov

## Send code

1. Read [BUILDING.md](BUILDING.md).
2. Make your change on a branch and open a pull request. Say what it fixes and which
   apps you tested it on.
3. By contributing you agree your work is released under the AGPL-3.0, like the rest of
   the project.

### How the code is meant to work

- **Behave like Android.** Framework classes under `runtime/java/android/...` mirror
  AOSP's public API and observable behaviour.
- **No app-specific code.** No branches on a package name. Fix the framework, shim or
  translator so every app gets the right behaviour.
- **No emulation or virtualization.** Native code runs as arm64, Java runs on HotSpot,
  and the bridge is at the Bionic libc ABI.
- **Comments explain why.**

Pull requests that defeat license checks or copy protection, forge attestation tokens,
bypass account or payment security, or help obtain apps you don't have the right to use
will be closed.

## Security problems

See [SECURITY.md](SECURITY.md). Please don't open a public issue for those.
