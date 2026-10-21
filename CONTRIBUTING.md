# Contributing to Mac.apk

Thanks for helping. There are two easy ways in.

## Report how an app runs

Most of the work on Mac.apk starts with a report. [Open an issue](https://github.com/kksimp/Mac.apk/issues/new)
with:

- the Mac.apk version and your macOS version,
- the app, its version, and where you got it,
- what happened, and
- the app's log from `~/Library/Logs/macapk/`. Look it over before posting: it records
  touch positions and on-screen messages (typed text is redacted).

Updates to the [compatibility list](COMPATIBILITY.md) are welcome in the same way.

## Send code

1. Read [BUILDING.md](BUILDING.md) and get a build running.
2. Make your change on a branch and open a pull request. Say what it fixes and which
   apps you tested it on.
3. The first time, the CLA bot asks you to sign the [Contributor License Agreement](CLA.md)
   by leaving a comment. You only do this once.

This repository is synced from the project's private development repo. When your pull
request is merged here, it's carried over there with you as the author, and it comes
back out in the next sync.

### How the code is meant to work

- **Behave like Android.** Framework classes under `runtime/java/android/...` mirror
  AOSP's public API and observable behaviour. Check the AOSP source for the same class
  before changing one.
- **No app-specific code.** No branches on a package name, no offsets that only fit one
  app's binary. Fix the framework, shim or translator so every app gets the right
  behaviour.
- **No emulation or virtualization.** Native code runs as arm64 (ARM32 is recompiled to
  arm64), Java runs on HotSpot, and the bridge is at the Bionic libc ABI, not at Linux
  syscalls.
- **License-clean dependencies.** BSD, MIT, Apache-2.0 and similar are fine. No GPL,
  AGPL or LGPL code linked into what ships, because it would stop Mac.apk from being
  offered under a commercial license.
- **Comments explain why.** Especially for ABI work: put the Bionic and macOS layouts
  side by side above a shim.

### Out of scope

Pull requests that defeat license checks or copy protection, forge Play Integrity or
other attestation tokens, bypass account or payment security, or help obtain apps you
don't have the right to use will be closed.

## Security problems

See [SECURITY.md](SECURITY.md). Please don't open a public issue for those.
