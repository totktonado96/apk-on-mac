<p align="center">
  <img src="images/apk-on-mac-logo.svg" width="128" height="128" alt="Apk on Mac logo">
</p>

<h1 align="center">Apk on Mac</h1>

<p align="center">
  <b>Run Android apps natively on Apple Silicon Macs.</b><br>
  No emulator, no virtual machine, no Linux underneath.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License: AGPL-3.0"></a>
  <img src="https://img.shields.io/badge/platform-macOS%2026.4%2B-lightgrey" alt="macOS 26.4+">
  <img src="https://img.shields.io/badge/arch-Apple%20Silicon-6d5dfc" alt="Apple Silicon">
  <img src="https://img.shields.io/badge/status-alpha-orange" alt="Status: alpha">
</p>

---

> **Apk on Mac is a community fork of [Mac.apk](https://github.com/kksimp/Mac.apk)
> by Kaleb Simpson (Voltare).** It is not affiliated with, endorsed by, or an
> official release of the Mac.apk project. "Mac.apk" and its logo belong to their
> owner; see [TRADEMARKS.md](TRADEMARKS.md).

## What it is

Apk on Mac runs Android apps directly on Apple Silicon. Each app becomes an ordinary
macOS app: it has its own window and Dock icon, draws through the Mac's GPU, and
runs at native speed.

There is no emulator. Android is not booted in the background, and there is no
Linux kernel underneath. Instead, the Android application environment is
implemented directly on macOS:

| Part of an APK | How it runs |
|---|---|
| Java / Kotlin (DEX) | converted to JVM bytecode once, then run on a bundled OpenJDK |
| Android framework | reimplemented in Java to behave like AOSP |
| 64-bit ARM native code | loaded as is through an ELF loader and a Bionic → Darwin libc shim |
| 32-bit ARM native code | recompiled to arm64 ahead of time |
| OpenGL ES / Vulkan | ANGLE and MoltenVK, both on Metal |

The upstream wiki explains the design in depth:
[How Mac.apk works](https://github.com/kksimp/Mac.apk/wiki/How-Mac.apk-Works).

## Why a fork

This fork tracks upstream and adds fixes and features that are still under review
upstream, or that go in a different direction:

- **Keyboard:**
  - Russian and other non-Latin layouts work: WASD and Cmd+C/V use the physical
    key position.
  - Keys no longer stick after Cmd+Tab.
  - Home, End, Page Up/Down and F1–F12 work.
- **Notifications:** Android notifications appear in macOS Notification Center,
  and clicking one opens the app.
- **Text-to-speech:** apps speak with macOS voices, and utterance callbacks
  actually fire.
- **Keep awake:** video apps keep the display awake through
  `FLAG_KEEP_SCREEN_ON` and wake locks.
- **Audio:** sound survives switching output devices, such as connecting AirPods.
- **Window:** a Window menu (⌘M, Zoom), and the window position is remembered
  per app.
- **Reliability:**
  - Alarms and reminders keep working (PendingIntent identity).
  - AsyncTask cancellation behaves like Android.
  - The per-app language persists across restarts.
  - 2FA apps get the HMAC-SHA1 keys they need.
  - The macOS system proxy is honoured.
- **Native layer:**
  - Correct arm64 `open()` flags.
  - Linux errno numbers in file calls.
  - TCP keepalive options are mapped to their macOS equivalents.
  - Static recursive mutexes are accepted.
  - Missing Bionic symbols were added.
- **Installer:**
  - The update dialog no longer promises to keep your data when it won't.
  - An app can't be uninstalled while it is running.
  - Free disk space is checked before installing.
  - App names that clash with built-in macOS apps are detected.

Upstream pull requests for these:
[#58](https://github.com/kksimp/Mac.apk/pull/58),
[#59](https://github.com/kksimp/Mac.apk/pull/59),
[#73](https://github.com/kksimp/Mac.apk/pull/73)–[#79](https://github.com/kksimp/Mac.apk/pull/79).
They are merged into this fork as they land.

## Status

**Alpha. No builds are published yet.**

- The codebase still uses the upstream product name internally (bundle IDs,
  paths, menu titles). Until those are renamed, binaries built from this repo
  must not be distributed under the Mac.apk name.
- [COMPATIBILITY.md](COMPATIBILITY.md) is upstream's list of apps tested by hand.

## Requirements

| | |
|---|---|
| **macOS** | 26.4 (Tahoe) or newer |
| **Hardware** | Any Apple Silicon Mac. Intel is not supported. |
| **Disk** | ~280 MB, plus roughly 1.5–3× each app's APK size |

## Building

See [BUILDING.md](BUILDING.md). You need the macOS 26.4 SDK (Xcode 26.4 or newer).

## Security

An Android app here runs as ordinary native code with **your macOS account's
permissions**. Unlike on a phone, there is no app sandbox around it. Only install
APKs you trust, from sources you trust.

## License

[GNU AGPL v3.0](LICENSE), the same license as upstream.

- Copyright in the upstream code belongs to Kaleb Simpson / Voltare and the
  Mac.apk contributors.
- Changes in this fork are © their authors and are released under the same
  license.
- If you distribute a build or offer it over a network, you must make the
  complete corresponding source available under the AGPL.

Bundled third-party components (ANGLE, MoltenVK, Capstone, OpenJDK, Bouncy
Castle, AOSP resources, GLib/libintl under the LGPL, and others) keep their own
licenses. See [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).

## Credits

All the hard work is upstream's: [Mac.apk](https://github.com/kksimp/Mac.apk) by
[@kksimp](https://github.com/kksimp). If you find this useful, consider
[sponsoring the original author](https://github.com/sponsors/kksimp).
