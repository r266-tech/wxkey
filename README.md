# wxkey


`wxkey` is the companion CLI used by [wechat-local-mcp](https://github.com/r266-tech/wechat-local-mcp)
to initialize local WeChat 4.x WCDB keys on macOS.

It reads the local WeChat process memory, finds candidate WCDB key material, and
verifies candidates against local DB page-1 SQLCipher HMACs. It writes the
resulting per-DB key map to `~/.config/wxcli/config.json`, where wechat-local-mcp can read
it later.

## Install

```bash
go install github.com/r266-tech/wxkey/cmd/wxkey@latest
```

## Usage

```bash
wxkey bootstrap
wxkey doctor
wxkey setup
wxkey scan --quiet
wxkey resign-wechat
```

Recommended first-run path:

```bash
wxkey bootstrap
```

`bootstrap` checks existing config, prepares an ad-hoc signed wx-mcp shadow copy
of WeChat when needed, asks for the Mac admin password once, stores that password
in the user's macOS Keychain, then runs setup and prints only a summary. It does
not print raw key material.

## SIP

SIP should stay enabled. First-time key extraction uses one supported path:
an ad-hoc signed WeChat process plus wxkey with administrator privileges.
Bootstrap signs a wx-mcp-managed shadow copy when the installed WeChat app is
protected by App Store app-management controls. The admin password is stored in
Keychain by `wxkey bootstrap` so later `wxkey setup` runs can refresh missing DB
keys unattended. Disabling SIP is not a supported setup step.

## Security

Do not paste raw `~/.config/wxcli/config.json`, DB keys, WeChat DBs, or message
contents into public issues.

---

<!-- babata-star-callout-v2 -->
## If wxkey helped you set things up

`wxkey` is a small bootstrap companion. The actual product you'll use day-to-day is **[wechat-local-mcp](https://github.com/r266-tech/wechat-local-mcp)** — that's the repo to star if you want to support continued maintenance. Part of [babata](https://github.com/r266-tech).
