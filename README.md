# wxkey

`wxkey` is the companion CLI used by [wx-mcp](https://github.com/r266-tech/wx-mcp)
to initialize local WeChat 4.x WCDB keys on macOS.

It reads the local WeChat process memory, finds candidate WCDB key material, and
verifies candidates against local DB page-1 SQLCipher HMACs. It writes the
resulting per-DB key map to `~/.config/wxcli/config.json`, where wx-mcp can read
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

`bootstrap` checks existing config, applies the no-SIP ad-hoc signing route for
WeChat.app when needed, asks for the Mac admin password once, stores that
password in the user's macOS Keychain, then runs setup and prints only a
summary. It does not print raw key material.

## SIP

SIP should stay enabled. First-time key extraction uses one supported path:
ad-hoc-signing the user's local WeChat.app and running wxkey with administrator
privileges. The admin password is stored in Keychain by `wxkey bootstrap` so
later `wxkey setup` runs can refresh missing DB keys unattended. Disabling SIP is
not a supported setup step.

## Security

Do not paste raw `~/.config/wxcli/config.json`, DB keys, WeChat DBs, or message
contents into public issues.
