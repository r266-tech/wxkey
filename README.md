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
WeChat.app when needed, then runs setup and prints only a summary. It does not
print raw key material.

## SIP

wx-mcp runtime DB decryption does not require SIP-disabled. First-time key
extraction requires a readable local WeChat task port. The recommended path is
ad-hoc-signing the user's local WeChat.app and running wxkey with administrator
privileges; SIP-disabled is only a fallback.

## Security

Do not paste raw `~/.config/wxcli/config.json`, DB keys, WeChat DBs, or message
contents into public issues.
