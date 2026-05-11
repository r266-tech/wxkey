# Security Policy

wxkey is a local companion utility for initializing wx-mcp. It reads the user's local WeChat process memory, verifies candidate WCDB keys against local database pages, and writes key material to `~/.config/wxcli/config.json`.

## Sensitive Data

Do not paste or upload:

- `~/.config/wxcli/config.json`
- raw WCDB keys or salts
- WeChat database files
- wxkey `scan` JSON output
- message/contact exports

`wxkey bootstrap` and `wxkey setup` are designed for local execution only.

## Privileged Side Effects

`wxkey bootstrap` may quit and reopen WeChat, ad-hoc re-sign `/Applications/WeChat.app`, and request administrator privileges so it can read the local WeChat task port. Run `wxkey doctor` first when you want a read-only status check.

wx-mcp runtime database reads do not require SIP-disabled when a usable key config already exists. First-time key extraction requires process memory access; the recommended path is ad-hoc signing plus administrator privileges, with SIP-disabled only as a fallback.

## Reporting

Report security issues privately to the repository owner. Do not include key material, database contents, or private message/contact data in reports.
