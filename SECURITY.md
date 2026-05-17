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

`wxkey bootstrap` may quit and reopen WeChat, create and ad-hoc sign a wx-mcp-managed WeChat shadow copy, and request administrator privileges so it can read the local WeChat task port. It stores the Mac admin password in the user's macOS Keychain under a wx-mcp-specific service so future `wxkey setup` runs can use `sudo -S` unattended. The explicit `resign-wechat` diagnostic command can still modify `/Applications/WeChat.app`, but bootstrap avoids that by default. Run `wxkey doctor` first when you want a read-only status check.

SIP should stay enabled. First-time and future key extraction use the same supported path: ad-hoc signing plus the stored sudo credential. Disabling SIP is not part of the supported setup flow.

## Reporting

Report security issues privately to the repository owner. Do not include key material, database contents, or private message/contact data in reports.
