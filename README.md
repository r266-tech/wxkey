# wxkey

**macOS WeChat 4.x key bootstrap companion for [wechat-cli](https://github.com/r266-tech/wechat-cli).**

`wxkey` 负责在 macOS 上初始化和刷新本机微信 WCDB 解密 key。普通用户通常不需要单独安装它：`wechat-cli` 的 release zip 已经内置 `wxkey`，一行安装会自动调用。

Windows 用户不需要 `wxkey`。Windows 版 `wechat-cli` 会直接扫描当前用户登录的 WeChat / Weixin 进程并写入 key map。

## 它做什么

- 扫描本机 macOS WeChat 4.x 进程，提取候选 WCDB key。
- 用本地数据库 page-1 HMAC 验证候选 key，避免写入错误 key。
- 把 per-DB key map 写到 `~/.config/wxcli/config.json`，供 `wechat-cli` 只读打开加密数据库。
- 在首次 bootstrap 时准备 wechat-cli 管理的 shadow WeChat，走无需关闭 SIP 的路线完成 `task_for_pid`。
- 把一次性 sudo 凭据存到用户 macOS Keychain，后续缺 key 时可无人值守刷新。
- 派生 WeChat V4 图片解码用的 `image_key` / `image_xor_key`，优先走本机 `kvcomm` cache，不读进程。

## 安装

普通用户推荐直接安装 `wechat-cli`：

```bash
curl -fsSL https://raw.githubusercontent.com/r266-tech/wechat-cli/main/scripts/install-release.sh | zsh
```

开发者单独安装：

```bash
go install github.com/r266-tech/wxkey/cmd/wxkey@latest
```

## 常用命令

```bash
wxkey bootstrap
wxkey doctor
wxkey setup
wxkey image-key
```

| 命令 | 用途 |
| --- | --- |
| `bootstrap` | 首次初始化推荐入口；检查环境、准备 shadow WeChat、获取 sudo、跑 setup |
| `doctor` | 轻量诊断；对比已缓存 key map 和本地 DB salts，列出缺 key 的 DB |
| `doctor --scan` | 重新验证 live `task_for_pid` / heap scan 覆盖率 |
| `setup` | 扫描并刷新 WCDB per-DB key map |
| `image-key` | 派生并验证微信 V4 图片 `.dat` 解码 key |
| `scan --quiet` | 底层扫描输出，主要给 `wechat-cli` 和维护者使用 |
| `resign-wechat` | 显式准备 wechat-cli shadow WeChat，通常由 `bootstrap` 自动处理 |

## 首次初始化

```bash
wxkey bootstrap
```

`bootstrap` 会：

1. 检查微信是否登录、本地 DB 是否存在、已有 key 覆盖率。
2. 必要时创建并 ad-hoc 签名 wechat-cli shadow WeChat。
3. 让用户在本机隐藏提示里输入一次 Mac admin 密码。
4. 把 sudo 凭据存入用户 Keychain。
5. 扫描 WeChat 进程内存并验证 key。
6. 写入 `~/.config/wxcli/config.json`。

不需要关闭 SIP。不要把 admin 密码、config.json、DB key 或微信数据库发到 issue、聊天窗口或 agent 对话里。

默认 key scan 最长跑 3 分钟，超时会退出并保留清晰错误，不会在安装脚本里无限挂住。需要维护者调长时可设置 `WXKEY_SETUP_TIMEOUT=5m`。

## Agent 使用边界

agent 可以自己跑 `wxkey doctor` / `wxkey setup` / `wxkey image-key`。如果覆盖不完整，agent 应该读取缺失 DB 列表，只让用户在微信里打开对应聊天、收藏或朋友圈页面，然后 agent 再重试。

不要把 `doctor` / `setup` 命令交给普通用户手工排查，除非用户明确要求自己操作。

## 安全说明

- `wxkey` 只在本机读取本机微信数据。
- raw key 不会打印到正常 stdout。
- key map 存在 `~/.config/wxcli/config.json`，权限和备份请按敏感文件处理。
- 本项目与腾讯、微信没有官方关联。

## License

See [LICENSE](LICENSE).

---

<!-- babata-star-callout-v2 -->
## If wxkey helped you set things up

`wxkey` is a bootstrap companion. The day-to-day product is [wechat-cli](https://github.com/r266-tech/wechat-cli) — that is the repo to star if you want to support continued maintenance. Part of [babata](https://github.com/r266-tech).
