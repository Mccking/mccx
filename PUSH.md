# 推送到 GitHub（三条命令 + 两个 secret）

这个目录已经是可提交状态，只差「你的凭据」。我没有、也不该有你的 token，所以最后一步由你执行。

## 1. 建仓库

建议**单独一个仓库**（例如 `mccx`），不要塞进 `hezhanleiok/xehn`：

- 那个仓库是 Go 桌面端，CI 路径、release 标签、体积都会互相干扰；
- 本项目的 `build.sh` / workflow 默认假设 Android 工程在仓库根目录。

网页建空仓库，或本地装 `gh` 后：

```bash
gh repo create mccx --private --source . --remote origin --push
```

## 2. 推送

```bash
cd E:\deepseek\xehn-vpn
git init
git add .
git commit -m "MccX: WARP client for Android (WireGuard + mihomo engines)"
git branch -M main
git remote add origin https://github.com/<你的账号>/mccx.git
git push -u origin main
```

## 3. 两个 secret（Actions 才能签名出可覆盖升级的包）

仓库 → Settings → Secrets and variables → Actions → New repository secret：

| 名称 | 值 |
|---|---|
| `MCCX_KEYSTORE_BASE64` | 现有 `keystore.jks` 的 base64 |
| `MCCX_KEYSTORE_PASS` | `xehn-apk` |

生成 base64（在项目目录执行，别把输出贴到公开地方）：

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("keystore.jks"))
```

```bash
base64 -w0 keystore.jks
```

> keystore 不在 git 里（`.gitignore` 已排除）。丢了它，以后所有新包都无法覆盖安装旧包。

## 4. 打开自更新

`src/com/xehn/warp/Updater.java` 第一处常量改成你的仓库地址：

```java
public static final String MANIFEST_URL =
        "https://github.com/<你的账号>/mccx/releases/latest/download/update.json";
```

改完重新打一次包并手动安装——**从这一版起，APP 才能自己发现并安装后续版本**（之前的版本里这个常量是空的）。

## 5. 验证

Actions 页面 → `mccx-release` → Run workflow。跑完应看到：

- Release `build-<n>`，内含 `mccx-3.1.<n>.apk` 和 `update.json`；
- 若上游 `xehn` 没变，定时任务不会发版（`changed=false`），避免版本号虚增。

## CI 会做什么

1. 拉上游 `hezhanleiok/xehn`，跑 `tools/sync_upstream.ps1` 提取常量与端点池；
2. 只有 `UpstreamDefaults.java` 变了才继续（手动触发除外）；
3. `setup-go` 编 `libmccxcore.so`；从 mihomo release 拉 Android 内核（拉不到也能出包，只是不带 mihomo）；
4. `tools/build.sh` 出 APK + `update.json`，发布到 Release。
