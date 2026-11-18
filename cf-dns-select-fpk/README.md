# cf-dns-select — 飞牛 fnOS 应用包（fpk）

将 [neon9809/cf-dns-select](https://github.com/neon9809/cf-dns-select)
（Cloudflare 最优节点自动测速 + 多实例 AdGuard Home DNS 重写，内置 Web Dashboard）
以 **Docker 应用**形态打包为飞牛 fnOS 的 `.fpk` 安装包。

**版本约定**：包版本与上游应用版本保持一致（当前 `0.3.5`），
compose 镜像固定为 `ghcr.io/brokendreamstar/cf-dns-select:0.3.5`，不使用 latest——
保证同一个 .fpk 在任何时间安装出的内容完全一致，可复现、可回滚。

## 目录结构

```
cf-dns-select-fpk/
├── manifest                        # 应用元数据（appname/version=0.3.5/platform=all/os_min_version=1.1.8）
├── SUBMISSION.md                   # 提交审核说明（host 网络论证 / 暴露面 / 访问控制）
├── ICON.PNG / ICON_256.PNG         # 包图标 64/256
├── app/
│   ├── docker/
│   │   ├── docker-compose.yaml     # 镜像固定 tag：ghcr.io/brokendreamstar/cf-dns-select:0.3.5
│   │   ├── .env                    # COMPOSE_PROFILES 默认值（随包携带，决定网络模式）
│   │   └── env/app.env             # 运行参数默认值（随包携带，安装后必然存在）
│   └── ui/
│       ├── config                  # 桌面入口（port=${wizard_port} 动态解析）
│       └── images/icon_{64,256}.png
├── cmd/                            # 沙箱生命周期脚本
│   ├── main                        # start/stop/status（自愈同步参数文件 + docker inspect 判运行态）
│   ├── install_callback            # 声明门禁 + 端口占用检测 + 主副本生成 + 模式一致性重建
│   ├── config_callback             # 「应用设置」提交后更新主副本并按新模式/端口重建容器
│   ├── upgrade_callback            # 升级后从主副本恢复参数文件（兼容 v1.0.0 旧位置迁移）
│   └── 其余 install/upgrade/uninstall/config 存根
├── config/
│   ├── privilege                   # run-as=package + join-groups=[docker]（重建容器所需）
│   └── resource                    # docker-project 声明（由应用中心托管 compose 生命周期）
└── wizard/
    ├── install                     # 使用声明 → 网络模式 → 白名单/端口 → 密码/时区
    └── config                      # 「应用设置」里可再次修改全部字段
```

## 关键设计

- **镜像固定版本**：两个 service 都引用 `ghcr.io/brokendreamstar/cf-dns-select:0.3.5`
  （ghcr 上同时存在 `0.3.5` 与 `v0.3.5` 标签）。升级 = 发布新 .fpk（新 tag 新镜像），
  不追上游 floating tag。
- **网络模式可选**：安装向导「网络模式」页二选一：
  - **host**（默认/推荐）：容器直接使用宿主网络栈，真实 IPv4+IPv6 测速环境；
  - **端口映射（bridge）**：仅暴露向导端口、兼容性更稳妥，但受 NAT 限制 **IPv6 测速不可用**。
  实现为 compose profiles：随包携带的 `app/docker/.env` 提供 `COMPOSE_PROFILES` 默认值，
  保证应用中心在任何阶段拉起容器都有确定配置；用户选择由回调同步到 `.env`，
  模式不一致的旧容器会被自动删除并以正确 profile 重建。详见 `SUBMISSION.md`。
- **端口语义**：实际端口由向导动态决定（`${wizard_port}`），manifest 不再声明固定
  `service_port`，并设 `checkport=false` 避免对名义端口误探测；入口 port 与运行参数
  始终一致。因使用入口动态变量，声明 `os_min_version=1.1.8`（文档要求 ≥1.1.8）。
- **安装时端口占用检测**：首次安装若所选端口已被占用，中止安装并给出可见提示，
  避免装完后容器反复重启。
- **参数文件随包携带**：`app/docker/env/app.env` 打进包内，
  compose 用官方文档明确支持的 `${TRIM_APPDEST}/docker/env/app.env` 绝对路径引用。
  应用文件一落地该文件就存在——无论应用中心在哪个阶段拉起 docker-project，
  都不会再出现 `env file ... not found` 导致的安装失败
  （v1.0.x 引用 `${TRIM_PKGVAR}/env/app.env`，该目录由回调生成，时序上可能晚于容器拉起）。
- **向导值 → 主副本 → 同步**：
  - 运行参数主副本 `${TRIM_PKGETC}/app.env`、部署参数主副本
    `${TRIM_PKGETC}/deploy.conf`（NET_MODE/BIND_PORT），升级保留、600 权限；
  - `install_callback` 用向导值生成主副本后同步到 target 内的引用路径；
  - `upgrade_callback` 在包覆盖 target 后从主副本恢复，并自动迁移 v1.0.x
    存放在 `${TRIM_PKGVAR}/env/app.env` 的旧配置；
  - `cmd/main start` 每次启动前做一次自愈同步；
  - `config_callback` 处理「应用设置」提交：更新主副本、同步并重建容器
    （密码留空表示保持不变）。
- **向导字段**：
  - `wizard_agreement` → 使用声明确认（radio 必选；不同意时安装中止并展示原因）；
  - `wizard_net` → 网络模式 host/bridge（写入 deploy.conf 与 `.env` 的 COMPOSE_PROFILES）；
  - `wizard_allowed_cidrs` → `DSA_ALLOWED_CIDRS`（必填，缺省放行三组 RFC1918 网段）；
  - `wizard_port` → 监听/映射端口（正则精确限定 100–65535，与脚本校验一致）；
  - `wizard_password` → `DSA_PASSWORD`（留空则首次启动随机生成，打印在容器日志）；
  - `wizard_tz` → `TZ`。
- **数据持久化**：`${TRIM_PKGVAR}/data:/app/data`，`config.json` 与 `colo_ip_db.json`
  均存于应用沙箱内。
- **最小权限**：未声明 data-share/usr-local-linker；生命周期脚本无特权操作；
  长期进程跑在官方镜像内的非 root 用户（uid 1000）。
- **platform=all**：官方镜像为 amd64/arm64 双架构。

## 图标（logo）

按平台规范，应用包必须包含：

| 文件 | 用途 | 要求 |
| --- | --- | --- |
| `ICON.PNG` | 包图标（应用中心等） | PNG 64×64，≤1024KB |
| `ICON_256.PNG` | 包图标高清 | PNG 256×256 |
| `app/ui/images/icon_{64,256}.png` | 桌面入口图标（`config` 中 `images/icon_{0}.png` 引用） | 同上 |

当前四个文件由 `logo.png`（512×512 源图）生成：`fpksb icons . --from logo.png`
会做面积法缩放并按规范加圆角蒙版。要更新 logo，替换 `logo.png` 后重新执行该命令即可；
也可直接用同名文件覆盖这四个 PNG（保持尺寸、sRGB、圆角矩形风格），然后重新 `fpksb build`。

## 构建与校验

```bash
fpksb check cf-dns-select-fpk          # 沙箱配置一致性校验
fpksb build cf-dns-select-fpk -o dist/cf-dns-select.fpk
# 或使用官方工具：
cd cf-dns-select-fpk && fnpack build
```

## 自动构建（GitHub Actions）

`.github/workflows/docker-publish.yml` 可自动完成 check → 版本一致性断言 → 冒烟测试 →
打包 → 附着 Release。采用方式：

1. 把整个工作区（`fpk-sandbox/`、`cf-dns-select-fpk/`、`.github/`）推到一个 GitHub 仓库；
2. 发版时保证 manifest.version、compose 镜像标签、git 标签三者一致
   （如 `0.3.5` / `:0.3.5` / `v0.3.5`），然后：

   ```bash
   git tag v0.3.5 && git push origin v0.3.5
   ```

3. Actions 构建完成后，`cf-dns-select.fpk` 与 `SHA256SUMS.txt` 会出现在同名 Release 下；
   三者不一致时 CI 直接失败，防止版本漂移。

## 安装到飞牛 fnOS

1. 应用中心 → 手动安装 → 选择 `dist/cf-dns-select.fpk`（本地测试用），
   或下载 Release 附件后在设备上执行 `appcenter-cli install-fpk cf-dns-select.fpk`；
2. 阅读并在「使用声明」步骤选择同意，选择网络模式，填写允许访问的网段、
   端口（默认 8080）、可选密码、时区；
3. 从桌面打开「CF DNS 优选」，用设置的密码登录 Dashboard
   （密码留空时执行 `docker logs cf-dns-select` 查看随机生成的初始密码）。

> 从 v1.0.x 升级：无需卸载，直接安装新包即可；旧的运行参数会自动迁移并继续生效。
