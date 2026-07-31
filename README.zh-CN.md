# Agent Sandbox

[English](README.md) | 简体中文

Agent Sandbox 是面向 coding agent 的本地隔离运行时。机器维护者只需安装
`asbx` CLI、准备一个或多个虚拟化后端，并安装项目自带的 Agent Skill；之后由
Agent 自行判断何时以及如何创建一次性 sandbox。

接入关系如下：

```text
Codex / Claude Code / Cursor / Gemini CLI / OpenCode
                         │
                  Agent Skill + shell
                         │
                       asbx
                         │
        Microsandbox / QEMU / Cuttlefish / Android Emulator
```

这份 README 面向负责部署机器或接入新后端的人。供 Agent 使用的工作流和命令
选择规则位于项目自带的
[`agent-sandbox` Skill](skill/agent-sandbox/SKILL.md)。

## 安装 CLI

项目暂未发布预编译二进制。请使用 Rust 1.94 或更新版本从源码目录安装：

```bash
cargo install --path crates/cli
asbx --version
```

首次安装或升级 CLI 后运行一次：

```bash
asbx setup
```

在交互式终端中，Setup 会启动引导界面，依次多选需要准备的后端和 Agent 集成，
然后展示变更计划，得到确认后才修改机器。它可以安装 Microsandbox runtime、
调用受支持的包管理器安装 QEMU、创建宿主配置，以及安装 Agent Skill。

如需明确指定目标，或进行非交互安装：

```bash
asbx setup \
  --default-backend microsandbox \
  --harness codex,claude-code \
  --yes

asbx setup --dry-run
asbx setup --check --json
```

`--dry-run` 会走完选择和规划流程，但不执行任何变更。`--yes` 表示不再询问并
执行已展示的计划。`--check` 只读；如果仍有待执行操作或需要人工修复的问题，
会以非零状态退出。

Skill 的安装位置为：

- Codex、Cursor、Gemini CLI 和 OpenCode：
  `~/.agents/skills/agent-sandbox`
- Claude Code：`~/.claude/skills/agent-sandbox`

CLI 升级后请重新运行 `asbx setup`，让受管理的 Skill 文件与 CLI 保持一致。
Agent Sandbox 复用 Skill 和 Agent 已有的 shell 能力，不需要 MCP server，也
不会启动常驻的 `asbx` daemon。

## 选择后端

这些后端解决的问题不同，不应被当作可以随意互换的虚拟机实现。

| 后端 | 适用场景 | 宿主支持 | Setup 行为 |
|---|---|---|---|
| `microsandbox` | 常规仓库构建、测试、OCI 镜像和语言环境 | 可在 Apple Silicon macOS、x86_64/ARM64 Linux 上自动安装 | 下载并校验 runtime |
| `android-emulator` | 已有的 Android SDK AVD | macOS、Linux、Windows | 校验工具、硬件加速和配置的 AVD |
| `cuttlefish` | AOSP/Cuttlefish phone image 和离线 Android 任务 | 带 KVM 和 vhost-vsock 的 Linux | 校验宿主设备、工具和构建产物 |
| `qemu` | 磁盘启动、自定义内核、其他架构、串口/QMP/GDB | macOS、Linux、Windows；跨架构可使用 TCG | 可通过受支持的 macOS/Linux 包管理器安装 |

普通 coding-agent 任务默认使用 Microsandbox。Android Emulator 是跨平台的
Android 方案；如果有兼容的 Linux 宿主且必须隔离 Android 网络，优先使用
Cuttlefish。QEMU 适合完整机器任务，而不是普通 OCI 项目执行。

后端不可用时，`asbx` 绝不会回退到宿主机直接执行 guest 命令。

## 准备 Microsandbox

在受支持的宿主上，Setup 可以直接配置 Microsandbox，无需另行手动安装：

```bash
asbx setup --default-backend microsandbox
asbx doctor --backend microsandbox
```

Setup 会解析最新稳定版 runtime bundle，并在安装前验证其发布的 SHA-256。
Rust 构建产物中包含匹配的 guest agent，但单独构建 CLI 不会安装宿主 runtime。

Microsandbox 适合默认的 Agent Skill 工作流，包括项目副本、OCI 镜像、可复用
语言环境、过滤网络、服务和 artifact。

## 准备 Android Emulator

Android Emulator 是跨平台 Android 后端。先通过 Android Studio 或 Android
SDK 命令行工具安装：

- Android SDK Emulator
- Android SDK Platform-Tools（`adb`）
- 与宿主架构兼容的 system image
- 基于该镜像创建的 Android Virtual Device
- 可用的宿主硬件加速：Hypervisor.Framework、KVM 或 WHPX

配置 `asbx` 前先检查 Android 安装：

```bash
emulator -accel-check
emulator -list-avds
adb version
```

在 `~/.agent-sandbox/config.toml` 中指定 AVD：

```toml
[android_emulator]
avd = "TestPhone"
boot_timeout = "5m"
shutdown_timeout = "30s"
gpu = "auto"

# 通常会从 ANDROID_SDK_ROOT 或标准 SDK 路径自动发现。
# sdk_root = "/path/to/Android/sdk"
# emulator = "/path/to/Android/sdk/emulator/emulator"
# adb = "/path/to/Android/sdk/platform-tools/adb"

[network]
allow_all_mode = true
```

然后选择并验证后端：

```bash
asbx setup --default-backend android-emulator
asbx doctor --backend android-emulator

# 可选的端到端冒烟测试
asbx run --android-avd TestPhone \
  --project-mode none \
  --network all \
  -- getprop ro.build.version.release
```

每个 sandbox 都会冷启动一个基于源 AVD 配置的私有副本，并使用全新数据状态；
源 AVD 本身不会被启动或修改。

Android Emulator 必须显式使用 `--network all`，同时宿主配置必须开启
`network.allow_all_mode = true`。Android SDK Emulator 没有可供 `asbx` 跨平台
实施完全断网或过滤出口流量的接口。如果不能接受 Android unrestricted
networking，请在 Linux 上使用 Cuttlefish。

## 准备 Cuttlefish

Cuttlefish 要求 Linux 宿主对 `/dev/kvm` 和 `/dev/vhost-vsock` 都具有读写
权限。先安装适合当前宿主的 Cuttlefish host packages，再将下列两个版本匹配的
Android 构建产物解压到同一个目录：

- `cvd-host_package.tar.gz`
- Cuttlefish device-image archive

配置该目录：

```toml
[cuttlefish]
artifacts = "/opt/android/cuttlefish"
boot_timeout = "5m"
shutdown_timeout = "30s"
```

选择并验证后端：

```bash
asbx setup --default-backend cuttlefish
asbx doctor --backend cuttlefish

# 可选的端到端冒烟测试
asbx run --backend cuttlefish \
  --project-mode none \
  --network off \
  -- getprop ro.build.version.release
```

`asbx setup` 不会下载 Android image，也不会安装 Cuttlefish host package；
它只验证已经准备好的构建产物和宿主能力。后端的离线模式需要较新的 host
tools 支持 `--enable_tap_devices`。

## 准备 QEMU

在 macOS 或 Linux 上，Setup 会先展示完整命令，再调用检测到的包管理器：

```bash
asbx setup --install-backend qemu
asbx doctor --backend qemu
```

在 Windows 上，或使用自定义安装时，请自行安装 QEMU。如果目标程序不在
`PATH` 中，则明确配置其路径：

```toml
[qemu]
binary = "/path/to/qemu-system-aarch64"
boot_timeout = "2m"
shutdown_timeout = "10s"
```

生命周期、串口输出、QMP 和 loopback GDB stub 不要求 guest 内安装额外软件。
如果需要项目复制、Agent 命令、shell 和 artifact 传输，guest 内必须提供
SSH：

```toml
[qemu]
ssh_user = "root"
ssh_key = "/path/to/qemu_guest_key"
```

每个任务的启动磁盘或内核由调用方提供。可写 root disk 使用 QEMU snapshot
模式，不会修改基础镜像。

## 设置宿主策略

机器所有者通过 `~/.agent-sandbox/config.toml` 控制不可突破的上限。可从
[`config.example.toml`](config.example.toml) 开始，并至少检查：

- 允许访问的 workspace root，以及是否允许读写挂载
- 默认网络模式和高风险的 `allow_all_mode` 开关
- CPU、内存、磁盘、输出、传输和缓存上限
- 各后端的路径、超时和凭证

Agent 请求可以收紧这些限制，但不能静默放宽。除非调用方明确传入某个值，
guest 不会继承宿主环境变量和凭证。

用以下命令确认机器已经可以交给 Agent：

```bash
asbx setup --check --json
asbx backend list --json
asbx doctor --backend microsandbox
```

最后一条命令中的后端名应替换为当前机器实际使用的后端。检查通过且 Skill
安装完成后，Agent 已经具备选择 `run`、`open`/`exec`/`close`、网络模式、
项目暴露方式和 artifact 处理方式所需的全部说明。

## 适配新后端

后端 adapter 只需实现一个小型生命周期 contract，并按实际能力选择可选操作：

1. 新增 runtime crate，实现
   [`SandboxRuntime`](crates/runtime/lib/lib.rs) 和 readiness checks。
2. 只实现适用的可选 trait，例如 `CommandRuntime`、`TerminalRuntime`、
   `FileTransferRuntime`、`SnapshotRuntime`、`ImageRuntime` 或
   `DebugRuntime`。
3. 声明匹配的 `BackendCapabilities`。如果声明的 feature 与实际 capability
   accessor 不一致，registry 会拒绝注册。
4. 在 [`app/bootstrap.rs`](crates/cli/bin/app/bootstrap.rs) 中注册并配置
   adapter。
5. 如果后端需要安装或检查宿主能力，扩展
   [`app/setup.rs`](crates/cli/bin/app/setup.rs)，并补充 contract 和生命周期
   测试。

不支持的功能无需在 backend-neutral core 中增加空实现。完整接入方式可参考
[`RuntimeRegistry`](crates/runtime/lib/registry.rs)、已有的
[`QEMU`](crates/runtime-qemu/lib/lib.rs) 和
[`Android Emulator`](crates/runtime-android-emulator/lib/lib.rs) adapter，以及
[设计文档](agent-sandbox.md)。

## 参考资料

- [Agent 使用说明](skill/agent-sandbox/SKILL.md)
- [CLI 参考](skill/agent-sandbox/references/cli.md)
- [环境选择](skill/agent-sandbox/references/environments.md)
- [故障排查](skill/agent-sandbox/references/troubleshooting.md)
- [架构与安全模型](agent-sandbox.md)
