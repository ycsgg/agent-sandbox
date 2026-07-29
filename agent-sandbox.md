# Agent Sandbox Wrapper 设计方案

## 1. 目标

构建一个本地、跨平台、按需启动的 sandbox wrapper，让 AI Agent 可以自行：

- 根据项目声明识别 Go、Rust、Node.js、TypeScript 等运行环境及版本。
- 使用预置环境、任意 OCI 镜像或 Microsandbox snapshot。
- 使用 QEMU 启动磁盘镜像、自定义 kernel/initrd/DTB 和不同 CPU 架构。
- 创建一次性 sandbox，执行编译、测试、审计和验证命令。
- 在同一个 sandbox 中进行多轮操作。
- 启动服务并通过宿主本地端口访问。
- 取回报告、日志和构建产物。
- 完成后销毁 sandbox，不留下常驻 VM 或 daemon。

底层通过 backend registry 同时支持 Microsandbox 和 QEMU。Microsandbox
负责快速 OCI 工作流；QEMU 负责完整系统启动、跨架构、串口、QMP 和 GDB
stub。上层 core、lease 和状态模型不与任一 backend 强耦合。

## 2. 威胁模型

### 2.1 信任对象

本方案假设以下对象可信：

- 用户。
- AI Agent 及其决策。
- Agent Sandbox wrapper。
- 由我们维护的基础镜像、环境目录和 provisioning 脚本。
- Microsandbox、libkrun、QEMU、宿主 hypervisor 和宿主内核。

Agent 可以自由选择命令、镜像、网络模式、guest 用户、资源和环境构建方式。wrapper 不需要防止一个主动恶意的 Agent 绕过产品意图。

### 2.2 不信任对象

以下内容视为不可信：

- 待审计项目源码。
- 项目中的构建脚本、测试脚本和 install hooks。
- `package.json` lifecycle scripts、`build.rs`、Makefile、shell script 等。
- 项目下载或携带的二进制文件。
- 第三方依赖及其安装过程。
- sandbox 内被攻陷的 guest 用户空间或 guest kernel。

### 2.3 保护目标

wrapper 主要保护：

- 宿主文件系统中项目范围之外的数据。
- 宿主进程、内核和其他 sandbox。
- 宿主凭证、环境变量、SSH key、云凭证和浏览器数据。
- 宿主内网、云 metadata endpoint 和本机敏感服务。
- 宿主 CPU、内存、磁盘和进程资源不被失控任务无限消耗。
- Agent 主进程不被无限 stdout/stderr 或 artifact 拖垮。

### 2.4 非目标

- 不防止可信 Agent 主动要求开放公网、扩大资源或运行高风险命令。
- 不把 Skill 指令当作安全边界。
- 不承诺抵御 hypervisor、VMM 或 CPU 虚拟化漏洞。
- 不在第一阶段实现多租户云服务、计费和 Kubernetes 调度。

## 3. 核心决策

### 3.1 使用 Skill，不使用 MCP

AI Agent 通过一个 `agent-sandbox` Skill 学习并调用本地 `asbx` CLI。

```text
AI Agent
   │
   │ 读取 SKILL.md
   │ 调用 shell
   ▼
asbx CLI
   ▼
Agent Sandbox Core
   ▼
Runtime Registry
   ├── Microsandbox SDK → libkrun → KVM / Hypervisor.framework / WHP
   └── QEMU → KVM / HVF / WHPX / TCG
```

不引入 MCP server，原因如下：

- Agent 通常已经具备 shell/exec 能力。
- CLI 更容易在 Codex、Claude Code 和其他 coding agent 间复用。
- 不需要新的常驻服务、协议和鉴权面。
- CLI 的 stdin/stdout、退出码和 JSONL 很适合构建、测试和审计流程。
- Skill 可以提供工作流指导、环境判断和错误恢复方式。

Skill 是使用说明和工作流，不承担强制隔离。即使 Agent 没有遵循 Skill，`asbx` 本身仍必须正确隔离不可信代码。

### 3.2 多 backend wrapper，不 fork VMM

固定 Microsandbox 版本并通过 adapter 使用其 Rust SDK；QEMU 通过独立
adapter 调用系统安装的 `qemu-system-*`，使用 QMP 管理生命周期，使用可选
SSH transport 提供命令和文件通道。

只在出现 wrapper 无法解决的 core 问题时维护小型 patch branch，并优先向上游提交：

- VM 无法可靠取消或清理。
- WHP、KVM、Hypervisor.framework 后端资源泄漏。
- VMM、virtio 或协议安全缺陷。
- 必须在 SDK 内实现的输出背压或生命周期能力。

环境检测、镜像选择、缓存、Skill、CLI、安全默认值和 artifact 管理都属于 wrapper，不应侵入 VMM。

### 3.3 不使用常驻热池

- 每次任务冷启动一个 microVM。
- 复用 OCI 只读层和磁盘 snapshot，不复用运行中的 VM。
- wrapper 退出时不留下后台 worker。
- 镜像和 snapshot 只占磁盘，不占常驻内存。

## 4. 用户与 Agent 体验

### 4.1 一次性运行

Agent 最常使用：

```bash
asbx run --project . --env auto -- cargo test --workspace
```

完整流程由 wrapper 自动完成：

```text
检测环境
  → 解析 OCI 镜像或 snapshot
  → 创建 ephemeral VM
  → 复制项目
  → 执行命令
  → 流式返回输出
  → 收集 /out
  → 停止并销毁 VM
```

`asbx` 的退出码默认等于 guest 命令退出码。

### 4.2 多轮会话

复杂审计或调试使用显式会话：

```bash
asbx open --project . --env auto
# 输出：sbx_01J...

asbx exec sbx_01J... -- npm ci
asbx exec sbx_01J... -- npm test
asbx exec sbx_01J... -- /bin/sh

asbx close sbx_01J...
```

会话有默认 TTL，但 Agent 可以在宿主配置允许范围内延长：

```bash
asbx touch sbx_01J... --ttl 2h
```

#### 4.2.1 QEMU 调试会话

Agent 不需要读取 QEMU state file、解析动态端口或拼接 debugger shell
命令。wrapper 把运行时上下文转换为结构化调试计划：

```bash
id="$(asbx open --backend qemu --kernel ./Image --initrd ./initramfs \
  --accelerator tcg --kernel-append nokaslr --gdb --pause-at-boot \
  --project-mode none --network off)"

asbx debug "$id" --print-command --json
asbx debug "$id" --symbols ./vmlinux
asbx close "$id"
```

`asbx debug` 负责：

- 从 backend metadata 获取 loopback GDB endpoint、架构、加速器和暂停状态。
- 自动发现 GDB/LLDB，始终通过参数数组启动，不经 shell。
- 校验 ELF/PE symbol file 的架构与 guest 一致。
- 对缺少 symbol、未暂停、KASLR 和非 TCG 加速器给出结构化提示。
- 通过 `--print-command --json` 将完整 program/arguments 交给 Agent 或 IDE。
- 默认不加载 guest boot image，并关闭 debugger init 与 symbol-script
  auto-load；只有显式 `--symbols` 才让宿主 debugger 解析文件。

内核构建、源码获取和特定调试过程不进入 wrapper；调用方只需提供匹配的
boot image、initramfs 和可选 `vmlinux`。

### 4.3 自由选择 OCI 镜像

Agent 可以绕过自动检测，直接选择镜像：

```bash
asbx run \
  --project . \
  --image node:22-bookworm \
  --network public \
  -- npm test
```

支持：

- Docker Hub、GHCR 和其他 OCI Registry。
- 镜像 tag 或 digest。
- 已通过 `msb load`/`asbx image load` 导入的本地 OCI 镜像。
- Microsandbox snapshot。

高复现性场景推荐 digest，但不强制 Agent 只能使用 Catalog 镜像。

### 4.4 自由构建环境

常见单语言项目：

```bash
asbx run --project . --env go@1.24 -- go test ./...
asbx run --project . --env rust@1.88 -- cargo test --workspace
asbx run --project . --env node@22 -- npm test
```

多语言环境：

```bash
asbx env create audit-full \
  --base ubuntu:24.04 \
  --toolchain go@1.24 \
  --toolchain rust@1.88 \
  --toolchain node@22

asbx run --project . --env audit-full -- ./scripts/verify.sh
```

环境创建结果保存为磁盘 snapshot，不保持 VM 运行。

### 4.5 服务验证

创建 sandbox 时声明 guest port：

```bash
asbx open \
  --project . \
  --env node@22 \
  --publish 3000

asbx exec sbx_01J... -- npm run dev -- --host 0.0.0.0
asbx ports sbx_01J...
```

默认返回随机 loopback 地址：

```text
3000/tcp → http://127.0.0.1:54321
```

Agent 可以从宿主测试该 URL。关闭 sandbox 后端口自动消失。

如果只需要功能验证，优先在 guest 内执行 `curl http://127.0.0.1:3000`，无需发布端口。

## 5. Skill 设计

### 5.1 目录结构

```text
agent-sandbox/
├── SKILL.md
├── scripts/
│   └── check-asbx.sh
└── references/
    ├── cli.md
    ├── environments.md
    └── troubleshooting.md
```

`SKILL.md` 保持简短，只包含核心决策流程。详细 CLI、环境解析和错误处理按需读取 references。

### 5.2 建议的 frontmatter

```yaml
---
name: agent-sandbox
description: Run, build, test, audit, or inspect untrusted software inside disposable local microVM sandboxes. Use when an agent needs to execute repository code, install project dependencies, validate generated changes, start a local service, test multiple language versions, or inspect suspicious build and test behavior without running it directly on the host.
---
```

### 5.3 SKILL.md 核心工作流

Skill 应指导 Agent：

1. 在准备执行项目代码、构建脚本或依赖安装时使用 `asbx`。
2. 优先运行 `asbx env detect --project . --json` 了解项目环境。
3. 单命令验证优先使用 `asbx run`。
4. 需要多次命令、安装依赖或启动服务时使用 `open → exec → close`。
5. 根据任务需要自由选择 `off`、`public` 或显式 allowlist 网络。
6. 默认复制项目；明确需要宿主与 guest 实时共享时再使用 workspace mount。
7. 将需要取回的文件写到 `/out`。
8. 会话完成后主动 `asbx close`；如果命令失败，先收集诊断再关闭。
9. 不在宿主直接执行来自项目的 install、build 或 test 命令。

### 5.4 Skill 中的自由度

Skill 不应机械要求所有任务都：

- 禁止网络。
- 使用非 root。
- 使用固定镜像。
- 使用固定资源。
- 限制为单条命令。

应根据任务选择：

- 对普通构建，允许公网依赖下载。
- 对需要 apt、npm、cargo、go install 的环境准备，允许 guest root。
- 对未知项目，先用 `auto`，发现不匹配后由 Agent调整镜像。
- 对调试场景，允许交互 shell 和较长 TTL。
- 对 Web 服务，允许 Agent 发布明确端口。

## 6. 环境自动检测

### 6.1 检测输入

只解析声明文件，不执行项目代码：

| 生态 | 文件 |
|---|---|
| Go | `go.mod`、`go.work` |
| Rust | `rust-toolchain.toml`、`rust-toolchain`、`Cargo.toml` |
| Node.js | `.nvmrc`、`.node-version`、`package.json` |
| Python | `.python-version`、`pyproject.toml`、`uv.lock` |
| Java | `.java-version`、`pom.xml`、`build.gradle*` |

第一阶段实现 Go、Rust、Node.js/TypeScript；其他生态通过 detector plugin 扩展。

### 6.2 检测结果

```bash
asbx env detect --project . --json
```

```json
{
  "languages": [
    {"name": "rust", "version": "1.88.0", "source": "rust-toolchain.toml"},
    {"name": "node", "version": "22", "source": ".nvmrc"}
  ],
  "package_managers": [
    {"name": "cargo"},
    {"name": "pnpm", "version": "10"}
  ],
  "suggested_environment": "snapshot:env-45b8...",
  "warnings": []
}
```

检测器对单个声明文件设置合理大小上限，避免读取异常大文件，但不需要对 Agent 隐藏检测结果或强制采用建议。

### 6.3 环境解析优先级

```text
显式 --image
  > 显式 --snapshot
  > 显式 --env
  > 项目 .agent-sandbox.yaml
  > --env auto 检测结果
```

### 6.4 快速路径与组合环境

```text
常用单语言版本
  → 直接使用预构建 OCI 镜像

多个语言或少见版本
  → 从 audit-base 创建 builder sandbox
  → 安装工具链
  → 停止
  → 创建 environment snapshot
```

环境缓存 key：

```text
sha256(
  base image digest
  + host architecture
  + toolchain versions
  + provisioning manifest version
)
```

环境 builder 不复制项目源码，因此其 snapshot 可以作为可信环境跨项目复用。

项目依赖安装发生在项目 sandbox 内。包含项目 install hooks 的 snapshot 必须标记为 project-scoped，不能自动晋升为全局可信环境。

## 7. Agent 可控项与宿主底线

### 7.1 Agent 可以控制

- 任意兼容的 OCI image/tag/digest。
- 自动环境、预置环境或 snapshot。
- guest root 或非 root 用户。
- Microsandbox default 或 restricted guest profile。
- CPU、内存和磁盘请求。
- sandbox TTL 和命令 timeout。
- 公网、关闭网络或域名 allowlist。
- guest 命令、shell、cwd 和显式环境变量。
- workspace copy 或授权 workspace mount。
- loopback 服务端口。
- 创建和复用 environment snapshot。

### 7.2 wrapper 必须保留的底线

这些限制保护的是宿主免受恶意代码影响，不是假设 Agent 恶意。

#### 虚拟化边界

- 项目代码只能在 microVM 内执行。
- 不提供 `--privileged-host`、宿主 namespace 或宿主 Docker socket。
- 不把 `/dev`、`/proc`、宿主根目录或 hypervisor device 暴露给 guest。

#### 宿主文件系统边界

- 默认将项目复制到 sandbox 私有 writable disk。
- mount 只能位于启动 wrapper 时授权的 workspace roots。
- 不允许项目代码访问 workspace 之外的宿主路径。
- macOS 上默认不使用 writable bind；Agent 可以显式选择在授权 workspace 内使用，但 CLI 必须提示其隔离弱于 copy 模式。
- bind 和 artifact 写入必须有磁盘增长 quota。

#### 凭证边界

- 不自动继承宿主环境变量。
- 不自动挂载 `$HOME`、SSH、Git credentials、云凭证或 Docker config。
- Agent 可以显式传入单个环境变量或 secret handle。
- secret 默认只对指定域名使用，不写入 sandbox 持久配置和日志。

#### 网络边界

- `public` 允许公网，但默认继续阻断 private、link-local、metadata 和 host。
- Agent 可以通过显式高风险选项开放 private/host 网络；该行为记录在运行摘要中。
- 发布端口默认只绑定 `127.0.0.1`。
- 非 loopback 绑定需要宿主配置允许，并打印明显警告。

#### 资源紧急上限

Agent 可以自由申请资源，但 wrapper 需要有宿主级 emergency cap，避免恶意代码或错误命令拖死机器：

```text
per-sandbox CPU       configurable
per-sandbox memory    configurable
per-sandbox disk      configurable
global concurrent VM  configurable
global reserved RAM   configurable
```

这些不是固定产品限制。默认值由宿主配置和可用资源动态计算，Agent 可以看到 effective limits。

#### 输出和 artifact

- 使用 streaming exec，不调用无界收集 stdout/stderr 的便捷 API。
- 默认完整流式输出到 Agent 终端。
- wrapper 只保留有限的内存 ring buffer。
- 可配置最大落盘日志，超过后轮转或丢弃旧内容。
- JSON 返回只携带 bounded tail 和 `truncated` 标记。
- `/out` artifact 有总容量上限，防止填满宿主磁盘。

#### 生命周期

- 默认 ephemeral。
- session 有 TTL，但 Agent 可以续期。
- CLI 父进程异常退出时依赖 parent watchdog 和 reaper 回收 sandbox。
- 启动时扫描上次崩溃留下的 sandbox。
- 终止采用 graceful stop → terminate → kill → remove。

## 8. 网络模式

提供容易理解的模式，同时允许 Agent 覆盖：

| 模式 | 行为 |
|---|---|
| `off` | 完全关闭网络 |
| `public` | 允许公网，阻断 host/private/link-local/metadata |
| `dependencies` | 根据项目生态生成 Registry allowlist |
| `all` | Microsandbox allow-all；明确标记高风险 |
| `rules` | Agent 传入自定义 domain/CIDR/port 规则 |

示例：

```bash
asbx run --project . --network off -- cargo test

asbx run --project . --network dependencies -- npm ci

asbx run \
  --project . \
  --network rules \
  --allow-domain registry.npmjs.org \
  --allow-domain github.com \
  -- npm ci
```

`dependencies` 是便利模式，不是强制模式。

## 9. 项目与 artifact 传输

### 9.1 Copy 模式

默认：

```bash
asbx run --project . --project-mode copy -- ...
```

安全 walker：

- 只访问授权 workspace root。
- 不跟随 symlink 离开 root。
- 拒绝 socket、FIFO 和 device。
- 对文件数量、单文件和总大小设置可配置上限。
- 保留普通文件、目录、可执行位和安全 symlink。

默认 ignore 可以提高性能，但 Agent 可以覆盖：

```text
.git/
node_modules/
target/
dist/
build/
coverage/
```

### 9.2 Workspace mount

需要 guest 实时修改宿主项目时：

```bash
asbx open --project . --project-mode mount-rw
```

仅允许挂载已授权 workspace。该模式允许项目代码修改项目文件，本身属于 Agent 明确选择的工作流。

### 9.3 Artifact

guest 将结果写入 `/out`：

```bash
asbx artifact list sbx_01J...
asbx artifact get sbx_01J... /out/report.json --to ./report.json
```

目标路径仍必须位于授权 workspace 或显式 output root。

## 10. CLI 设计

### 10.1 命令树

```text
asbx
├── doctor
├── run
├── open
├── exec
├── shell
├── close
├── list
├── inspect
├── touch
├── ports
├── artifact
│   ├── list
│   └── get
├── env
│   ├── detect
│   ├── create
│   ├── list
│   ├── inspect
│   └── remove
├── image
│   ├── pull
│   ├── load
│   ├── list
│   └── prune
└── cache
    ├── status
    └── prune
```

### 10.2 通用参数

```text
--project PATH
--project-mode copy|mount-ro|mount-rw
--env auto|NAME|LANG@VERSION
--image OCI_REF
--snapshot NAME
--cpus N
--memory SIZE
--disk SIZE
--user USER
--security default|restricted
--network off|public|dependencies|all|rules
--timeout DURATION
--ttl DURATION
--publish GUEST_PORT[:HOST_PORT]
--env-var KEY=VALUE
--output text|json|jsonl
```

### 10.3 JSONL 事件

供 Agent 稳定解析：

```json
{"type":"environment.resolved","image":"node:22","cache_hit":true}
{"type":"sandbox.ready","id":"sbx_01J...","boot_ms":61}
{"type":"exec.stdout","data":"..."}
{"type":"exec.stderr","data":"..."}
{"type":"exec.exit","code":0,"duration_ms":18231}
{"type":"artifact","path":"/out/report.json","size":12520}
{"type":"sandbox.removed","id":"sbx_01J..."}
```

stdout/stderr 的原始内容与控制事件应使用不同 fd 或统一 JSONL，避免 Agent 误解析。

## 11. wrapper 内部模块

```text
agent-sandbox/
├── crates/
│   ├── core/          # spec、lease、状态机
│   ├── cli/           # asbx 参数、装配、命令编排和请求转换
│   ├── policy/        # 宿主底线与 effective config
│   ├── detector/      # 项目环境检测
│   ├── environment/   # OCI、toolchain、snapshot
│   ├── runtime/       # backend trait
│   ├── runtime-msb/   # Microsandbox adapter
│   ├── runtime-qemu/  # QEMU/QMP/SSH adapter
│   ├── transfer/      # project/artifact broker
│   ├── exec/          # streaming、timeout、output
│   ├── state/         # SQLite、lease、reaper
│   └── cache/         # OCI/snapshot quota 与 LRU
├── environments/
│   ├── catalog.yaml
│   ├── toolchains.yaml
│   └── provisioning/
└── skill/
    └── agent-sandbox/
```

CLI 内部按职责拆分：

```text
main.rs                 # 进程入口
app.rs                  # Clap 参数模型
app/bootstrap.rs        # 配置、状态和 concrete backend 装配
app/commands.rs         # 命令分派与用户可见工作流
app/request.rs          # CLI 参数 → runtime-neutral core request
debugger.rs             # debugger 发现、计划和启动
```

backend contract 使用 lifecycle + optional capabilities，而不是要求每个
backend 实现一个不断变大的接口：

```rust
trait SandboxRuntime {
    fn backend_id(&self) -> BackendId;
    fn capabilities(&self) -> BackendCapabilities;

    // 均有默认 None；backend 只暴露真实支持的能力。
    fn command_runtime(&self) -> Option<&dyn CommandRuntime> { None }
    fn file_transfer_runtime(&self) -> Option<&dyn FileTransferRuntime> { None }
    fn snapshot_runtime(&self) -> Option<&dyn SnapshotRuntime> { None }
    fn debug_runtime(&self) -> Option<&dyn DebugRuntime> { None }

    async fn create(&self, spec: &CreateSpec) -> Result<SandboxInfo>;
    async fn stop(&self, sandbox: &str) -> Result<()>;
    async fn kill(&self, sandbox: &str) -> Result<()>;
    async fn remove(&self, sandbox: &str) -> Result<()>;
    async fn list(&self) -> Result<Vec<SandboxInfo>>;
    async fn inspect(&self, sandbox: &str) -> Result<SandboxInfo>;
    async fn doctor(&self) -> Result<Vec<(String, bool, String)>>;
}

trait CommandRuntime {
    async fn exec_stream(
        &self, sandbox: &str, request: ExecRequest
    ) -> Result<ExecStream>;
}
```

新增 backend 的稳定接入面：

1. 实现 `SandboxRuntime` 生命周期，不需要 snapshot/image/exec 的空桩。
2. 按实际能力选择实现 `CommandRuntime`、`TerminalRuntime`、
   `FileTransferRuntime`、`SnapshotRuntime`、`ImageRuntime` 或
   `DebugRuntime`。
3. 在 `BackendCapabilities` 声明相同 feature。Registry 注册时会校验声明
   与 capability accessor 一致，启动阶段即可发现适配错误。
4. 只在 `app/bootstrap.rs` 注册 concrete adapter；core 和已有命令不依赖
   backend 类型。实现 `DebugRuntime` 的 GDB remote backend 可直接复用
   `asbx debug`，无需增加 backend 名称分支或解析私有 metadata。

`--backend` 直接解析开放式 `BackendId`，不维护 CLI backend 枚举；因此新增
backend 不需要修改 Clap 参数模型。

backend-facing 的 boot source、feature 和 debug protocol 枚举标记为
`non_exhaustive`；既有 adapter 对未来 root source 返回 `Unsupported`，而不是
因为新增枚举成员被迫同步改造。Snapshot store 和 image-cache store 也可独立
配置，backend 不需要为了承担其中一种角色而伪造另一种 capability。

## 12. 状态与目录

Unix：

```text
~/.agent-sandbox/
├── config.toml
├── state.db
├── images/
├── environments/
└── logs/

/tmp/asbx-<uid>/
├── sockets/
└── leases/
```

Windows：

```text
%LOCALAPPDATA%\agent-sandbox\
%TEMP%\asbx-<sid>\
```

运行时 socket 使用短路径，避免 macOS Unix socket 104 字节限制。

Microsandbox 自身的 `MSB_HOME` 由 wrapper 管理，不要求 Agent 直接操作。

## 13. 配置

宿主配置示例：

```toml
[runtime]
backend = "microsandbox"
max_concurrent_sandboxes = 4
max_reserved_memory = "12G"
default_ttl = "30m"
max_ttl = "8h"

[qemu]
# binary = "/usr/local/bin/qemu-system-aarch64"
# ssh_user = "root"
# ssh_key = "/Users/example/.ssh/qemu_guest"
boot_timeout = "2m"
shutdown_timeout = "10s"

[workspace]
roots = [
  "/Users/example/labs",
]
allow_rw_mount = true
rw_mount_quota = "2G"

[network]
default = "public"
allow_all_mode = true
allow_private_override = true
allow_non_loopback_publish = false
max_custom_rules = 64

[resources]
default_cpus = 2
default_memory = "2G"
default_disk = "16G"
max_cpus = 8
max_memory = "16G"
max_disk = "64G"

[output]
memory_tail = "2M"
max_log_disk = "128M"
max_artifact_total = "2G"

[cache]
max_size = "50G"
```

这里的默认值应保持宽松、可见和可配置，不把特定数字写死在 Skill。

## 14. 清理语义

### 14.1 一次性运行

无论命令成功、失败、timeout 或 Agent 中断：

```text
stop guest
  → 等待短暂 graceful timeout
  → terminate VM
  → kill VM
  → 验证进程退出
  → 删除 ephemeral state
```

### 14.2 会话模式

- `close` 立即清理。
- `touch` 续期。
- TTL 到期后清理。
- wrapper 启动时清理 stale lease。
- 宿主重启后，下一次 `asbx` 调用触发 bounded reconciliation。
- QEMU 不安装常驻 TTL helper；其到期 VM 在下一次 `asbx` 调用时回收。
- Microsandbox 还使用 runtime maximum duration 作为独立的清理兜底。

### 14.3 保留内容

默认保留：

- OCI 只读镜像 cache。
- environment snapshot。
- Agent 明确保存的 artifact。

默认删除：

- sandbox writable upper。
- 项目临时依赖和构建目录。
- sandbox 运行日志，除非 Agent指定保留。
- 端口映射和 runtime socket。

## 15. 实现状态

### Phase 1：最小可用闭环（已实现）

- Rust workspace 和 `asbx` CLI。
- Microsandbox adapter。
- `run` 一次性执行。
- `open/exec/close` 会话。
- project copy。
- streaming stdout/stderr。
- ephemeral、timeout 和异常清理。
- `off/public` 网络模式。
- `--image` 和 Go/Rust/Node 基础环境。
- 第一版 Agent Skill。

### Phase 2：环境体验

- `env detect`。
- `--env auto`。
- toolchain catalog。
- 多语言 environment builder。（已实现）
- environment snapshot cache。（已实现）
- `.agent-sandbox.yaml`。

### Phase 3：开发与审计体验

- workspace mount。（已实现）
- artifact broker。（已实现）
- service port 发布。（已实现）
- JSONL 事件。（已实现）
- log retention。
- cache quota/LRU。（已实现）

### Phase 4：跨平台与加固

- Linux x86_64/arm64 CI。（已配置）
- macOS arm64 CI。（已配置）
- Windows x86_64/arm64 CI。（已配置）
- 父进程崩溃、宿主重启和强制 kill 测试。
- 性能基准和长时间稳定性测试。

## 16. 恶意代码测试集

wrapper 必须用真实 hostile workloads 验证：

- fork bomb。
- 无限 stdout/stderr。
- 无限创建文件和填满磁盘。
- 创建百万小文件。
- symlink、hardlink 和 path traversal。
- 扫描宿主、内网和 metadata endpoint。
- 读取宿主环境变量和常见 credential path。
- 忽略 SIGTERM。
- guest OOM、kernel panic 和异常关机。
- package manager lifecycle script 执行恶意命令。
- 启动大量监听端口。
- wrapper 在 pull、boot、exec、shutdown 各阶段被强制杀死。

验收标准不是阻止代码破坏自己的 guest，而是：

- 不能逃出 VM。
- 不能读取未授权宿主文件。
- 不能使用未显式注入的宿主凭证。
- 不能无限占用宿主资源或日志磁盘。
- VM 和端口最终可回收。

## 17. MVP 验收标准

1. Agent 只需一条 `asbx run --project . --env auto -- ...` 即可验证 Go、Rust 或 Node 项目。
2. Agent 可以指定任意兼容 OCI 镜像。
3. Agent 可以开启公网、安装依赖、使用 guest root 和交互 shell。
4. 项目代码始终运行在独立 microVM 内。
5. 项目默认无法看到 workspace 之外的宿主文件。
6. 不显式注入时，guest 看不到宿主凭证和环境变量。
7. stdout flood 不会导致 Agent/wrapper 内存无界增长。
8. 磁盘填满、进程失控或超时后 sandbox 能被回收。
9. 一次性任务结束后没有常驻 VMM 进程。
10. 相同环境第二次运行能够复用 OCI cache 或 snapshot。
11. Skill 能指导 Agent 在 one-shot、session、service 三种模式间正确选择。
12. Agent 可以通过结构化计划连接 QEMU debugger，无需处理动态端口或
    debugger 参数差异。

## 18. 最终产品形态

```text
Agent Skill
  教 Agent 何时使用 sandbox、如何选择模式和处理失败

asbx CLI
  提供自由、可组合、可脚本化的 sandbox 操作

Agent Sandbox Core
  负责环境解析、宿主边界、生命周期、流式输出和缓存

Runtime Backends
  Microsandbox 负责 OCI、guest agent、精细网络和文件系统设备
  QEMU 负责完整系统、跨架构、串口、QMP 和 GDB stub
```

核心体验是“自由但有宿主边界”：

- Agent 可以自由建立和修改 guest 环境。
- Agent 可以运行任意 guest 命令和选择网络。
- 恶意项目即使拿到 guest root，也只能破坏自己的 VM 和 Agent 明确授予的 workspace。
- VM 不常驻，环境通过 OCI 和 snapshot 复用。
