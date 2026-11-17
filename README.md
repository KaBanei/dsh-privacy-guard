# dsh-privacy-guard · 隐私守卫

> 给 [DeepSeek Harness](https://github.com/deepseek-ai) 加一道「隐私门」：AI 想读写个人隐私数据时，必须由你本人在 **Windows 原生窗口**里输入隐私密码并明确同意；平时它会把敏感信息加密收进本机隐私库。

[English](README.en.md) · [MIT License](LICENSE)

---

## 为什么需要它

DSH 的 Agent 天生拥有 `read` / `write` / `grep` / `pwsh` / 桌面控制等工具。这意味着只要模型「想」，它就能读到简历、证件、聊天记录、账号密码——而多数时候你并不会逐条检查它读了什么。

`dsh-privacy-guard` 在工具调用链路上加了两道闸：

- **路径层**：目标落在受保护目录时，工具调用先挂起，弹出系统原生认证窗；
- **内容层**：工具返回内容里出现身份证、银行卡、密码等敏感信息时，同样挂起；你拒绝，整段结果被阻断，原文不会进入模型上下文。

密码只在本机校验，**不会出现在对话记录里，也不会进入模型上下文**。

## 功能

| 能力 | 说明 |
| --- | --- |
| 路径保护 | 受保护目录下的读/写/删除/`grep`/`glob`/shell 命令都会触发认证 |
| 内容保护 | 工具结果命中身份证（校验位）、银行卡（Luhn）、手机号、邮箱、密码、API Key、私钥等 |
| 原生认证窗 | PowerShell + WinForms 系统窗口，TopMost、倒计时、密码遮罩、可见脱敏摘要 |
| 加密隐私库 | 敏感值用隐私密码派生的密钥加密（scrypt + AES-256-GCM），只存本机 |
| 授权有效期 | 默认 10 分钟（同一会话、同一位置），可取消勾选变为「仅本次」 |
| 防刷屏 | 每分钟最多弹窗次数可配；超限自动拒绝 |
| 防爆破 | 连续输错 5 次开始指数退避锁定（最长 30 分钟） |
| 审计 | 只记录类型/路径/时间/决定，不记录值 |
| 零网络 | 不发起任何网络请求，不上传任何数据 |

## 工作原理

```
模型发起工具调用
      │
      ▼
tools/pre-execute  ── 命中受保护路径？ ──是──▶ 原生认证窗 ──拒绝/超时──▶ 调用被拦截
      │否                                              │允许
      ▼                                                ▼
   工具执行 ◀──────────────────────────────────────────┘
      │
      ▼
tools/post-execute ── 结果含敏感信息？ ──是──▶ 原生认证窗 ──拒绝──▶ 整段结果阻断
      │否                                              │允许
      ▼                                                ▼
   返回给模型                                        返回给模型
```

## 环境要求

- **Windows 10 / 11**（认证窗依赖 Windows PowerShell 5.1 + WinForms；其他平台会拒绝安装）
- DeepSeek Harness（支持 `dsh` bundle / `cordis` 插件）
- Node.js **>= 22**

## 安装

### 从 npm

```powershell
dsh plugin --profile desktop add dsh-privacy-guard
```

### 从 GitHub

```powershell
dsh plugin --profile desktop add github:KaBanei/dsh-privacy-guard
```

或克隆后从目录安装：

```powershell
git clone https://github.com/KaBanei/dsh-privacy-guard.git
dsh plugin --profile desktop add .\dsh-privacy-guard
```

### 从 tarball

```powershell
dsh plugin --profile desktop add .\dsh-privacy-guard-0.1.0.tgz
```

安装后重启 DSH（或让 profile 重载），插件会自动注册 `/privacy` 命令。

## 第一次使用

在对话输入框输入：

```
/privacy setup
```

按提示在弹出的系统窗口里设置**隐私密码**（至少 8 位）。请务必牢记：隐私库用这个密码派生的密钥加密，**忘记后无法找回**。

之后 AI 第一次访问受保护目录时会弹认证窗；你输入密码并点「允许本次」才会放行。

## 命令

| 命令 | 作用 |
| --- | --- |
| `/privacy` / `/privacy status` | 查看状态、受保护路径、解锁情况、近 24 小时授权/拒绝次数 |
| `/privacy setup` | 首次设置 / 修改隐私密码 |
| `/privacy unlock` | 解锁隐私库（后台加密收集需要） |
| `/privacy lock` | 立即锁定：清空内存密钥与已发放授权 |
| `/privacy scan` | 立即扫描并加密收集敏感信息 |
| `/privacy vault` | 查看隐私库分类统计（不显示具体值） |
| `/privacy paths` | 列出受保护路径 |
| `/privacy addpath <路径>` / `rmpath <路径>` | 增删受保护路径（支持 `~` 与 `*` `**` 通配） |
| `/privacy on` / `off` | 启用 / 停用拦截 |
| `/privacy strict on\|off` | 严格模式：手机号/邮箱等中敏感信息也强制认证 |
| `/privacy audit [n]` | 查看最近 n 条审计记录 |
| `/privacy test` | 自检（加密、检测器、PowerShell、存储） |

## 配置

配置文件：`~/.dsh/privacy-guard/config.json`（可用 `DSH_HOME` 改根目录）。

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | 总开关 |
| `protectedPaths` | 自动探测 `桌面/文档/图片` 下 `个人/隐私/私人/证件/资料` | 受保护目录，支持通配 |
| `autoCollect` | `true` | 自动收集开关 |
| `collectRoots` | 同 `protectedPaths` | 自动收集扫描根目录 |
| `collectIntervalMinutes` | `30` | 扫描间隔（分钟） |
| `grantTtlSeconds` | `600` | 一次授权的有效期 |
| `keyCacheMinutes` | `15` | 解锁后密钥在内存中的保留时间 |
| `promptTimeoutSeconds` | `120` | 认证窗无操作自动拒绝的秒数 |
| `maxPromptsPerMinute` | `6` | 每分钟最多弹窗次数（防刷屏） |
| `strictScan` | `false` | 严格模式 |
| `scanWebResults` | `false` | 是否也扫描联网结果 |
| `extraPatterns` | `[]` | 追加的自定义正则（按高敏感处理） |

## 数据与安全

### 数据文件（`~/.dsh/privacy-guard/`）

| 文件 | 内容 | 是否加密 |
| --- | --- | --- |
| `config.json` | 受保护路径、开关、超时等 | 否（无隐私内容） |
| `secrets.json` | 盐、scrypt 参数、被密码封装的隐私库密钥 | 密钥已封装；密码本身不落盘 |
| `vault.enc` | 收集到的敏感值 | **是**（AES-256-GCM，需密码） |
| `index.json` | 敏感信息「类型/计数/来源」元数据 | 否（不含原始值） |
| `audit.log` | 认证与拦截审计 | 否（只记类型/路径/时间，不记值） |
| `state.json` | 失败次数、锁定截止时间 | 否 |

### 密码与密钥

- 密钥派生：scrypt（N=32768, r=8, p=1）→ 32 字节 KEK；
- 隐私库密钥（DEK）随机生成，用 KEK 以 AES-256-GCM 封装后落盘；
- 密码错误由 GCM 认证失败判定，不单独存密码哈希；
- 隐私库密钥只在解锁期间驻留内存，`/privacy lock` 或超时即清除。

### 威胁模型

**能防住：**

- AI 直接 `read` / `grep` / shell 读取受保护目录 → 必须你本人输密码；
- AI 读取了别处的文件、结果里恰好含身份证/银行卡/密码 → 结果被阻断；
- AI 通过 shell 拼接命令绕路 → 命令文本里的受保护路径同样会命中；
- 磁盘丢失或被拷走 → `vault.enc` 没有密码解不开；
- AI 读隐私库文件本身 → 只有密文；读 `secrets.json` 也只有盐和封装后的密钥。

**防不住 / 需要你知道的：**

1. **同用户全量权限可自我篡改**：拥有 `~/.dsh` 或插件目录写权限的程序可以改写配置、删掉插件来绕过。请配合 DSH 的沙箱与审批（`read-only` / `workspace-write`）使用。
2. **解锁窗口期**：解锁后密钥在主机进程内存中保留一段时间，这是后台自动加密入库所必需的。
3. **图片 / 截图**：文本检测器看不到二进制图像里的证件；这类请用路径规则覆盖。
4. **元数据**：`index.json`、`audit.log` 会记录哪些文件含敏感信息（不含值）。
5. **响应文件**：认证过程中密码会短暂写入 `%TEMP%` 下的响应文件（进程退出前删除），同用户进程在毫秒级窗口内理论上可读。

### 隐私声明

- 本插件**不发起任何网络请求**，不含遥测；
- 所有数据只写入本机 `~/.dsh/privacy-guard/`；
- 加密库的密钥只由你设置的密码派生，作者无法解密。

## 常见问题

**为什么用独立密码，而不是 Windows Hello / 锁屏密码？**
Windows Hello PIN 无法被普通桌面程序验证；微软账户密码用 `LogonUser` 校验也经常失败。独立密码不依赖登录方式、离线可验证，而且能真正参与加密。

**忘记密码怎么办？**
隐私库无法恢复（这是设计目标）。可删除 `~/.dsh/privacy-guard/` 重新初始化，但已收集的加密内容会丢失。

**支持 macOS / Linux 吗？**
目前认证窗依赖 Windows PowerShell + WinForms，仅支持 Windows。其他平台会拒绝安装。

**会不会误拦正常操作？**
默认只保护 `个人/隐私/私人/证件/资料` 这类目录；内容层默认只对高敏感信息（证件、银行卡、密码、API Key）强制认证。觉得太频繁可把 `strictScan` 关掉或缩短授权时长。

## 卸载

```powershell
dsh plugin --profile desktop remove dsh-privacy-guard
```

数据目录 `~/.dsh/privacy-guard/` 不会自动删除，需要时手动删除（删除后隐私库不可恢复）。

## 开发

```powershell
node test/selftest.mjs   # 20 项自检，不弹窗、只写临时目录
```

目录结构：

```
dsh-privacy-guard/
├─ src/
│  ├─ index.mjs      # 插件入口：拦截、授权、命令、收集
│  ├─ detect.mjs     # 敏感信息检测器（含身份证/Luhn 校验）
│  ├─ crypto.mjs     # scrypt + AES-256-GCM
│  ├─ paths.mjs      # 路径解析与受保护目录匹配
│  ├─ store.mjs      # 配置 / 密钥 / 隐私库 / 审计
│  └─ dialog.mjs     # 原生认证窗驱动
├─ assets/dialog.ps1 # WinForms 认证窗
├─ test/selftest.mjs
└─ cordis.patch.yml  # bundle patch
```

## 许可

[MIT](LICENSE)
