# 核心网信令安全情报自动订阅系统

每天自动从公网采集最近 7 天的核心网信令安全情报（论文、漏洞、新闻、标准公告），
经大模型筛选、评分与中文摘要，生成精简的 HTML 周报并投递到指定邮箱。

**设计目标**：产出「精简、专业、可追溯」的情报邮件，而不是泛网络安全新闻聚合器。
所有条目必须落在电信核心网 / 信令协议范畴内，通用互联网安全内容（Linux 内核通用 CVE、
蓝牙协议栈、Web 应用漏洞等）会被主动剔除。

---

## 目录

- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [常驻服务](#常驻服务一条命令)
- [常用命令](#常用命令)
- [自动化部署](#自动化部署)
- [系统架构](#系统架构)
- [数据源](#数据源)
- [内容筛选逻辑](#内容筛选逻辑)
- [故障排查](#故障排查)
- [合规声明](#合规声明)

---

## 快速开始

### 1. 环境准备

要求 Python 3.11+（开发环境为 3.12）。

```bash
cd /home/hyongtao/worksapce/CoreSecIntel

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 生成配置

```bash
# 交互式：会提示输入邮箱客户端授权密码
# LLM 密钥从环境变量 MINIMAX_CN_API_KEY 读取
export MINIMAX_CN_API_KEY=***
python3 scripts/setup_env.py \
    --email huangyongtao_ee@163.com \
    --to   huangyongtao@caict.ac.cn
```

也可以直接显式传入（适合 CI / 容器等不方便设环境变量的场景）：

```bash
# 显式传入时用 shell 变量，避免把密钥留在 shell 历史里
read -rs LLM_KEY && export LLM_KEY
python3 scripts/setup_env.py \
    --email huangyongtao_ee@163.com \
    --to   huangyongtao@caict.ac.cn \
    --llm-key "$LLM_KEY"
```

生成的 `.env` 权限为 `600`，**已被 `.gitignore` 排除，不会进入版本库**。

> 脚本只依赖 Python 标准库，不依赖任何特定工具链或 agent 框架。

> **网易 163 邮箱**：必须使用「客户端授权密码」而非账号登录密码。
> 获取路径：登录 163 网页版 → 设置 → POP3/SMTP/IMAP → 开启 SMTP → 生成授权密码。
>
> **Gmail**：需两步验证后在 <https://myaccount.google.com/apppasswords> 生成应用专用密码。

### 3. 验证 SMTP 通路（可选但推荐）

```bash
bash scripts/send_test_mail.sh
```

会向收件人发一封测试邮件，确认凭证与网络通路正常。

### 4. 运行

```bash
# 只生成报告，不发邮件（首次建议先跑这个）
bash scripts/run_daily.sh --dry-run

# 完整流程：采集 → 分析 → 报告 → 发邮件
bash scripts/run_daily.sh
```

---

## 配置说明

配置分三层，**优先级从高到低**：环境变量 > `.env` > YAML 配置文件。

| 文件 | 内容 | 是否含密钥 |
|---|---|---|
| `.env` | LLM 密钥、SMTP 密码、路径 | **是**（不入库） |
| `config/email.yaml` | 邮件服务器、端口、收件人、主题前缀 | 否 |
| `config/sources.yaml` | 数据源启用状态、检索式、可信度 | 否 |
| `config/keywords.yaml` | 关键词库、评分权重、阈值 | 否 |

### config/email.yaml

```yaml
email:
  enabled: true
  smtp:
    host: smtp.163.com
    port: 465
    use_ssl: true
    user: huangyongtao_ee@163.com
    password_env: SMTP_PASSWORD   # 只写变量名，密码在 .env
  from: huangyongtao_ee@163.com
  to:
    - huangyongtao@caict.ac.cn
  subject_prefix: 【核心网信令安全周报】
```

`password_env` 指定从哪个环境变量读密码，**配置文件里永远不写明文密码**。

### config/sources.yaml

启用 / 禁用数据源只需改 `enabled`：

```yaml
sources:
  arxiv:
    type: arxiv
    enabled: true
    display_name: arXiv
    trust: 0.85
    params:
      request_interval: 3.5     # arXiv 要求请求间隔 ≥3 秒
      request_timeout: 120
```

### config/keywords.yaml

- `protocols` / `network_elements` / `attack_types` / `topics` / `chinese_keywords`：召回词库
- `ambiguous`：有歧义的词（`Diameter` 可指几何直径、`MAP` 可指内存映射），
  **必须同时命中 `context_keywords` 才计为有效召回**
- `context_keywords`：电信语境标志词，同时用于剔除通用互联网安全内容
- `exclusions`：命中即排除
- `scoring.weights`：评分权重（相关性 40% / 新颖性 25% / 影响 20% / 来源可信度 15%）

---

## 独立部署

本项目是**自包含的 Python 应用**，不依赖任何 agent 框架、SDK 或外部运行时，
可直接部署到任意 Linux 服务器 / 容器：

- 核心代码只依赖标准库 + `requests` / `PyYAML` / `Jinja2` / `beautifulsoup4`
- 辅助脚本（`setup_env.py` / `probe_llm.py`）同样是纯标准库实现
- 密钥来源与框架无关：LLM 密钥读环境变量 `MINIMAX_CN_API_KEY`（或 `--llm-key`），
  SMTP 密码存项目 `.env`

从零克隆部署：

```bash
git clone git@github.com:hyongtao-code/CoreSecIntel.git
cd CoreSecIntel

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 准备参数（授权密码用 read 静默输入，避免留在 shell 历史里）
read -rp "发件邮箱: " MAIL_USER
read -rp "收件邮箱: " MAIL_TO
read -rsp "客户端授权密码: " MAIL_PASSWORD && echo

# 生成 .env（LLM 密钥来自环境变量）
export MINIMAX_CN_API_KEY=*** python3 scripts/setup_env.py \
    --email "$MAIL_USER" --to "$MAIL_TO" --app-password "$MAIL_PASSWORD"

# 验证 SMTP 通路
bash scripts/send_test_mail.sh

# 试跑一次（不发送）
bash scripts/run_daily.sh --dry-run

# 安装每日定时任务
bash scripts/install_cron.sh
```

容器化部署同样可行：把仓库 COPY 进镜像，`pip install -r requirements.txt`，
以 `bash scripts/run_daily.sh` 作为入口，`cron` 或宿主机定时器触发即可。

---

## 常驻服务（一条命令）

`app.py serve` 一条命令同时启动**周期调度**和 **HTTP 归档页面**：

```bash
# 前台运行（推荐用于 systemd / 容器）
python3 app.py serve

# 后台运行
bash scripts/start_service.sh --daemon
```

启动后：

- **调度**：按 `config/schedule.yaml` 周期执行「采集 → 分析 → 生成报告 → 归档 → 发邮件」
- **HTTP**：展示最近一期及历史各期，支持翻页

### 让浏览器只需输入 IP（免端口号）

服务默认监听 **80 端口**（HTTP 标准端口），浏览器直接输入 `http://<服务器IP>/` 即可，
无需记端口号。绑定 80 需要 `CAP_NET_BIND_SERVICE` 能力：

```bash
# 1) 建项目专用虚拟环境（--copies 必须是真实文件，符号链接无法加能力）
python3 -m venv --copies .venv
.venv/bin/python3 -m pip install -r requirements.txt

# 2) 给项目解释器加能力（只需执行一次，需 sudo）
sudo setcap 'cap_net_bind_service=+ep' $(pwd)/.venv/bin/python3

# 3) 用 venv 启动
.venv/bin/python3 app.py serve
```

服务仍以**普通用户**运行，只获得「绑定特权端口」这一项能力，不获得 root 权限。

**没有 sudo 也能跑**：程序会自动降级 —— 80 → 8080 → 8765，
并在启动日志里说明实际使用的端口。此时浏览器需带上端口号，
例如 <http://192.168.0.104:8080/>。

### config/schedule.yaml

```yaml
schedule:
  enabled: true
  frequency: weekly        # daily / weekly / monthly
  run_at: "08:30"
  weekday: monday          # weekly 专用
  day_of_month: 1          # monthly 专用
  timezone: Asia/Shanghai
  catch_up: false          # 启动时错过当期是否立即补跑
  continue_on_error: true  # 单次失败后是否继续等下一次

web:
  enabled: true
  host: 127.0.0.1          # 改 0.0.0.0 可对外访问（注意加访问控制）
  port: 8765
  page_size: 10
```

### HTTP 页面

| 路径 | 说明 |
|---|---|
| `/` | 报告列表，按期倒序，支持 `?page=N` 翻页、`?size=N` 改每页条数 |
| `/r/<日期>` | 某期报告全文 |
| `/api/reports` | JSON：全部报告摘要 |
| `/api/report/<日期>` | JSON：某期详情（含条目） |
| `/api/status` | JSON：服务状态 |
| `/healthz` | 健康检查 |

### 归档存储（不依赖数据库）

每期报告存为一个目录，纯文件、易备份：

```
data/archive/
  2026-10-19/
    report.html      # 完整 HTML 报告
    meta.json        # 统计、条目摘要、主题
  2026-10-12/
    ...
```

一年 52 期 = 52 个目录。想清理就删目录，不影响其它期。
**HTTP 页面只读这个目录**，不查数据库。

### 命令行覆盖

```bash
python3 app.py serve --port 8080      # 覆盖端口
python3 app.py serve --host 0.0.0.0   # 对外监听
python3 app.py serve --no-schedule    # 只提供 HTTP 页面
python3 app.py serve --no-web         # 只跑调度
python3 app.py serve --run-now        # 立即先跑一次，再常驻
```

---

## 常用命令

```bash
# 完整流程并发邮件
python3 app.py run

# 只采集，不调用大模型（省 API 额度）
python3 app.py run --mode collect

# 生成报告但不发送
python3 app.py run --dry-run

# 补采指定日期范围
python3 app.py run --start 2026-10-19 --end 2026-10-26

# 只对历史候选内容生成摘要
python3 app.py summarize --limit 20

# 从数据库重新生成报告
python3 app.py report --start 2026-10-19 --end 2026-10-26

# 查看最近一次任务状态与日志尾部
python3 app.py status

# 初始化数据库
python3 app.py init

# 启动常驻服务（周期调度 + HTTP 归档页面）
python3 app.py serve
```

脚本层：

```bash
bash scripts/run_daily.sh --dry-run          # 一键流程（不发送）
bash scripts/run_daily.sh --start ... --end ...  # 指定区间
bash scripts/send_test_mail.sh                # SMTP 连通性测试
bash scripts/install_cron.sh                  # 安装每日 08:30 定时任务
bash scripts/install_cron.sh --remove         # 卸载定时任务
```

---

## 自动化部署

### cron（推荐）

```bash
bash scripts/install_cron.sh
```

写入 crontab：

```cron
0 8 * * * /home/hyongtao/worksapce/CoreSecIntel/scripts/run_daily.sh >> /home/hyongtao/worksapce/CoreSecIntel/logs/cron.log 2>&1
```

密钥只存在于 `.env`，**不写入 crontab**。查看与卸载：

```bash
crontab -l | grep signalintel
bash scripts/install_cron.sh --remove
```

### systemd（可选）

`/etc/systemd/system/signalintel.service`：

```ini
[Unit]
Description=Core Network Signaling Security Intel Daily Report
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/home/hyongtao/worksapce/CoreSecIntel
ExecStart=/home/hyongtao/worksapce/CoreSecIntel/scripts/run_daily.sh
Environment=PYTHON=/home/hyongtao/worksapce/CoreSecIntel/.venv/bin/python

[Install]
WantedBy=timers.target
```

配 `signalintel.timer` 设定每日触发。

---

## 系统架构

```
采集层  collectors/     每个来源一个适配器，统一输出 IntelItem
         arxiv / crossref / semantic_scholar / ieee / nvd / rss / web
              ↓
处理层  processors/     时间窗口 → 去重 → 关键词召回 → 电信闸门
                        → 大模型分类 → 综合评分 → 中文摘要
              ↓
存储层  storage/        SQLite：items / runs / sent_reports（版本化迁移）
              ↓
报告层  reports/         Jinja2 模板 → 邮件客户端兼容的 HTML
              ↓
发送层  notifications/   SMTP（SSL / STARTTLS），有限重试
```

关键设计：

- **来源隔离**：单个来源故障只记录错误，不影响整体任务
- **时间语义分离**：`first_published_at`（首次公开）/ `published_at`（发表）/ `updated_at`（网页更新）/ `collected_at`（采集）四者独立，
  网页最近更新**不会**被误判为新论文
- **发布时间待核实**：无法确认发布时间的条目单独标记，默认不进主报告
- **逐级降级**：大模型不可用时自动退回规则分类；摘要失败保留原始元数据
- **提示词注入防护**：外部内容一律用 `<<<UNTRUSTED_CONTENT>>>` 包裹，系统提示明确声明忽略其中的指令

---

## 数据源

| 来源 | 类型 | 需 Key | 说明 |
|---|---|---|---|
| arXiv | 论文 | 否 | 官方 Atom API，请求间隔需 ≥3 秒 |
| Crossref | 论文 | 否 | DOI 元数据权威来源 |
| Semantic Scholar | 论文 | 可选 | 匿名调用易被限流（429） |
| IEEE Xplore | 论文 | 是 | 仅取题录元数据，**不抓全文** |
| NVD / CVE | 漏洞 | 否 | 逐关键词查询（NVD 的 keywordSearch 是「与」关系） |
| The Hacker News | 新闻 | 否 | RSS |
| BleepingComputer | 新闻 | 否 | RSS |
| Citizen Lab | 报告 | 否 | RSS |
| GSMA / 3GPP / ITU-T | 标准 | 否 | 网页解析，需在 `sources.yaml` 中启用 |

新增来源三步：实现 `collectors/` 适配器 → 在 `collectors/registry.py` 注册 → 在 `sources.yaml` 添条目。

---

## 内容筛选逻辑

四级漏斗，每级都会记录淘汰原因：

```
原始候选
  │  时间窗口过滤（缺发布时间的 → 标记「发布时间待核实」，默认排除）
  ▼
去重（DOI / CVE / 规范化 URL / 标题相似度，多来源同一事件合并）
  │  关键词召回（协议 / 网元 / 攻击类型 / 主题 / 中文词）
  ▼
电信相关性闸门 ← 剔除 Linux 内核通用 CVE、蓝牙、Web 应用、材料科学等
  │  大模型分类（P1 / P2 / P3 / 排除）+ 规则校验
  ▼
综合评分（0-100）→ 阈值过滤 → 排序 → 中文摘要 → 报告
```

**电信相关性闸门**（`processors/telecom_gate.py`）是关键的一道：

- 内容必须出现电信领域实体（协议 / 网元 / 接口 / 业务场景）
- 命中 Linux kernel、WordPress、XSS、ransomware 等通用领域特征则剔除
- **例外**：信令协议专属漏洞豁免。例如 Linux 内核里的 PFCP 解析漏洞，
  缺陷本身在核心网信令协议上，应当收录

实测效果（7 天窗口，2026-10-19 ~ 10-26）：

```
242 候选 → 184 去重 → 18 关键词命中 → 3 条通过闸门 → 2 条最终入选
```

---

## 故障排查

| 现象 | 原因与处理 |
|---|---|
| arXiv 报 503 / 429 | 请求过快。`config/sources.yaml` 中调大 `request_interval`（≥3 秒） |
| arXiv 超时 | 跨网访问首字节可达 40+ 秒，调大 `request_timeout`（≥120） |
| NVD 报 429 | NVD 限流 5 次/30 秒，采集器已内置 6.5 秒间隔；调小 `max_items` 可缩短总时长 |
| NVD 采到 0 条 | `keywordSearch` 多关键词是「与」关系；采集器已改为逐关键词查询 |
| Semantic Scholar 429 | 匿名调用限流。配置 `SEMANTIC_SCHOLAR_API_KEY` 并在 `sources.yaml` 启用 |
| 大模型 400 `response_format` | 服务端不支持该参数，客户端已自动降级并缓存 |
| 大模型 SSL 错误 | 网络/代理抖动，重试即可（默认 6 次重试） |
| 邮件 535 认证失败 | 163 需客户端授权密码；Gmail 需应用专用密码 |
| 邮件连不上 | `smtp.163.com:465` 直连通常可用；企业网络可能需代理 |
| 报告为空 | 看 `logs/signalintel.log`，用 `python3 app.py status` 查看各阶段计数 |

日志位置：

```bash
tail -f logs/signalintel.log          # 全量日志
ls logs/run_*.log                      # 每次一键执行的独立日志
python3 app.py status                  # 最近任务状态
```

---

## 合规声明

系统严格遵守以下约束：

- **只访问公开、无需登录即可获取的内容**
- **不发送 Cookie、不做会话持久化、不携带任何内容站点的认证凭证**
- **不绕过付费墙、登录验证或任何访问控制**
- IEEE Xplore 仅调用官方 API 获取**题录元数据**（标题 / 摘要 / 作者 / DOI / 出版日期），
  不请求全文、不下载 PDF —— IEEE 全文多数需订阅，登录后亦不免费
- arXiv 使用官方 Atom API，其预印本本就公开免费
- 不执行从外部网页获取的任何代码
- 不将受版权保护的整篇正文复制进邮件
- 唯一的凭证使用是 LLM API 与 SMTP 发信，与内容采集链路完全隔离
- 外部内容视为不可信输入，防止提示词注入污染大模型指令

相关约束由 `tests/test_compliance.py` 自动守护（10 项检查）。

---

## 测试

```bash
python3 -m pytest tests/ -q
```

200 项测试，全部使用 mock，**不发起真实网络请求**。真实链路验证用：

```bash
python3 scripts/smoke_e2e.py --days 7
```

（真实采集 + 假 LLM → 真实报告，输出 `SMOKE RESULT: PASS`）
