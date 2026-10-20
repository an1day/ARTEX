# ARTEX Agent Test Engine 0.1

当前为可运行的服务 MVP。实现会话隔离、双通道 SSE、受限 MCP 工具、单 worker 作业、证据归档和 canary 验证。真实 wesmart/PRE 协议尚未核对，工具日志与 native finding/retest 导入尚未接入。

代码来自用户自有 ai-protocol-fuzzer 的必要模块和本轮新增实现。本目录随 ARTEX 仓库适用的许可证分发；保留原有声明。未迁入旧配置、账号、历史结果、压缩包或第三方 payload 库。此目录是后续 ARTEX 引擎开发的主位置，原项目仅保留兼容修复。

## 安装和离线检查

Python 3.11+：

```bash
python -m pip install -e ".[dev]"
python -m pytest tests -q
```

建议使用独立虚拟环境。不要同时在同一环境 editable-install 本包和完整 ai-protocol-fuzzer：二者使用同一个 Python import namespace。

## 合成演示

先从本地秘密存储注入随机 `AGENT_TEST_SERVICE_TOKEN`，至少 32 字符；ARTEX 与 sidecar 使用相同值。不要把令牌写入浏览器、报告或 Git。

```bash
python -m ai_protocol_fuzzer.service.demo --data-dir .data/demo --port 8791
```

该命令同时启动一个临时回环 SSE 目标和 MCP 服务，不访问任何真实 Agent 或 PRE。演示目标的 scope_revision 为 synthetic-v1。T03 是两轮协议基线；T08 故意模拟 canary 泄露但只形成模拟候选；T09 明确 blocked。

ARTEX 后端进程配置：

```text
ARTEX_AGENT_TEST_URL=http://127.0.0.1:8791/mcp
AGENT_TEST_SERVICE_TOKEN=<从本地秘密存储注入的同一令牌>
```

按 ARTEX 原有方式启动 PostgreSQL、Go 后端及前端，登录后打开 `/function/agent-security`。侧栏也有“Agent 安全测试”。本页使用现有 JWT，不把 sidecar 令牌传给浏览器。

容器中的 127.0.0.1 指向容器自身。当前 bridge 只允许回环服务地址：先用原生后端与原生 sidecar 验证；容器间连接和相应网络策略尚未开放。

## 登记真实目标

```bash
python -m ai_protocol_fuzzer.service.server --registry examples/configs/agent-service-local.example.yaml --data-dir .data/live --port 8791
```

模板默认 disabled。真实目标需填精确 origin、身份引用、source_commit（或部署版本说明）、scope_revision，完成协议核对后设置 protocol_reviewed=true，再显式启用。凭据只经 headers_env 引用；认证失败不自动寻找或使用旧凭据。

PRE 另需 `environment: pre`、`allow_remote: true`、HTTPS 和精确 allowed_origins。参考 agent-service-pre.example.yaml。配置中的预置域名是示例，实际授权地址保存在忽略的本地配置文件中。私网 DNS 地址必须明确登记 allowed_peer_cidrs，默认不放行；socket 地址固定到已检查的解析结果，保留原 Host/TLS SNI，不跟随重定向、不继承系统代理。若环境必须使用代理，当前版本返回限制而非自动绕过网络策略。

首轮 PRE 只登记 T03。T08 需目标预置随机 canary，且有可比基线和独立新会话复核；T09 需要可信工具执行日志适配，当前固定 blocked。

### PRE 消息接口适配

`base_url` 包含业务前缀（例如 `/api/bullgpt-vega`），引擎在其后拼接 `/session/prompt`。`query_params` 允许 `appID`/`workspaceID`，敏感工作空间标识可经 `query_params_env` 引用环境变量。上下文参数贯穿创建、订阅、提交，并参与会话隔离键；不在注册文件中复用抓包中的 sessionID。

`headers_env` 支持 `access_token`、`did` 等认证/身份头；静态 `headers` 只接受已列出的业务头，拒绝内联凭据、Host 和任意转发头。`model_selection` 配置 modelID/providerID，`generate_message_ids` 每轮生成新 messageID/part ID；`timestamp_header` 在每个请求发送时生成毫秒 t_time。不要复用抓包时间戳、消息 ID 或 part ID。

后续脱敏材料说明 PRE 使用客户端 `ses_` 会话标识和 `/session/message/id` 分配步骤。设置 `session_mode: client_message_id` 后，引擎按身份、工作空间和运行生成新会话，先 POST `/session/message/id`（空 JSON），再发送 prompt；每个后续 turn 同样分配一次。不会调用旧 `/session` 创建接口，不允许复用 URL 中捕获的 sessionID。`server_create` 保留供旧协议与合成演示使用。

分配接口响应结构尚未提供；当前只检查状态及体积，不猜测其中的消息 ID。最简提交只含 parts；`generate_message_ids: false` 不向其中添加客户端 messageID/part ID。可选 model 配置仍保留，确认可省略时可删去 model_selection。

`response_channel: session_event` 从带 workspaceID/sessionID/appID 的 `/session/event` 收集回复，同时有界排空 prompt 响应。`response_channel: prompt_sse` 直接解析 prompt 的 text/event-stream，不再订阅另一条流。两种模式不合并重复事件、不自动回退或重发 prompt，均须有有效文本和匹配结束事件；新别名支持 session.idle / turn-complete。client_message_id 模式下订阅流结束事件必须带匹配 sessionID，直接 prompt 流允许请求本身提供关联。连接、心跳和快照不是完成证明。

当前正文解析仍支持 message.updated / message.part.updated / message.part.delta 结构。用户提供的是 App 流连接/心跳样例，尚无实际回复正文、完整结束事件及分配响应样例；其他格式会明确失败或超时，不会算成功。平台本轮未请求 PRE，保持 enabled=false 和 protocol_reviewed=false。不订阅 App 全局流，不执行 PATCH 或账号间权限测试。

## API 与状态

MCP `/mcp` 支持 list_target_capabilities、list_test_cases、start_test_run、get_test_run、cancel_test_run、get_evidence_manifest、get_evidence_preview、verify_candidate。ARTEX `/api/agent-security/tools/{tool}` 只转发该固定集合，受现有 JWT 保护。

- start 只接受注册 ID，不接受任意 URL、prompt、shell 或文件路径；幂等键绑定输入。
- 目标请求最多 1 次/秒，单 worker，每用例最多 12 次请求，整轮最多 100 次/20 分钟，输入不可提升预算。
- 重启把未完成作业标为 interrupted，不重放 prompt。
- 取消关闭客户端流、停止新动作；目标端 abort 尚未实现，目标工具可能继续执行。
- 原始事件在内存中有字节/数量上限，转为完整脱敏 NDJSON 工件落盘；UI 只返回有限预览。超限明确失败，不给完整证据结论。
- 默认拒绝压缩 SSE，避免无界解压；PRE 若使用 gzip，须确认 identity 编码是否可用或增加有界解压后再启用。
- 证据摘要与正文哈希可复核；哈希本身不证明漏洞。无可信观测时不 confirmed。

## 当前限制

SQLite 是新运行记录的持久源；ARTEX 现有 PostgreSQL 任务/意图关系只携带关联 ID，专用 PG 索引、任务图写回、native finding/retest 导入仍待后续实现。UI 不宣称 native 漏洞已登记。

目前不支持共享账户下的多租户隔离、多执行 worker、任意工具测试、持久记忆测试或自动远程攻击生成。现有 ARTEX 通用工具能力未被本模块重写；专用测试角色只绑定此 sidecar，不把被测 MCP 放入控制面。

脱敏覆盖登记的秘密、canary、常见敏感字段与 Bearer 值；未知敏感信息仍需要人工审阅后再导出。Windows chmod 不是完整 ACL 管理，数据目录须放在受控用户目录。
