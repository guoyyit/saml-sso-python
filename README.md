# saml-sso-python

基于 SAML 2.0 的联邦身份接入服务：外部身份提供方（IdP）通过 POST 绑定提交签名断言，
本服务（SP）校验断言后在本地建立可独立管理的会话，并支持单点登出（SLO）。

## 架构

```
saml_sso/
├── config.py      配置模型与 JSON 加载（多 IdP）
├── errors.py      可区分的错误类型（每种拒绝原因一个错误码）
├── metadata.py    IdP 元数据解析 + 受信任密钥管理（KeyStore）
├── assertion.py   断言/LogoutRequest 校验（签名、时间、受众、发行方）
├── replay.py      SQLite 持久化重放防护
├── attributes.py  断言属性 -> 本地会话属性映射（按 IdP 隔离）
├── sessions.py    本地会话存储（线程安全，支持 SLO 失效）
├── audit.py       脱敏审计日志（JSONL）
└── app.py         FastAPI 端点
```

### 端点

| 端点 | 方法 | 说明 |
| --- | --- | --- |
| `/login/{idp_id}` | GET | 生成 AuthnRequest，302 重定向到 IdP（HTTP-Redirect 绑定） |
| `/saml/acs/{idp_id}` | POST | 接收 `SAMLResponse`（POST 绑定），校验通过后建立本地会话并下发 HttpOnly Cookie |
| `/saml/slo/{idp_id}` | POST | 接收 IdP 签名的 `SAMLRequest`（LogoutRequest），按 NameID+SessionIndex 失效会话 |
| `/logout` | POST | 本地登出，会话立即失效 |
| `/me` | GET | 查看当前会话（每次请求重新授权） |

## 信任模型

1. **密钥信任**：SP 只信任每个 IdP 配置中显式列出的 X.509 证书（PEM）。
   断言签名内嵌的证书若不在信任列表中，直接以 `untrusted_key` 拒绝——
   绝不使用断言自带的证书去验证断言本身。
2. **签名强制**：Response 或 Assertion 至少其一必须携带有效 XML-DSig 签名。
   未签名（`unsigned_assertion`）、签名无效或被篡改（`invalid_signature`）、
   密钥不受信（`untrusted_key`）分别返回可区分的错误码。
3. **防签名包装（XSW）**：属性提取只针对验签通过的元素本身，
   攻击者插入的未签名副本不会被采信。
4. **发行方绑定**：断言 Issuer 必须与所选 IdP 的 `entity_id` 完全一致，
   防止一个 IdP 的断言被拿到另一个 IdP 的端点上使用。
5. **受众限制**：断言的 AudienceRestriction 必须包含本 SP 的 `sp_entity_id`。
6. **时间条件**：NotBefore / NotOnOrAfter 之外（含可配置的时钟偏移容忍窗口）一律拒绝。
7. **重放防护**：断言 ID 在断言有效期内只能消费一次，记录持久化在 SQLite 中，
   进程重启不丢失；并发消费由数据库主键约束保证只有一个成功。
8. **IdP 隔离**：每个 IdP 有独立的信任密钥、属性映射与必需属性；
   会话绑定来源 IdP，SLO 只失效匹配 IdP + NameID (+ SessionIndex) 的会话。
9. **审计脱敏**：审计日志不记录原始断言 XML；`name_id` 与各 IdP 声明的
   `sensitive_attributes` 一律以 SHA-256 摘要形式落盘。

## 配置项

通过 JSON 文件配置，以环境变量 `SAML_SSO_CONFIG` 指定路径：

```json
{
  "sp_entity_id": "urn:example:sp",
  "sp_acs_url": "https://sp.example.com/saml/acs",
  "clock_skew_seconds": 60,
  "session_ttl_seconds": 28800,
  "replay_db_path": "replay_cache.sqlite3",
  "audit_log_path": "audit.log",
  "idps": {
    "corp-idp": {
      "entity_id": "urn:corp:idp",
      "sso_url": "https://idp.example.com/sso",
      "certificates": ["-----BEGIN CERTIFICATE-----\n...", "-----BEGIN CERTIFICATE-----\n..."],
      "attribute_mapping": {"uid": "uid", "mail": "email", "displayName": "display_name"},
      "required_attributes": ["uid"],
      "sensitive_attributes": ["email"]
    }
  }
}
```

| 配置项 | 默认 | 说明 |
| --- | --- | --- |
| `sp_entity_id` | `urn:example:sp` | 本服务的 SAML 实体 ID，用于受众校验 |
| `sp_acs_url` | `http://localhost:8000/saml/acs` | ACS 基础地址（AuthnRequest 中拼接 `/{idp_id}`） |
| `clock_skew_seconds` | `60` | 时间条件校验的时钟偏移容忍窗口 |
| `session_ttl_seconds` | `28800` | 本地会话有效期 |
| `replay_db_path` | `replay_cache.sqlite3` | 重放防护 SQLite 数据库路径 |
| `audit_log_path` | `audit.log` | 审计日志（JSONL）路径 |
| `idps.<id>.entity_id` | 必填 | IdP 实体 ID，用于 Issuer 校验 |
| `idps.<id>.sso_url` | `""` | IdP 单点登录地址（/login 重定向目标） |
| `idps.<id>.certificates` | `[]` | 受信任签名证书（PEM），**可配置多把以支持轮换** |
| `idps.<id>.attribute_mapping` | `{}` | 断言属性名 -> 本地属性名；映射外的属性被丢弃 |
| `idps.<id>.required_attributes` | `["uid"]` | 建立会话必需的本地属性，缺失拒绝（`missing_attribute`） |
| `idps.<id>.sensitive_attributes` | `["email"]` | 审计时需要脱敏的本地属性 |

### 密钥轮换流程

1. IdP 发布包含新证书的元数据；运维将新证书**追加**到 `certificates`。
2. 轮换窗口内新旧密钥签名的断言均可通过验证。
3. IdP 切换到新密钥签名后，从 `certificates` 中**移除**旧证书；
   此后旧密钥签名的断言以 `untrusted_key` 拒绝。

`metadata.parse_idp_metadata()` 可解析 IdP 元数据 XML 提取签名证书，
`metadata.KeyStore` 提供去重的增删接口，便于自动化轮换。

## 错误码

所有校验失败返回 HTTP 400（会话失效为 401），响应体包含可区分的 `error` 字段：

| 错误码 | 含义 |
| --- | --- |
| `unknown_idp` | 未配置的 IdP |
| `malformed_assertion` | XML 无法解析或结构不合法 |
| `unsigned_assertion` | 缺少签名 |
| `invalid_signature` | 签名无效或被篡改 |
| `untrusted_key` | 签名密钥不在信任列表 |
| `assertion_not_yet_valid` | NotBefore 超出容忍窗口 |
| `assertion_expired` | NotOnOrAfter 超出容忍窗口 |
| `audience_restriction` | 受众不包含本 SP |
| `issuer_mismatch` | 发行方与 IdP 配置不符 |
| `replay_detected` | 断言已被消费 |
| `missing_attribute` | 缺少必需属性 |
| `session_invalid` | 会话不存在、过期或已登出（401） |

## 运行与测试

```bash
uv sync
uv run uvicorn main:app --reload     # 启动服务
uv run pytest                        # 运行测试（48 项）
```

测试使用 `tests/helpers.py` 中本地生成的 IdP 与自签名证书完成端到端验证，
覆盖签名篡改、过期断言、重放、密钥轮换、属性缺失与登出等场景。
