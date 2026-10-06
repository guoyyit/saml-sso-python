# SAML SSO Python

基于 SAML 2.0 的联邦身份接入服务：外部身份提供方（IdP）通过 POST 绑定
发送签名断言，本服务（SP）验签后建立可独立管理的本地会话。

## 信任模型

```
┌─────────┐   1. 重定向登录    ┌──────────┐
│  浏览器  │ ───────────────▶ │   IdP    │
│         │ ◀─────────────── │          │
└────┬────┘   2. POST 签名断言 └────┬─────┘
     │                             │ 3. 元数据/证书（带外预置）
     ▼                             ▼
┌─────────────────────────────────────────┐
│  SP（本服务）                            │
│  · 验签：只信任本地配置的 IdP 证书        │
│  · 校验：时间窗 / 受众 / 重放             │
│  · 映射：IdP 属性 → 本地会话属性          │
└─────────────────────────────────────────┘
```

核心原则：

- **静态信任锚**：SP 不在线获取 IdP 密钥。受信任的签名证书通过元数据
  文件或证书文件在部署时预置，断言 KeyInfo 中内嵌的证书必须与本地
  信任集合中的某一份完全一致，否则按 `untrusted_key` 拒绝。
- **密钥轮换**：`IdpConfig.certificates` 接受多份证书。轮换时先并置
  新旧密钥（两者均可验签），待 IdP 切换完成后再移除旧密钥。
- **验签后才解析**：断言数据只从验签通过的已签名元素中提取，抵御
  签名包装（XSW）攻击；仅允许 SHA-2 系列签名与摘要算法。
- **重放防护**：断言 ID 在有效期内只能消费一次，记录持久化在 SQLite
  中，进程重启不丢失；主键约束保证并发消费只有一个成功。
- **会话隔离**：会话记录所属 IdP 的 entityID；属性映射按 IdP 独立
  配置，不同 IdP 的同名 SAML 属性可映射到不同本地字段。
- **审计脱敏**：审计日志只记录映射后的会话属性，且配置为敏感的字段
  一律以 `***` 代替；原始断言 XML 不进入审计日志。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/saml/acs` | 断言消费服务（ACS），表单字段 `SAMLResponse` |
| POST | `/saml/slo` | 单点登出，表单字段 `SAMLRequest`（须签名） |
| GET  | `/me` | 查询当前会话（Cookie `saml_session`） |
| POST | `/logout` | 本地登出，会话立即失效 |
| POST | `/protected/write` | 示例受保护写接口 |

### 错误响应

所有拒绝都返回 `{"error": <code>, "detail": <message>}`，`error` 为
机器可读原因：

| error | HTTP | 含义 |
| --- | --- | --- |
| `signature_missing` | 403 | 断言未携带签名 |
| `signature_invalid` | 403 | 签名无效或被篡改 |
| `untrusted_key` | 403 | 签名密钥不在信任集合中 |
| `assertion_expired` | 403 | 超过 NotOnOrAfter（含容忍窗口） |
| `assertion_not_yet_valid` | 403 | 未到 NotBefore（含容忍窗口） |
| `audience_mismatch` | 403 | 受众限制不包含本服务 |
| `replay_detected` | 409 | 断言 ID 已被消费 |
| `missing_attribute` | 422 | 缺少必需属性 |
| `unknown_idp` | 403 | 签发方不是已配置的 IdP |
| `not_authenticated` | 401 | 无有效本地会话 |

## 配置项

通过环境变量配置（见 `main.py`）：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `SP_ENTITY_ID` | `http://localhost:8000` | 本服务 entityID（受众校验依据） |
| `SP_ACS_URL` | `http://localhost:8000/saml/acs` | ACS 地址 |
| `SAML_IDP_ENTITY_ID` | （必填） | IdP 的 entityID |
| `SAML_IDP_METADATA_FILE` | – | IdP 元数据 XML 路径，自动提取签名证书 |
| `SAML_IDP_CERT_FILE` | – | 无元数据时单独的签名证书 PEM |
| `SAML_REQUIRED_ATTRS` | `uid=uid` | 必需属性映射 `SAML名=本地名,...` |
| `SAML_OPTIONAL_ATTRS` | 空 | 可选属性映射，格式同上 |
| `SAML_SENSITIVE_FIELDS` | 空 | 审计脱敏的本地字段，逗号分隔 |
| `SAML_CLOCK_SKEW` | `60` | 时钟偏移容忍窗口（秒） |
| `SAML_SESSION_TTL` | `3600` | 本地会话有效期（秒） |
| `SAML_DB_PATH` | `saml_sso.db` | SQLite 路径（重放缓存 + 会话） |
| `SAML_AUDIT_LOG` | `saml_audit.log` | 审计日志路径（JSON Lines） |

多 IdP 场景请以编程方式构造 `Settings(idps=(...))`，每个 `IdpConfig`
拥有独立的证书集合、属性映射与脱敏字段。

## 运行与测试

```bash
uv sync
uv run pytest                 # 44 项测试：签名篡改/过期/重放/轮换/属性/登出/审计/端到端
SAML_IDP_ENTITY_ID=... SAML_IDP_METADATA_FILE=idp-metadata.xml \
    uv run uvicorn main:app
```

测试使用 `tests/idp.py` 中的本地 IdP 模拟器：运行时生成 RSA 密钥对与
自签名证书，可签发/篡改断言与登出请求，无需任何外部依赖。
