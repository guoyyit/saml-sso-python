"""断言属性到本地会话属性的映射。

每个 IdP 使用独立的映射规则；缺少必需属性时拒绝建立会话。
"""

from __future__ import annotations

from .config import IdpConfig
from .errors import MissingAttributeError


def map_attributes(idp: IdpConfig, assertion_attributes: dict[str, list[str]]) -> dict[str, str]:
    """按 IdP 配置把断言属性映射为本地属性。

    - 只保留映射表中声明的属性（IdP 之间隔离，未知属性不进入会话）
    - 多值属性取第一个值
    - 缺少必需属性或必需属性为空时抛出 MissingAttributeError
    """
    local: dict[str, str] = {}
    for remote_name, local_name in idp.attribute_mapping.items():
        values = assertion_attributes.get(remote_name)
        if values:
            local[local_name] = values[0]

    missing = [name for name in idp.required_attributes if not local.get(name)]
    if missing:
        raise MissingAttributeError(
            f"assertion from idp {idp.idp_id!r} missing required attributes: {missing!r}",
            detail={"idp_id": idp.idp_id, "missing": missing},
        )
    return local
