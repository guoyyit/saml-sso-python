"""断言属性到本地会话属性的映射。

每个 IdP 使用独立的映射规则；缺少必需属性时拒绝建立会话。
"""

from __future__ import annotations

from .config import IdpConfig


def map_attributes(idp: IdpConfig, assertion_attributes: dict[str, list[str]]) -> dict[str, str]:
    """按 IdP 配置把断言属性映射为本地属性。

    - 只保留映射表中声明的属性（IdP 之间隔离，未知属性不进入会话）
    - 多值属性取第一个值
    - 缺少必需属性时抛出 MissingAttributeError
    """
    raise NotImplementedError
