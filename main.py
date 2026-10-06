"""服务入口：加载配置并创建应用。"""

import os

from saml_sso.app import create_app
from saml_sso.config import Settings, load_settings

_config_path = os.environ.get("SAML_SSO_CONFIG")
settings = load_settings(_config_path) if _config_path else Settings()

app = create_app(settings)
