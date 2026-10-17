from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck

SECRET_KEY_PATTERNS = [
    "password", "passwd", "secret", "api_key", "apikey",
    "access_key", "secret_key", "token", "private_key", "credential",
]

# Keys Checkov injects into the parsed config that are not real properties.
META_KEYS = {"__file__", "__startline__", "__endline__", "resource_type"}


def _properties(conf):
    if isinstance(conf, dict) and isinstance(conf.get("Properties"), dict):
        return conf["Properties"]
    return conf if isinstance(conf, dict) else {}


class AgentCoreRuntimeEnvSecrets(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="AgentCore Runtime must not set secret-like plaintext env vars",
            id="CKV_AGENTCORE_4",
            categories=[CheckCategories.SECRETS],
            supported_resources=["AWS::BedrockAgentCore::Runtime"],
        )

    def scan_resource_conf(self, conf):
        props = _properties(conf)
        env = props.get("EnvironmentVariables")
        if not isinstance(env, dict):
            return CheckResult.PASSED
        for key in env.keys():
            if key in META_KEYS:
                continue
            lower_key = str(key).lower()
            if any(pat in lower_key for pat in SECRET_KEY_PATTERNS):
                return CheckResult.FAILED
        return CheckResult.PASSED


check = AgentCoreRuntimeEnvSecrets()
