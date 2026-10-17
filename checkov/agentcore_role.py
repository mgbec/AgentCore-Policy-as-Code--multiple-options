from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


def _properties(conf):
    if isinstance(conf, dict) and isinstance(conf.get("Properties"), dict):
        return conf["Properties"]
    return conf if isinstance(conf, dict) else {}


class AgentCoreRuntimeRole(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="AgentCore Runtime must specify a non-empty RoleArn",
            id="CKV_AGENTCORE_3",
            categories=[CheckCategories.IAM],
            supported_resources=["AWS::BedrockAgentCore::Runtime"],
        )

    def scan_resource_conf(self, conf):
        props = _properties(conf)
        role = props.get("RoleArn")
        if isinstance(role, str) and role.strip():
            return CheckResult.PASSED
        return CheckResult.FAILED


check = AgentCoreRuntimeRole()
