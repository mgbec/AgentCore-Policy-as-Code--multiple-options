from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


def _properties(conf):
    # Depending on the Checkov entry point, conf may be the full resource
    # (with a nested "Properties") or the Properties body itself.
    if isinstance(conf, dict) and isinstance(conf.get("Properties"), dict):
        return conf["Properties"]
    return conf if isinstance(conf, dict) else {}


class AgentCoreRuntimeAuthorizer(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="AgentCore Runtime must configure inbound authorization",
            id="CKV_AGENTCORE_1",
            categories=[CheckCategories.IAM],
            supported_resources=["AWS::BedrockAgentCore::Runtime"],
        )

    def scan_resource_conf(self, conf):
        props = _properties(conf)
        if props.get("AuthorizerConfiguration"):
            return CheckResult.PASSED
        return CheckResult.FAILED


check = AgentCoreRuntimeAuthorizer()
