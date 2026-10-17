from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


def _properties(conf):
    if isinstance(conf, dict) and isinstance(conf.get("Properties"), dict):
        return conf["Properties"]
    return conf if isinstance(conf, dict) else {}


class AgentCoreRuntimeNetworkVpc(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="AgentCore Runtime must use VPC network isolation",
            id="CKV_AGENTCORE_2",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["AWS::BedrockAgentCore::Runtime"],
        )

    def scan_resource_conf(self, conf):
        props = _properties(conf)
        net = props.get("NetworkConfiguration")
        if not isinstance(net, dict):
            return CheckResult.FAILED
        if net.get("NetworkMode") == "VPC":
            return CheckResult.PASSED
        return CheckResult.FAILED


check = AgentCoreRuntimeNetworkVpc()
