# Conftest policy for AWS::BedrockAgentCore::Runtime
#
# Run with:
#   conftest test examples/agentcore-insecure.yaml --policy conftest/policy
#
# Conftest parses the file (YAML/JSON) and hands the raw document to Rego as
# `input`, with no cloud-model normalization. So input.Resources is available
# directly, and unmodeled resource types like AgentCore are fully visible.
package main

import rego.v1

resource_type := "AWS::BedrockAgentCore::Runtime"

secret_key_patterns := [
	"password", "passwd", "secret", "api_key", "apikey",
	"access_key", "secret_key", "token", "private_key", "credential",
]

runtimes[name] := res if {
	some name, res in input.Resources
	res.Type == resource_type
}

looks_like_secret(key) if {
	lower_key := lower(key)
	some pat in secret_key_patterns
	contains(lower_key, pat)
}

# Rule 1: inbound authorization must be configured.
deny contains msg if {
	some name, res in runtimes
	not res.Properties.AuthorizerConfiguration
	msg := sprintf("[CKV_AGENTCORE_1] AgentCore Runtime '%s' has no AuthorizerConfiguration; incoming requests are not authenticated.", [name])
}

# Rule 2: runtime must use VPC network isolation.
deny contains msg if {
	some name, res in runtimes
	res.Properties.NetworkConfiguration.NetworkMode != "VPC"
	msg := sprintf("[CKV_AGENTCORE_2] AgentCore Runtime '%s' uses NetworkMode '%s'; use 'VPC'.", [name, res.Properties.NetworkConfiguration.NetworkMode])
}

deny contains msg if {
	some name, res in runtimes
	not res.Properties.NetworkConfiguration
	msg := sprintf("[CKV_AGENTCORE_2] AgentCore Runtime '%s' has no NetworkConfiguration.", [name])
}

# Rule 3: an execution role (RoleArn) must be provided and non-empty.
deny contains msg if {
	some name, res in runtimes
	not res.Properties.RoleArn
	msg := sprintf("[CKV_AGENTCORE_3] AgentCore Runtime '%s' has no RoleArn.", [name])
}

deny contains msg if {
	some name, res in runtimes
	res.Properties.RoleArn == ""
	msg := sprintf("[CKV_AGENTCORE_3] AgentCore Runtime '%s' has an empty RoleArn.", [name])
}

# Rule 4: no plaintext secrets in EnvironmentVariables.
deny contains msg if {
	some name, res in runtimes
	some key, _ in res.Properties.EnvironmentVariables
	looks_like_secret(key)
	msg := sprintf("[CKV_AGENTCORE_4] AgentCore Runtime '%s' sets a secret-like environment variable '%s'.", [name, key])
}
