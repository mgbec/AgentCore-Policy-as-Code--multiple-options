# METADATA
# title: Bedrock AgentCore Runtime security checks (YAML)
# description: >-
#   YAML-selector twin of agentcore_runtime.rego. Identical rules, but applies
#   to CloudFormation templates scanned as raw YAML (--misconfig-scanners=yaml).
#   Trivy does not accept more than one selector entry per check in this
#   version, so JSON and YAML variants are shipped separately. Note: raw YAML
#   scanning does not resolve CloudFormation intrinsics (!Ref, !Sub, etc.); for
#   templates that use them, prefer the JSON template + agentcore_runtime.rego.
# custom:
#   id: AGENTCORE-RUNTIME-0001
#   avd_id: AVD-AGENTCORE-0001
#   provider: aws
#   service: bedrock-agentcore
#   severity: HIGH
#   short_code: runtime-security
#   recommended_action: >-
#     Configure AuthorizerConfiguration, set NetworkMode to VPC, provide a
#     RoleArn, and remove plaintext secrets from EnvironmentVariables.
#   input:
#     selector:
#       - type: yaml
package user.aws.bedrockagentcore.runtime_yaml

resource_type := "AWS::BedrockAgentCore::Runtime"

secret_key_patterns := [
	"password",
	"passwd",
	"secret",
	"api_key",
	"apikey",
	"access_key",
	"secret_key",
	"token",
	"private_key",
	"credential",
]

is_runtime(res) {
	res.Type == resource_type
}

looks_like_secret(key) {
	lower_key := lower(key)
	some i
	contains(lower_key, secret_key_patterns[i])
}

# Rule 1: Inbound authorization must be configured.
deny[res] {
	some name
	runtime := input.Resources[name]
	is_runtime(runtime)
	not runtime.Properties.AuthorizerConfiguration
	msg := sprintf("AgentCore Runtime '%s' has no AuthorizerConfiguration; incoming requests are not authenticated.", [name])
	res := result.new(msg, runtime)
}

# Rule 2: Runtime should run in a VPC, not with public networking.
deny[res] {
	some name
	runtime := input.Resources[name]
	is_runtime(runtime)
	runtime.Properties.NetworkConfiguration.NetworkMode != "VPC"
	msg := sprintf("AgentCore Runtime '%s' uses NetworkMode '%s'; use 'VPC' for network isolation.", [name, runtime.Properties.NetworkConfiguration.NetworkMode])
	res := result.new(msg, runtime)
}

deny[res] {
	some name
	runtime := input.Resources[name]
	is_runtime(runtime)
	not runtime.Properties.NetworkConfiguration
	msg := sprintf("AgentCore Runtime '%s' has no NetworkConfiguration; default networking may be public.", [name])
	res := result.new(msg, runtime)
}

# Rule 3: An execution role (RoleArn) must be provided and non-empty.
deny[res] {
	some name
	runtime := input.Resources[name]
	is_runtime(runtime)
	not runtime.Properties.RoleArn
	msg := sprintf("AgentCore Runtime '%s' has no RoleArn; an explicit least-privilege execution role is required.", [name])
	res := result.new(msg, runtime)
}

deny[res] {
	some name
	runtime := input.Resources[name]
	is_runtime(runtime)
	runtime.Properties.RoleArn == ""
	msg := sprintf("AgentCore Runtime '%s' has an empty RoleArn.", [name])
	res := result.new(msg, runtime)
}

# Rule 4: No plaintext secrets in EnvironmentVariables.
deny[res] {
	some name, key
	runtime := input.Resources[name]
	is_runtime(runtime)
	runtime.Properties.EnvironmentVariables[key]
	looks_like_secret(key)
	msg := sprintf("AgentCore Runtime '%s' sets a secret-like environment variable '%s'; use AgentCore Identity or a secrets store instead.", [name, key])
	res := result.new(msg, runtime)
}
