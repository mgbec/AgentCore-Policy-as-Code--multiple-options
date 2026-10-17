# METADATA
# title: Bedrock AgentCore Runtime security checks
# description: >-
#   Custom Trivy checks for AWS::BedrockAgentCore::Runtime CloudFormation
#   resources. Trivy has no built-in provider model for Bedrock AgentCore,
#   so this check runs against the raw template body (scan with
#   --misconfig-scanners=json). It enforces inbound authentication, VPC
#   network isolation, a non-empty execution role, and the absence of
#   plaintext secrets in environment variables.
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
#       - type: json
package user.aws.bedrockagentcore.runtime

resource_type := "AWS::BedrockAgentCore::Runtime"

# Keys that strongly suggest a plaintext secret in EnvironmentVariables.
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

# Iterate over every AgentCore Runtime resource in the template.
is_runtime(res) {
	res.Type == resource_type
}

looks_like_secret(key) {
	lower_key := lower(key)
	some i
	contains(lower_key, secret_key_patterns[i])
}

# ---------------------------------------------------------------------------
# Rule 1: Inbound authorization must be configured.
# ---------------------------------------------------------------------------
deny[res] {
	some name
	runtime := input.Resources[name]
	is_runtime(runtime)
	not runtime.Properties.AuthorizerConfiguration
	msg := sprintf("AgentCore Runtime '%s' has no AuthorizerConfiguration; incoming requests are not authenticated.", [name])
	res := result.new(msg, runtime)
}

# ---------------------------------------------------------------------------
# Rule 2: Runtime should run in a VPC, not with public networking.
# ---------------------------------------------------------------------------
deny[res] {
	some name
	runtime := input.Resources[name]
	is_runtime(runtime)
	runtime.Properties.NetworkConfiguration.NetworkMode != "VPC"
	msg := sprintf("AgentCore Runtime '%s' uses NetworkMode '%s'; use 'VPC' for network isolation.", [name, runtime.Properties.NetworkConfiguration.NetworkMode])
	res := result.new(msg, runtime)
}

# Flag when NetworkConfiguration is entirely absent.
deny[res] {
	some name
	runtime := input.Resources[name]
	is_runtime(runtime)
	not runtime.Properties.NetworkConfiguration
	msg := sprintf("AgentCore Runtime '%s' has no NetworkConfiguration; default networking may be public.", [name])
	res := result.new(msg, runtime)
}

# ---------------------------------------------------------------------------
# Rule 3: An execution role (RoleArn) must be provided and non-empty.
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Rule 4: No plaintext secrets in EnvironmentVariables.
# ---------------------------------------------------------------------------
deny[res] {
	some name, key
	runtime := input.Resources[name]
	is_runtime(runtime)
	runtime.Properties.EnvironmentVariables[key]
	looks_like_secret(key)
	msg := sprintf("AgentCore Runtime '%s' sets a secret-like environment variable '%s'; use AgentCore Identity or a secrets store instead.", [name, key])
	res := result.new(msg, runtime)
}
