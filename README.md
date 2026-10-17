# Policy-as-Code for Amazon Bedrock AgentCore

The same four security rules for `AWS::BedrockAgentCore::Runtime`, implemented in
four policy-as-code tools so you can compare approaches and pick what fits your
stack. AgentCore is recent enough that not every scanner models it yet, which
makes it a useful real-world test of how each tool handles a resource type it
doesn't natively understand.

For a head-to-head writeup of the tools (what works, what needs a workaround, and
a recommendation), see [`TOOL_COMPARISON.md`](TOOL_COMPARISON.md).

## The rules

Every implementation enforces the same four controls on an AgentCore Runtime:

1. **Inbound authorization** — `AuthorizerConfiguration` must be set, so incoming
   requests are authenticated.
2. **Network isolation** — `NetworkMode` must be `VPC` (not `PUBLIC`, and
   `NetworkConfiguration` must be present).
3. **Execution role** — `RoleArn` must be present and non-empty (an explicit
   least-privilege role).
4. **No plaintext secrets** — `EnvironmentVariables` must not contain secret-like
   keys (`*PASSWORD*`, `*API_KEY*`, `*TOKEN*`, `*SECRET*`, etc.). Use AgentCore
   Identity or a secrets store instead.

The example templates have one failing runtime and one compliant one:

| File | Contents |
|------|----------|
| `examples/agentcore-insecure.json` | One insecure + one secure runtime (JSON). |
| `examples/agentcore-insecure.yaml` | Same, in YAML. |
| `examples/agentcore-secure.yaml` | A compliant runtime only (passes every tool). |

## Project layout

| Path | Purpose |
|------|---------|
| `policies/agentcore_runtime.rego` | Trivy custom check, JSON selector. |
| `policies/agentcore_runtime_yaml.rego` | Trivy custom check, YAML selector. |
| `schemas/agentcore-template.json` | JSON schema for Trivy file matching / type-checking. |
| `checkov/*.py` | Checkov custom checks (one Python file per rule). |
| `cfn-guard/agentcore_runtime.guard` | cfn-guard rules (AWS DSL). |
| `conftest/policy/agentcore.rego` | Conftest / OPA Rego policy. |
| `examples/` | Insecure and secure example templates. |
| `tools/` | Pinned cfn-guard and conftest binaries used to verify the rules. |
| `TOOL_COMPARISON.md` | Side-by-side comparison and recommendation. |

## Running each tool

The commands below are PowerShell (Windows). On Linux/macOS, swap the backtick
line continuations for backslashes.

### cfn-guard

Reads the CloudFormation template structure directly — no special flags, works on
unmodeled resource types out of the box.

```powershell
cfn-guard validate --rules cfn-guard/agentcore_runtime.guard --data examples/agentcore-insecure.yaml
```

The insecure runtime fails all four rules; `examples/agentcore-secure.yaml` passes
(exit 0).

### Conftest (OPA)

Hands the raw parsed document to OPA Rego as `input`, with no normalization, so
`input.Resources` is available directly.

```powershell
conftest test examples/agentcore-insecure.yaml --policy conftest/policy
```

Expected: `6 tests, 1 passed, 5 failures` on the insecure file; `6 passed` on the
secure file.

### Trivy

Trivy needs a workaround for AgentCore — see the next section for why. Short
version: scan the template as raw JSON/YAML.

```powershell
trivy config examples/agentcore-insecure.json `
  --misconfig-scanners=json `
  --config-check policies/agentcore_runtime.rego `
  --config-file-schemas schemas/agentcore-template.json `
  --check-namespaces user
```

For the YAML template, use the YAML variant:

```powershell
trivy config examples/agentcore-insecure.yaml `
  --misconfig-scanners=yaml `
  --config-check policies/agentcore_runtime_yaml.rego `
  --check-namespaces user
```

### Checkov

Checkov parses CloudFormation natively and matches the custom Python checks on the
resource type directly.

```powershell
checkov -f examples/agentcore-insecure.yaml --framework cloudformation --external-checks-dir checkov
```

> **Environment note:** the Checkov custom checks are correct (verified against the
> registry directly), but on this machine the Checkov CLI did not register external
> checks — Checkov 3.3.27 running on the just-released Python 3.14, which it
> predates. They are expected to run normally on a supported interpreter
> (Python 3.11–3.12). See `TOOL_COMPARISON.md` for detail.

## Why Trivy needs a workaround

Trivy normalizes CloudFormation and Terraform into its own **cloud model**
(`input.aws.<service>`) before handing it to Rego. That model only contains
services Trivy ships a provider for (S3, IAM, RDS, etc.).

Bedrock AgentCore is **not in Trivy's cloud model**, so a normal cloud check can
never see an AgentCore resource — the scan always comes back clean. Verified on
Trivy 0.75.0: a check with `selector: type: cloud` only sees
`input.aws = {config, iam, rds}`; AgentCore is absent.

The fix is to scan the template as **raw JSON/YAML** instead of as CloudFormation.
That bypasses normalization and gives the Rego check the raw template body,
including `input.Resources` with the real AgentCore resources. The key flags:

- `--misconfig-scanners=json` (or `=yaml`): forces Trivy to treat the file as raw
  JSON/YAML rather than auto-detecting it as CloudFormation. **This is the flag
  that makes the check work.**
- `--config-check`: path to the Rego check file (or a directory of them).
- `--check-namespaces user`: the checks live under the `user.*` package; Trivy
  only evaluates custom namespaces when you name them here.
- `--config-file-schemas`: associates a schema for file matching and Rego
  type-checking. Required for generic JSON/YAML scanning to pick up matching files.

### Trivy expected result

The insecure runtime produces 5 findings; the secure runtime produces none:

```
agentcore-insecure.json (json)
Tests: 5 (SUCCESSES: 0, FAILURES: 5)
Failures: 5 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 5, CRITICAL: 0)

AGENTCORE-RUNTIME-0001 (HIGH): AgentCore Runtime 'InsecureAgentRuntime' has no AuthorizerConfiguration; ...
AGENTCORE-RUNTIME-0001 (HIGH): AgentCore Runtime 'InsecureAgentRuntime' has no RoleArn; ...
AGENTCORE-RUNTIME-0001 (HIGH): AgentCore Runtime 'InsecureAgentRuntime' sets a secret-like environment variable 'DB_PASSWORD'; ...
AGENTCORE-RUNTIME-0001 (HIGH): AgentCore Runtime 'InsecureAgentRuntime' sets a secret-like environment variable 'OPENAI_API_KEY'; ...
AGENTCORE-RUNTIME-0001 (HIGH): AgentCore Runtime 'InsecureAgentRuntime' uses NetworkMode 'PUBLIC'; ...
```

Trivy exits non-zero (code 1) when findings exist, which is what you want in CI.

### Trivy caveats

- **Two files, one check.** Trivy 0.75 does not route correctly when a single
  check declares more than one `selector` entry (`type: json` *and* `type: yaml`
  together causes the file to be skipped). So the JSON and YAML variants are
  shipped as separate files with distinct package names.
- **CloudFormation intrinsics.** Raw YAML scanning does not resolve `!Ref`,
  `!Sub`, `!GetAtt`, etc. If your template relies on them for the fields this
  check inspects (e.g. `RoleArn: !GetAtt Role.Arn`), prefer the JSON form, or be
  aware that an intrinsic value will not equal `""` and will pass the RoleArn
  check. Static values are evaluated exactly as written.

## Scope and extending

These checks target `AWS::BedrockAgentCore::Runtime` only. Other AgentCore resource
types (Memory, Gateway, BrowserCustom, etc.) are not covered yet; add new rules
following the same pattern — match on the resource `Type`, then inspect its
properties (PascalCase, matching the CloudFormation schema).

## Reference

- [AWS::BedrockAgentCore::Runtime CloudFormation reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrockagentcore-runtime.html)
- [Trivy custom checks](https://trivy.dev/docs/latest/tutorials/misconfiguration/custom-checks/)
- [Checkov custom policies](https://www.checkov.io/3.Custom%20Policies/Custom%20Policies%20Overview.html)
- [AWS CloudFormation Guard](https://docs.aws.amazon.com/cfn-guard/latest/ug/what-is-guard.html)
- [Conftest](https://www.conftest.dev/)

Content was rephrased for compliance with licensing restrictions.
