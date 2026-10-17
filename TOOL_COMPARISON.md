# AgentCore policy-as-code: tool comparison

The same four security rules for `AWS::BedrockAgentCore::Runtime` implemented
in four tools, so you can see which fits best. Rules:

1. `AuthorizerConfiguration` must be set (authenticated inbound).
2. `NetworkMode` must be `VPC`.
3. `RoleArn` must be present and non-empty.
4. No secret-like keys in `EnvironmentVariables`.

All examples live in `examples/`. The insecure template has one failing runtime
and one compliant one; `agentcore-secure.yaml` is compliant only.

## Results on this machine (verified)

| Tool | Reads AgentCore natively? | Special flags needed | Verified here |
|------|---------------------------|----------------------|---------------|
| **cfn-guard** | Yes | none | ✅ 4 rules FAIL on insecure, PASS on secure |
| **Conftest (OPA)** | Yes | none | ✅ 5 findings on insecure, 6/6 pass on secure |
| **Trivy** | No (needs raw-scan workaround) | `--misconfig-scanners=json` | ✅ works, see main `README.md` |
| **Checkov** | Yes (by design) | `--external-checks-dir` | ⚠️ logic verified, CLI blocked by env (see below) |

### Why Trivy needs a workaround

Trivy normalizes CloudFormation/Terraform into its built-in cloud model
(`input.aws.<service>`), which only contains services it ships a provider for.
AgentCore is not in that model, so a normal check sees nothing. You have to scan
the template as raw JSON/YAML to reach the resource. Full detail in `README.md`.

### cfn-guard — cleanest for CloudFormation-only

```powershell
cfn-guard validate --rules cfn-guard/agentcore_runtime.guard --data examples/agentcore-insecure.yaml
```

Reads the template structure directly. New/unmodeled resource types just work.
Output includes line numbers and the exact failing property. AWS-native, single
binary, no runtime dependency. Downside: its own DSL (not Rego), can't do
Terraform, and can't pattern-match arbitrary map keys — so the secret-key rule
enumerates known names explicitly rather than scanning every key.

### Conftest — cleanest if you want pure Rego

```powershell
conftest test examples/agentcore-insecure.yaml --policy conftest/policy
```

Hands the raw parsed document to OPA Rego as `input`, with no normalization, so
`input.Resources` is available directly and the secret-key loop works exactly
like you'd want. This is essentially what we had to force Trivy into, but native.
Downside: it is a policy engine only — no bundled CVE/secret scanning, no
built-in AWS checks. You bring all the rules.

### Checkov — most feature-rich, but blocked in this environment

```powershell
checkov -f examples/agentcore-insecure.yaml --framework cloudformation --external-checks-dir checkov
```

Checkov parses CloudFormation natively (including intrinsics) and matches custom
Python checks on the resource type directly — no raw-scan trick. The four checks
in `checkov/` are correct: a direct registry test produced
FAIL/FAIL/FAIL/FAIL on the insecure runtime and PASS on the secure one.

However, on **this machine** the Checkov CLI does not register the external
checks (they do not appear in `checkov --list` and never execute). The cause is
the environment: Checkov 3.3.27 running on the just-released **Python 3.14**,
whose dependency stack Checkov predates. The policies are expected to run
normally on a supported interpreter (Python 3.11–3.12). Treat the Checkov files
as ready-to-use once run on a supported Python.

## Recommendation

- **CloudFormation only, want it to just work** → cfn-guard.
- **Want Rego and only need the policy engine** → Conftest.
- **Already standardized on Trivy for vuln/secret scanning** → keep the Trivy
  policy in `README.md`; it works with the documented flag.
- **Want a full IaC security scanner with native custom policy** → Checkov, on a
  supported Python version.

Content was rephrased for compliance with licensing restrictions.
