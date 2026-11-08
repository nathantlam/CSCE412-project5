# CSCE 412 Project 5

Nathan Lam · NetID: nathanlam

Website: https://csce412nathanlam.me

This project combines a five-page static website with four specialized AI agents. The agents interpret requirements, plan deployment, invoke constrained tools, verify AWS security, and diagnose a controlled failure. OpenAI supplies model reasoning and function selection; Python validates results, enforces approvals, and performs the actual network and AWS operations.

## Repository contents

- `cloud_agents/`: executable agents, orchestrator, model integration, and deployment/verification tools.
- `website/`: five interconnected HTML pages, custom error page, CSS, JavaScript, and an SVG illustration. These are the complete editable website source files.
- `infra/`: the project's scoped IAM policy, private S3 bucket policy, and OAC configuration.
- `tests/`: local unit tests for validation, approvals, tool restrictions, and recovery.
- `config.json`: non-secret resource identifiers for the deployed project.
- `.env.example`: environment-variable template without credentials.
- `requirements.txt`: direct dependencies; `requirements-lock.txt`: exact tested dependency versions.

The technical report, recording guide, screenshots, recorded execution evidence, virtual environment, and credentials are maintained separately. Running the program creates ignored local output and recovery-state folders.

## Architecture

Namecheap registers the domain. Route 53 resolves the custom domain to CloudFront, which serves the website over HTTPS and fetches objects from a private S3 REST origin using signed Origin Access Control requests. ACM in `us-east-1` supplies the viewer certificate. Website objects are stored in S3 in `us-east-2`.

CloudFront redirects HTTP to HTTPS. The bucket has all four Block Public Access settings enabled, and its policy allows reads only from the configured CloudFront distribution. CloudFront uses `index.html` as its default root and maps missing-resource errors to `404.html` with HTTP status 404.

The pages are Home, About, Architecture, Explore, and Verification. Shared navigation connects all five. The Explore page's JavaScript buttons update a request-flow explanation and accessible pressed state. The website requires no backend server.

## Agents and communication

1. **Requirements Analyst** (`cloud_agents/agents/requirements.py`) inspects local website files, decomposes the request, and identifies dependencies and task owners.
2. **Deployment Engineer** (`deployment.py`) reads the requirements handoff, inspects an upload/configuration plan, and can request the deployment tool in deploy mode.
3. **Security Verifier** (`security.py`) invokes public HTTP/TLS/DNS checks and authenticated AWS configuration inspection.
4. **Failure Diagnostician** (`diagnosis.py`) reads the prior handoffs, measured results, and controlled failure snapshot to propose a root cause and correction. It cannot change AWS resources.

`cloud_agents/__main__.py` orchestrates them sequentially. Each agent has separate instructions and an allowlist of executable tools. The orchestrator saves each validated JSON report, reads it back, and passes its structured content and artifact reference to the next agent. This is programmatic agent-to-agent exchange rather than manual copying between chats.

`model.py` calls OpenAI's Responses API. The model selects available function tools, receives tool observations, and produces a schema-constrained report. Outstanding required tools must run before finalization; deployment is exposed only after its plan tool succeeds. Python calculates the workflow pass flag from measured public and AWS results, independently of the model's prose.

## Installation

Use Python 3.10 or later. The tested environment used Python 3.13 on Windows. From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
Copy-Item .env.example .env
```

For dependency resolution rather than exact tested versions, install `requirements.txt` instead. Boto3's CRT dependency is included for browser-based AWS login support. Other dependencies are requests, python-dotenv, jsonschema, and dnspython. On macOS/Linux, use `.venv/bin/python` and `cp .env.example .env`.

Edit `.env` privately:

```dotenv
OPENAI_API_KEY=your_api_key
OPENAI_MODEL=gpt-4.1-mini
AWS_PROFILE=project5-agent
```

The API key needs usable API credit/quota and access to a model supporting Responses, function tools, and structured outputs. The default model is `gpt-4.1-mini`. LLM runs consume API usage; unit tests do not. Do not commit `.env` or include it in a recording.

Install AWS CLI v2 and sign in to the restricted project identity:

```powershell
aws login --profile project5-agent --region us-east-2
```

Complete IAM sign-in yourself in the browser. The IAM user needs the AWS-managed `SignInLocalDevelopmentAccess` policy plus the reviewed project permissions in `infra/iam-project-policy.json`. Creating the identity and attaching policies are human administrator steps. Temporary credentials expire; repeat login when necessary. The browser's normal console session alone does not authenticate Python.

The SDK uses the standard AWS credential chain. The configured profile must belong to the expected account; the application checks identity using STS and rejects root credentials and other AWS accounts. STS is used only for identity verification. The application cannot create IAM identities or credentials.

## Configuration and initial infrastructure

`config.json` contains the actual domain, bucket, region, distribution ID/domain, certificate ARN, Route 53 zone ID, validation CNAME, and required page names. Resource identifiers are not access credentials. To reproduce this in another account, review and replace all identifiers and matching IAM/bucket-policy scopes first. Do not grant access to another student's resources.

Initial provisioning is a documented human step; subsequent website deployment and verification are executable:

1. Register the approved custom domain at Namecheap.
2. Create a general-purpose S3 bucket with ACLs disabled and all public-access blocks enabled. Use the regional REST endpoint, not a public website endpoint.
3. Request an ACM certificate in `us-east-1`, publish its DNS validation CNAME, and wait for `Issued`.
4. Create a standard CloudFront distribution using the S3 origin and an OAC with `SigningBehavior=always` and `SigningProtocol=sigv4`. Apply the distribution-scoped bucket policy. The JSON files under `infra/` show these settings.
5. Attach the certificate and domain alias, set `index.html`, and enable HTTP redirection. Record the resulting identifiers in `config.json`.
6. Create the public Route 53 hosted zone manually. Set its ID in `config.json` and in the IAM policy. The runtime policy is scoped to this existing zone and does not grant zone creation.
7. Run DNS preparation to write the alias and certificate validation record. Copy any other required DNS records, review DNSSEC, and manually delegate all four Route 53 nameservers at Namecheap. Keep the certificate validation CNAME for renewal.
8. Run the approved deployment and verification commands below. Wait for CloudFront propagation before assessing the result.

## Running the system

```powershell
# Prerequisites, local file integrity, and a non-mutating deployment plan
.\.venv\Scripts\python.exe -m cloud_agents doctor
.\.venv\Scripts\python.exe -m cloud_agents site
.\.venv\Scripts\python.exe -m cloud_agents plan

# Public network checks; no LLM call or AWS credentials required
.\.venv\Scripts\python.exe -m cloud_agents verify

# Authenticated read-only configuration and deployment status
.\.venv\Scripts\python.exe -m cloud_agents inspect
.\.venv\Scripts\python.exe -m cloud_agents status

# All four real LLM agents, read-only audit
.\.venv\Scripts\python.exe -m cloud_agents workflow

# All four agents with an approved deployment operation
.\.venv\Scripts\python.exe -m cloud_agents workflow --mode deploy

# Deterministic deployment tool without a model call
.\.venv\Scripts\python.exe -m cloud_agents deploy

# DNS planning and approved record preparation in the configured hosted zone
.\.venv\Scripts\python.exe -m cloud_agents dns plan
.\.venv\Scripts\python.exe -m cloud_agents dns prepare
```

The deployment tool uploads a hash-checked inventory from `website/`, without deleting unrelated objects. It updates the configured distribution's root document, certificate, redirects, and custom error responses, then requests a cache invalidation. The exact plan must receive typed approval before mutations. It does not change bucket policies, IAM, or origin permissions. Wait for `status` to report `Deployed`, then verify again. AWS accepting a change does not establish propagation; a partially failed deployment must be inspected and checked again.

## Reproducing a representative agent workflow

1. Run `doctor` to check credential presence without printing secrets.
2. Run `workflow`. Watch actual `agent_started`, `model_response`, `tool_requested`, `tool_result`, `artifact_saved`, and `handoff` events.
3. Open the newly generated `outputs/<run-id>/` folder. Inspect `requirements.json`, `deployment.json`, `security.json`, and `diagnosis.json` to follow the structured handoffs.
4. Compare the agents' interpretations with `public_evidence.json` and `aws_evidence.json`. Inspect `workflow_summary.json`: an overall pass requires both measured sets to pass.
5. For deployment, use `workflow --mode deploy`, review its exact plan, and approve only the intended changes. Run another audit after propagation.

Each report contains a summary, findings, next steps, owner-assigned tasks, and limitations. Artifacts identify the configured model, input artifacts, and completed tool names. Model-response events include API token usage. `events.jsonl` records the local execution sequence, tool requests, observations, validation feedback, and approvals.

Exit codes are `0` for success, `2` for measured incomplete/failed checks, and `1` for an operation error, missing API key, or rejected approval. There is no simulated-agent demonstration mode; unit-test simulations are labelled and used only for tests.

## Controlled failure and recovery

```powershell
.\.venv\Scripts\python.exe -m cloud_agents verify
.\.venv\Scripts\python.exe -m cloud_agents failure break
# Review and approve. Wait for status Deployed and observe the homepage failure.
.\.venv\Scripts\python.exe -m cloud_agents status
.\.venv\Scripts\python.exe -m cloud_agents workflow

.\.venv\Scripts\python.exe -m cloud_agents failure restore
# Review and approve restoration. Wait for propagation, then verify recovery.
.\.venv\Scripts\python.exe -m cloud_agents status
.\.venv\Scripts\python.exe -m cloud_agents verify
.\.venv\Scripts\python.exe -m cloud_agents workflow
```

The experiment changes only CloudFront's default root to a confirmed absent filename. The original field is saved in ignored `.state/` before mutation. The homepage should fail while explicit `/index.html` still works; the Security and Diagnosis agents use measured results and that snapshot to identify the cause. Recovery uses a fresh ETag and restores only the original field, preserving unrelated settings. An unexpected concurrent root change is refused. The restore command does not depend on the LLM API, and both changes require separate approval gates. Preserve recovery state until restoration is verified.

This deployment has completed the actual 200 -> 404 -> 200 experiment and a final passing four-agent recovery audit. Recorded evidence is submitted separately. Re-running the commands creates new observations; old results are never substituted for a fresh execution.

## Tests and execution boundaries

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The 17 local tests cover website links, tool allowlists, schema validation, required-tool sequencing, denial-by-default approval, redaction, account/root rejection, exact OAC policy matching, and safe recovery. They use simulated responses solely to test control flow, not to claim live model or AWS success.

Tools accept no model-controlled arguments: targets come from validated local configuration. The model cannot execute arbitrary code or shell commands. Tool loops are bounded and each tool can run once per agent invocation. The orchestrator returns observations to the model and rejects invalid reports. Public checks validate TLS, navigation/assets, HTTP redirection, CloudFront delivery, DNS delegation, custom errors, and anonymous S3 denial. Authenticated inspection checks the underlying AWS settings. Visual responsiveness and JavaScript interaction also require browser demonstration.

Credentials, `.venv/`, `outputs/`, `.state/`, caches, logs, reports, and recordings are ignored. Logs redact configured credentials and common key formats, but generated evidence should still be reviewed before sharing. Keep the website available until grading completes. Use a private repository and give the designated teaching staff access.

## References and AI disclosure

- [OpenAI function calling](https://developers.openai.com/api/docs/guides/function-calling)
- [AWS private S3 origins and OAC](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html)
- [CloudFront certificate requirements](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html)
- [Route 53 DNS migration](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/MigratingDNS.html)
- [AWS CLI browser-based login](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html)

Codex assisted with website source, agent code, configuration, tests, and documentation. The running agents use the configured OpenAI API model for interpretation and tool selection. Python and AWS perform the actual measurements and operations. The student is responsible for reviewing, understanding, and demonstrating the implementation.
