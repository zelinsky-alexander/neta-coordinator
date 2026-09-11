# NETA Full-Cycle Linux Acceptance

This is the manual, destructive integration/acceptance harness for a fresh NETA deployment. It is intentionally **never triggered by push, pull request, schedule, or release**. The only workflow trigger is `workflow_dispatch`.

The workflow resolves the selected repositories to immutable commits, verifies that the selected agent commit already has the required immutable Linux package, provisions two temporary Ubuntu EC2 instances, installs a fresh coordinator/PostgreSQL/portal stack in Docker using the repository deployment path, creates an ephemeral two-day test PKI, installs the prebuilt Linux agent package, enrolls it into the fleet, updates centrally managed rules, executes the Linux NETA Lab suite including two-host inbound scenarios, validates restart/reconnect behavior and a negative mTLS control, collects logs/results, and terminates the temporary EC2 resources in an `EXIT` trap.

## Manual selections

Every run chooses these independently:

- coordinator repository and branch/tag/commit;
- portal repository and branch/tag/commit;
- agent repository and branch/tag/commit;
- NETA Lab repository and branch/tag/commit;
- `all` Linux scenarios or a comma-separated scenario list;
- coordinator and agent EC2 instance types.

The workflow defaults both EC2 hosts to `t3.small`, but these are editable workflow-dispatch inputs on every run. The coordinator host runs PostgreSQL, coordinator and portal; the endpoint host runs the packaged NETA agent and NETA Lab.

All four selected refs are resolved once on the GitHub runner and frozen to exact commit SHAs for that run. The selected agent commit must have the immutable development release `dev-<full-commit-sha>` produced by the agent `Build Supported Agent Flavors` workflow. Before any EC2 resources are created, the harness verifies `release-manifest.json`, the expected Linux package name for the AMI architecture, and package availability. The endpoint later downloads the same package and verifies its SHA-256 against the manifest before installation. **No C++ compilation or CMake test build occurs on the acceptance EC2 endpoint.**

If no package exists for the selected agent commit, acceptance fails during the preflight phase before creating the temporary security group or EC2 instances.

Windows-only Lab scenarios are reported as `NOT_APPLICABLE` by this Linux acceptance job. NETA-LAB-016, NETA-LAB-017, and the connected phase of NETA-LAB-018 are driven by the full-cycle orchestrator because their ground truth requires a second owned host. For NETA-LAB-018 the orchestrator preserves the required idle-listener interval before making the one controlled peer connection.

## GitHub repository variables

Configure these repository variables in `neta-coordinator` before the first run:

- `NETA_AWS_REGION`, for example `eu-central-1`;
- `NETA_AWS_ROLE_ARN`, the IAM role assumed through GitHub OIDC;
- `NETA_AWS_VPC_ID`;
- `NETA_AWS_SUBNET_ID`, a public subnet with an Internet Gateway route;
- `NETA_AWS_AMI_ID`, an Ubuntu 24.04 AMI whose default SSH user is `ubuntu` and whose architecture matches the chosen EC2 instance family.

No long-lived AWS access key, enrollment token, fleet CA key, coordinator private key, portal client key, or agent private key is stored in GitHub. Test secrets and PKI are generated per run and destroyed with the hosts.

## AWS OIDC provider and role

Create the AWS IAM OIDC provider for:

```text
https://token.actions.githubusercontent.com
```

with audience:

```text
sts.amazonaws.com
```

GitHub currently emits immutable owner/repository IDs in this repository's OIDC `sub` claim. The workflow prints only the non-secret OIDC identity claims (`iss`, `aud`, `sub`, `repository`, `ref`) before STS assumption so the trust policy can be checked without exposing the JWT.

For this repository, the working any-branch subject pattern is:

```text
repo:zelinsky-alexander@34163821/neta-coordinator@1351657477:*
```

A matching trust policy is:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:zelinsky-alexander@34163821/neta-coordinator@1351657477:*"
      }
    }
  }]
}
```

If GitHub changes the subject format, use the safe diagnostic claim printed by a manual run and update the trust condition to the exact repository identity rather than broadening it unnecessarily. For a tighter policy, restrict the subject further to the branch/environment from which the workflow is allowed to run.

The workflow currently requests a two-hour STS session. Set the IAM role maximum session duration to at least two hours, or reduce `--duration-seconds` in the workflow if the suite is known to complete within a shorter period.

## IAM permissions

The acceptance role needs only temporary EC2/network provisioning operations. No IAM mutation and no `iam:PassRole` are required. Start with these actions and narrow resources/conditions for your account/VPC:

```text
ec2:CreateSecurityGroup
ec2:DeleteSecurityGroup
ec2:AuthorizeSecurityGroupIngress
ec2:RunInstances
ec2:TerminateInstances
ec2:CreateTags
ec2:DescribeInstances
ec2:DescribeInstanceStatus
ec2:DescribeSecurityGroups
ec2:DescribeSubnets
ec2:DescribeVpcs
ec2:DescribeImages
```

The harness creates one temporary security group. SSH is allowed only from the current GitHub runner public IP. Coordinator port 8443 and controlled Lab ports 18000-18999 are allowed only between instances that carry that same temporary security group. Instance Metadata Service v2 is required on both EC2 instances.

## What the workflow verifies

The acceptance path covers:

1. exact ref resolution and immutable agent-package preflight before AWS provisioning;
2. fresh EC2 provisioning and SSH bootstrap;
3. coordinator and PostgreSQL fresh installation in Docker;
4. ephemeral Fleet CA, coordinator server certificate, agent-issuer certificate, Java trust store, and portal client certificate creation;
5. coordinator HTTPS/mTLS startup and health;
6. portal fresh Docker installation, mTLS files, native-auth configuration, production topology/security properties and health endpoint;
7. immutable package manifest/SHA-256 verification and runtime-only Linux agent installation;
8. agent CSR enrollment, coordinator-issued identity certificate, `AgentHello` and heartbeat;
9. central rule-set download/validation/activation;
10. Linux NETA Lab command suite;
11. peer-driven NETA-LAB-016, NETA-LAB-017, and NETA-LAB-018 connected phase;
12. agent restart and authenticated heartbeat;
13. coordinator restart, bounded health convergence and agent recovery;
14. application-layer client-certificate rejection using a structurally valid Heartbeat for the real enrolled agent but deliberately omitting the client certificate; acceptance requires the coordinator's `401 client certificate is required` response;
15. post-test portal health and coordinator state collection;
16. logs, frozen revision SHAs, production-parity evidence, Lab summaries, JUnit XML, JSON summary and `ACCEPTANCE.md` generation;
17. unconditional AWS resource cleanup.

The Lab `expected.yaml` files remain the scenario ground-truth specification. The current integration harness treats scenario command completion plus the NETA system-level evidence/fleet checks as the automated gate; it does not invent semantic assertions when an `expected.yaml` field is not yet exposed by a stable machine-readable coordinator/agent query. Those expected files and runtime evidence should be used to extend scenario-specific assertions as the evidence query surface stabilizes.

## Agent package prerequisite

For the agent repository/ref you intend to test:

1. open **Actions → Build Supported Agent Flavors** in that agent repository;
2. choose the branch/ref you want to acceptance-test;
3. run it with `publish_development=true` if that ref is not already published automatically;
4. wait for the immutable `dev-<commit-sha>` release to be published;
5. start the NETA full-cycle workflow and select the same agent repository/ref.

For pushes to `main`, the existing packaging workflow publishes the Linux development release automatically when its Linux package jobs are green.

## Output artifact

The workflow uploads `neta-full-cycle-report/` for 14 days. It contains at least:

```text
ACCEPTANCE.md
acceptance.json
junit.xml
environment.txt
production-parity.txt
coordinator-revisions.txt
agent-revisions.txt
lab/summary.tsv
lab/summary.json
lab/peer-summary.tsv
logs/
```

A failed test still attempts artifact upload, and the AWS cleanup trap still runs.

## Dependencies and licensing

The harness intentionally avoids Terraform, PyYAML and cloud SDK libraries. It uses command-line/runtime components already standard for this deployment path.

- **AWS CLI v2** — Apache-2.0; AWS EC2/STS API calls; actively maintained by AWS. Main security concern: IAM scope, so the acceptance role must remain narrowly permissioned.
- **OpenSSL** — Apache-2.0; ephemeral keys/certificates, package TLS runtime dependency and PKCS#12 creation; actively maintained. Test private keys are short-lived and never uploaded as artifacts.
- **Docker Engine / Moby** — Apache-2.0; existing coordinator/portal production-style deployment runtime; actively maintained. The EC2 hosts are disposable and should use current Ubuntu security updates.
- **Docker Compose v2** — Apache-2.0; existing deployment orchestration; actively maintained.
- **Python 3** — PSF License; standard-library-only controlled NETA Lab peer/server helpers on the disposable coordinator host. No Python package from PyPI is added by this harness.
- **GitHub `actions/upload-artifact` v4** — MIT; CI-only artifact upload. The workflow pins the reviewed immutable commit `ea165f8d65b6e75b540449e92b4886f43607fa02` rather than a moving tag.

The implementation uses standard GitHub Actions OIDC and AWS STS `AssumeRoleWithWebIdentity` interfaces rather than copied third-party provisioning code. Before commercial/public release, normal dependency/license and similarity review should still be performed as part of the project's release process.
