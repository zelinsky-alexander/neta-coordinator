# NETA Full-Cycle Linux Acceptance

This is the manual, destructive integration/acceptance harness for a fresh NETA deployment. It is intentionally **never triggered by push, pull request, schedule, or release**. The only workflow trigger is `workflow_dispatch`.

The workflow provisions two temporary Ubuntu EC2 instances, installs a fresh coordinator/PostgreSQL/portal stack, creates an ephemeral two-day test PKI, installs a fresh Linux agent, enrolls it into the fleet, updates centrally managed rules, executes the Linux NETA Lab suite including two-host inbound scenarios, validates restart/reconnect behavior and a negative mTLS control, collects logs/results, and terminates the temporary EC2 resources in an `EXIT` trap.

## Manual selections

Every run chooses these independently:

- coordinator repository and branch/tag/commit;
- portal repository and branch/tag/commit;
- agent repository and branch/tag/commit;
- NETA Lab repository and branch/tag/commit;
- `all` Linux scenarios or a comma-separated scenario list;
- coordinator and agent EC2 instance types.

The selected agent ref must contain the exact-ref integration installer support (`NETA_SKIP_GIT_UPDATE`). If it does not, the harness fails rather than silently checking out `main`.

Windows-only Lab scenarios are reported as `NOT_APPLICABLE` by this Linux acceptance job. NETA-LAB-016 and NETA-LAB-017 are driven by the full-cycle orchestrator because their ground truth requires a second owned host.

## GitHub repository variables

Configure these repository variables in `neta-coordinator` before the first run:

- `NETA_AWS_REGION`, for example `eu-north-1`;
- `NETA_AWS_ROLE_ARN`, the IAM role assumed through GitHub OIDC;
- `NETA_AWS_VPC_ID`;
- `NETA_AWS_SUBNET_ID`, a public subnet with an Internet Gateway route;
- `NETA_AWS_AMI_ID`, an Ubuntu 24.04 x86-64 AMI whose default SSH user is `ubuntu`.

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

The role trust policy should restrict the subject to the repository that owns the workflow. A baseline trust condition is:

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
        "token.actions.githubusercontent.com:sub": "repo:zelinsky-alexander/neta-coordinator:*"
      }
    }
  }]
}
```

For a tighter production policy, restrict the GitHub subject further to the branch/environment from which this workflow is allowed to run.

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

1. fresh EC2 provisioning and SSH bootstrap;
2. coordinator and PostgreSQL fresh installation;
3. ephemeral Fleet CA, coordinator server certificate, agent-issuer certificate, trust store, and portal client certificate creation;
4. coordinator HTTPS/mTLS startup and health;
5. portal fresh installation, mTLS files, native-auth configuration and health endpoint;
6. exact selected agent checkout, eBPF-required build/tests and installation;
7. agent CSR enrollment, coordinator-issued identity certificate, `AgentHello` and heartbeat;
8. central rule-set download/validation/activation;
9. Linux NETA Lab command suite;
10. peer-driven inbound NETA-LAB-016 and concurrent inbound/outbound NETA-LAB-017;
11. agent restart and authenticated heartbeat;
12. coordinator restart and agent recovery;
13. unauthenticated message-ingestion rejection under mTLS;
14. post-test portal health and coordinator state collection;
15. logs, revision SHAs, Lab summaries, JUnit XML, JSON summary and `ACCEPTANCE.md` generation;
16. unconditional AWS resource cleanup.

The Lab `expected.yaml` files remain the scenario ground-truth specification. The current first integration harness treats scenario command completion plus the NETA system-level evidence/fleet checks as the automated gate; it does not invent semantic assertions when an `expected.yaml` field is not yet exposed by a stable machine-readable coordinator/agent query. Those expected files and runtime evidence should be used to extend scenario-specific assertions as the evidence query surface stabilizes.

## Output artifact

The workflow uploads `neta-full-cycle-report/` for 14 days. It contains at least:

```text
ACCEPTANCE.md
acceptance.json
junit.xml
environment.txt
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
- **OpenSSL** — Apache-2.0; ephemeral keys/certificates and PKCS#12 creation; actively maintained. Test private keys are short-lived and never uploaded as artifacts.
- **Docker Engine / Moby** — Apache-2.0; existing coordinator/portal deployment runtime; actively maintained. The EC2 hosts are disposable and should use current Ubuntu security updates.
- **Docker Compose v2** — Apache-2.0; existing deployment orchestration; actively maintained.
- **GitHub `actions/upload-artifact@v4`** — MIT; uploads the final acceptance directory; maintained by GitHub. It is CI-only, not linked into NETA binaries. Pinning to a reviewed commit SHA can further reduce action supply-chain risk before production use.

The implementation uses standard GitHub Actions OIDC and AWS STS `AssumeRoleWithWebIdentity` interfaces rather than copied third-party provisioning code. Before commercial/public release, normal dependency/license and similarity review should still be performed as part of the project's release process.
