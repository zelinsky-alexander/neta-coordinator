# C1/C2 Agent Build Reporting

This note records the coordinator-side wire contract implemented for C1/C2.

## Compatibility

Existing agents remain valid. Build reporting is optional and is accepted only on `AgentHello` and `Heartbeat` messages.

## Payload contract

A reporting agent adds an optional `build` object to the existing message payload:

```json
{
  "build": {
    "version": "1.4.0",
    "build_id": "20260905.1",
    "git_commit": "91ad71c31e",
    "os": "linux",
    "arch": "arm64",
    "artifact_sha256": "0123456789abcdef...",
    "protocol_version": 1,
    "schema_version": 7,
    "features": ["ebpf", "openssl"]
  }
}
```

When `build` is present, `version`, `build_id`, `os`, and `arch` are required. The remaining fields are optional. `artifact_sha256` accepts either 64 hexadecimal characters or `sha256:` followed by 64 hexadecimal characters; the coordinator stores the normalized lowercase digest without the prefix.

`features`, when present, must be a JSON array.

## Persistence

After the message has passed normal envelope, enrollment, certificate, and sequence validation, the coordinator updates the reporting agent row with the observed build identity and sets `build_reported_at`.

The stored values represent observed runtime state, not desired upgrade state.

Messages from existing agents without `payload.build` leave existing build-inventory columns unchanged.
