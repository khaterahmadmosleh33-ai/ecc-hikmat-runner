# ECC private runner gateway

An authenticated single-owner command runner for a dedicated Render Free Web Service.
No API keys, login tokens, user files, or account details belong in this repository.

Current status: source prepared; not deployed or connected. Local syntax checks pass.
The development container maps only UID 0, so privilege-separation integration tests
must run in the Docker build before deployment can succeed. Live execution is unverified.

Set `ECC_RUNNER_SECRET` to a random secret of at least 40 characters at runtime.
Deploy this directory as a Docker web service, plan `free`, with `/health` as its health endpoint.
The companion owner-private ChatGPT Site authenticates the user and stores results and text files.

Commands run as UID 10001 with a clean environment, no new privileges, bounded CPU, address space,
process count, file size, elapsed time and output. The HTTP coordinator retains the runtime secret.
Set `ECC_GUEST_UID` to a dedicated non-root UID in 10000–65533 on shared hosts;
the default 10001 is intended for isolated builds. This avoids host-wide per-UID
process-count contention while retaining the process limit.
Execution is limited to one operation at a time. Only run code trusted by the account owner: this
shared Linux container is **not** a VM sandbox and outbound network access is enabled.

Sessions last 30 minutes. Files and the runner ledger are ephemeral: Render may sleep or restart
the service, and the caller must preserve useful inputs and results in durable storage.
Health checks are public and side effect free. Every command and file endpoint requires a secret.
The service does not include a Codex subscription, account login, or ECC lifecycle-hook installation.

MIT License. Copyright (c) 2026 ECC for Hikmat contributors.
