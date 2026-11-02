# ECC private runner gateway

An authenticated single-owner command runner for a dedicated Render Free Web Service.
No API keys, login tokens, user files, or account details belong in this repository.

The Docker build runs real integration tests for Node/Python execution, secret
separation, no-new-privileges, file safety, HTTP authentication, stable request IDs,
process cleanup, output truncation, optional timeouts, concurrent status/cancellation and session cleanup. Local syntax
checks alone do not establish runtime compatibility. A development environment
that maps only UID 0 skips those tests; use the Docker build to execute them.

Set `ECC_RUNNER_SECRET` to a random secret of at least 40 characters at runtime.
Deploy this directory as a Docker web service, plan `free`, with `/health` as its health endpoint.
The companion owner-private ChatGPT Site authenticates the user and stores results and text files.

Commands run as the configured non-root UID (default 10001) with a clean environment, no new privileges, bounded address space, process count, individual file size and retained output. The HTTP coordinator retains the runtime secret.
Set `ECC_GUEST_UID` to a dedicated non-root UID in 10000–65533 on shared hosts;
the default 10001 is intended for isolated builds. This avoids host-wide per-UID
process-count contention while retaining the process limit.
One job runs at a time; status and cancellation remain available concurrently. Only run code trusted by the account owner: this
shared Linux container is **not** a VM sandbox and outbound network access is enabled.

Commands are asynchronous: `/v1/exec` returns `job_id` immediately; `/v1/job` or `/v1/result` polls it and `/v1/cancel` requests cancellation without deleting the workspace. `/v1/stop` cancels any active job and closes the workspace. Sessions have no fixed expiry and commands have no default deadline. Optional `timeout_seconds` sets a user-chosen deadline. Output retains a bounded tail; reaching its cap does not kill a job. Files and the runner ledger are ephemeral: Render may sleep or restart
the service, and the caller must preserve useful inputs and results in durable storage.
Health checks are public and side effect free. Every command and file endpoint requires a secret.
The service does not include a Codex subscription, account login, or ECC lifecycle-hook installation.

MIT License. Copyright (c) 2026 ECC for Hikmat contributors.
