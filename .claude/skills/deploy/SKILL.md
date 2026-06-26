---
name: deploy
description: Deploy so-ops to a remote host via SSH using scripts/deploy.sh. Use when the user wants to push code changes to their Security Onion companion VM.
disable-model-invocation: true
---

Deploy so-ops to the remote host specified by the user: `$ARGUMENTS`

## Steps

1. Confirm the SSH target. If `$ARGUMENTS` is empty, ask the user for: `user@host` and optionally a ProxyJump host.

2. Check local state before deploying:
   - Run `git status` to confirm there are no uncommitted changes the user may want to include.
   - Run `ruff check src/` and report any errors. Warn the user if lint fails but do not block.

3. Run the deploy script:
   ```bash
   bash scripts/deploy.sh <user@host> [--proxy <jump-host>]
   ```
   The script auto-detects Windows (Git Bash) vs Linux and uses tar+ssh or rsync accordingly.

4. The script will:
   - Rsync (Linux) or tar+ssh (Windows) the repo to the remote
   - Run `pip install -e .` on the remote
   - Install systemd units from `systemd/` with sudo and reload the daemon
   - Restart affected services

5. After deploy, verify the remote installation:
   ```bash
   ssh <user@host> "so-ops status"
   ```

6. Report success or any errors from the remote output.

## Common issues

- **Line ending errors on remote**: The deploy script calls `dos2unix` on scripts. If it fails, the user needs `dos2unix` installed on the remote.
- **systemd permission errors**: The remote user needs passwordless sudo for `systemctl` commands, or the user will be prompted for a password.
- **Ollama not running**: If triage/health fails after deploy, check `ssh <host> "systemctl status ollama"`.
