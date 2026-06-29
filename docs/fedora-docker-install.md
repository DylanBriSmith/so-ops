# Fedora Docker Install Guide

This guide installs so-ops on a minimal Fedora VM using Docker + systemd timers. The timers call `docker compose run` on a schedule — no cron daemon needed, and all output goes to journald.

## What runs and when

| Timer | Schedule | Command |
|-------|----------|---------|
| `so-triage.timer` | Every 15 minutes | `so-ops triage` |
| `so-health.timer` | Daily at 7:10 AM EST | `so-ops health` |
| `so-vulnscan-nmap.timer` | Sundays at 2:00 AM EST | `so-ops scan --type nmap` |
| `so-vulnscan-nuclei.timer` | Wednesdays at 2:00 AM EST | `so-ops scan --type nuclei` |

## Prerequisites

- Fedora (minimal install is fine)
- Network access to your Security Onion manager on port 9200
- A firewall rule on the SO manager allowing this machine: `sudo so-firewall includehost elasticsearch_rest <this-vm-ip> && sudo so-firewall apply`

## 1. Install Docker

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
```

Verify:
```bash
docker --version
docker compose version
```

## 2. Clone the repo

```bash
sudo git clone https://github.com/benolenick/so-ops.git /opt/so-ops
cd /opt/so-ops
```

## 3. Create config.toml

```bash
sudo cp config.example.toml config.toml
sudo nano config.toml
```

At minimum, fill in:
- `[elasticsearch]` — host, user (leave password blank, use `.env` instead)
- `llm_provider` — `"openrouter"` or `"ollama"`
- `[openrouter]` or `[ollama]` section

## 4. Create .env for secrets

```bash
sudo nano /opt/so-ops/.env
```

```ini
SO_OPS_ES_PASSWORD=your_elasticsearch_password
SO_OPS_OR_API_KEY=sk-or-v1-your_openrouter_key
```

```bash
sudo chmod 600 /opt/so-ops/.env
```

Docker Compose reads `.env` automatically from the working directory — secrets never touch `config.toml`.

## 5. Build the image

```bash
cd /opt/so-ops
sudo docker compose build
```

## 6. Test manually before enabling timers

```bash
cd /opt/so-ops
sudo docker compose run --rm so-ops config-check
sudo docker compose run --rm so-ops triage
```

Check the output looks right before letting the timers take over.

## 7. Install systemd timers

```bash
cd /opt/so-ops
sudo bash systemd/install.sh
```

The script:
1. Creates a `soops` system user (no login shell)
2. Adds `soops` to the `docker` group
3. Installs unit files to `/etc/systemd/system/`
4. Enables and starts all four timers

## 8. Verify timers are running

```bash
systemctl list-timers so-*.timer
```

You should see all four timers with their next trigger time.

## Viewing logs

```bash
# All so-ops output
journalctl -u so-triage.service -f

# Last health report
journalctl -u so-health.service -n 100

# Last nmap scan
journalctl -u so-vulnscan-nmap.service -n 100
```

## Running a command manually

You can trigger any command at any time without affecting the timer schedule:

```bash
cd /opt/so-ops
docker compose run --rm so-ops triage
docker compose run --rm so-ops health
docker compose run --rm so-ops test-notify
```

## Resetting the triage cursor

To re-process already-seen alerts (e.g. for testing):

```bash
docker compose run --rm so-ops bash -c "rm -f ~/so-ops-data/state/triage.json"
```

Or exec into the state volume directly:

```bash
docker volume inspect so-ops_so-ops-state
# find the mountpoint, then delete triage.json
```

## Updating

```bash
cd /opt/so-ops
git pull
docker compose build
# Timers will pick up the new image on next run automatically
```

## Disabling a timer

```bash
sudo systemctl disable --now so-vulnscan-nuclei.timer
```

Re-enable:
```bash
sudo systemctl enable --now so-vulnscan-nuclei.timer
```
