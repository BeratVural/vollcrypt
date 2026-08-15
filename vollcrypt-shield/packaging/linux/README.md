# Vollcrypt Shield native package

The package installs the CLI, a hardened `vollcrypt-shield@.service` template,
the unprivileged `vollcrypt-shield` system identity, and private configuration
and state directories. It never creates a baseline, activates a policy, or
starts/enables an instance during installation.

Create `/etc/vollcrypt-shield/<scope>.toml` and its first baseline explicitly,
grant the service identity read access only to that monitored root, then enable
the matching instance:

```console
sudo -u vollcrypt-shield vollcrypt-shield init --config /etc/vollcrypt-shield/app.toml --break-glass-key /offline/app.seed
sudo -u vollcrypt-shield vollcrypt-shield baseline --config /etc/vollcrypt-shield/app.toml --scope app
sudo systemctl enable --now vollcrypt-shield@app.service
```

The packaged unit is detection-only by default: `ProtectSystem=strict` keeps
the monitored filesystem read-only. Before enabling an active quarantine or
rollback policy, add a scope-specific systemd drop-in containing the narrowest
possible `ReadWritePaths=/absolute/monitored/root`, then rerun the mandatory
dry-run and policy approval flow. Never grant a protected system root.

The break-glass seed must remain outside `/etc/vollcrypt-shield`, the monitored
root, and `/var/lib/vollcrypt-shield`. Package removal does not delete operator
configuration, signed evidence, keys, quarantine records, or the service user.
