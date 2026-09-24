# BIG-IP UCS backup

Creates, downloads, and removes a UCS archive on each BIG-IP listed in `bigipbackup.yaml`
using iControl REST. Meant to run weekly from cron.

## Setup
    pip install -r requirements.txt
    cp example-bigipbackup.env bigipbackup.env && chmod 600 bigipbackup.env
    vi bigipbackup.yaml    # fill in creds
    cp example-bigipbackup.yaml bigipbackup.yaml && chmod 600 bigipbackup.yaml
    vi bigipbackup.yaml    # fill in devices

The account needs the **Administrator** role on each device (required for `save sys ucs`).

**Resource Administrator** should work according to documentation, but DOES NOT.

## Config and credential discovery
`--config` is optional. Without it, the script uses the first `bigipbackup.yaml` found in:
1. the current directory
2. the script's directory
3. `/etc/bigipbackup/`

`BIGIP_USER` / `BIGIP_PASS` already set in the environment win. Any not set are read from
`bigipbackup.env`, looked for next to the config file first, then in the same locations.

## Test
    ./bigipbackup.py --dry-run                                # auth + list only
    ./bigipbackup.py --device bigip01b.example.org

## Cron (Sundays 02:00)
    0 2 * * 0  /usr/bin/python3 /opt/bigipbackup/bigipbackup.py

(Finds `bigipbackup.yaml` and `bigipbackup.env` in the script's directory.)

Exit code is non-zero if any device fails, so set `MAILTO=` in the crontab or hook it into monitoring.

## Notes
- UCS files are **unencrypted and include private keys**. Files are written 0600 and
  directories 0700; keep `backup_dir` on restricted storage.
- Restore: copy to `/var/local/ucs/` on the device and run `tmsh load sys ucs <file>`
  (add `no-license` when restoring to different hardware).
