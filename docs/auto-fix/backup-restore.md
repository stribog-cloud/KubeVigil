# Backup and Restore

Every `kubevigil fix --apply` operation creates a mandatory backup before modifying any files. There is no `--no-backup` flag -- backup is always created.

## How Backups Work

When `--apply` is used, KubeVigil:

1. Collects all files that will be modified
2. Creates a backup directory
3. Copies every original file into the backup, preserving the relative directory structure and file permissions
4. Generates a `RESTORE.md` file with restore instructions
5. Only then writes patched files to disk

If the backup creation fails, no files are modified and the fix operation exits with code `2`.

## Backup Directory

The default backup directory is created next to the source path with a timestamp:

```
<source-path>.kubevigil-backup-YYYYMMDDTHHMMSS
```

For example:

```bash
kubevigil fix ./manifests/ --apply
# Creates: ./manifests/.kubevigil-backup-20250115T103045/
```

### Custom Backup Directory

Use `--backup-dir` to specify a custom location:

```bash
kubevigil fix ./manifests/ --apply --backup-dir /tmp/kubevigil-backups/run-001
```

The backup directory can also be set in `.kubevigil.yaml`:

```yaml
fix:
  backup_dir: /var/backups/kubevigil
```

CLI flags override configuration file values.

## Backup Contents

The backup directory mirrors the source directory structure. For example:

```
./manifests/.kubevigil-backup-20250115T103045/
  deployment.yaml          # Original deployment.yaml
  services/
    frontend-svc.yaml      # Original frontend-svc.yaml
  RESTORE.md               # Restore instructions
```

After a fix with `--apply --report`, a `FIX-REPORT.md` is also written to the backup directory:

```
./manifests/.kubevigil-backup-20250115T103045/
  deployment.yaml
  services/
    frontend-svc.yaml
  RESTORE.md
  FIX-REPORT.md
```

## RESTORE.md

Every backup includes a `RESTORE.md` file with:

- Timestamp of when the backup was created
- Source path that was scanned
- Quick restore command to restore all files at once
- A table mapping each backup file to its original location
- Individual `cp` commands for restoring specific files

Example `RESTORE.md` content:

```markdown
# KubeVigil Fix Backup -- Restore Instructions

Backup created: 2025-01-15 10:30:45
Source: /home/user/project/manifests

## Quick Restore (all files)

    cp -r /home/user/project/manifests/.kubevigil-backup-20250115T103045/* /home/user/project/manifests/

## Individual File Restore

| Backup File | Original Location |
|------------|-------------------|
| /home/user/.../deployment.yaml | /home/user/project/manifests/deployment.yaml |
| /home/user/.../services/frontend-svc.yaml | /home/user/project/manifests/services/frontend-svc.yaml |

## Restore Commands

    cp "/home/user/.../deployment.yaml" "/home/user/project/manifests/deployment.yaml"
    cp "/home/user/.../services/frontend-svc.yaml" "/home/user/project/manifests/services/frontend-svc.yaml"
```

## Restoring Files

### Restore All Files

Copy the entire backup directory back to the source:

```bash
cp -r ./manifests/.kubevigil-backup-20250115T103045/* ./manifests/
```

### Restore a Single File

Copy just the specific file:

```bash
cp ./manifests/.kubevigil-backup-20250115T103045/deployment.yaml ./manifests/deployment.yaml
```

### Using RESTORE.md

Open the `RESTORE.md` file in the backup directory for ready-to-use copy commands tailored to your specific file paths.

## Backup in CI

In CI environments, backups are still created. You can redirect them to an artifacts directory for archival:

```bash
kubevigil fix ./manifests/ --apply --yes --backup-dir ./backup-artifacts/
```

Then upload the backup directory as a CI artifact for later recovery if needed.

## Summary Output

After applying fixes, the summary includes the backup path and restore instructions:

```
KubeVigil Fix Summary
---------------------
Files scanned:       12
Files to modify:      4
Findings total:       9

By risk classification:
  Safe:                  5  [applied]

Backup: ./manifests/.kubevigil-backup-20250115T103045

To restore: cp -r ./manifests/.kubevigil-backup-20250115T103045/* ./manifests/
Fix report: ./manifests/.kubevigil-backup-20250115T103045/FIX-REPORT.md
```
