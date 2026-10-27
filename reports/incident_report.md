# Incident Triage Report

**Generated:** 2026-10-27 10:44 UTC
**Source:** `sample_logs\auth.log`
**Findings:** 4

## Summary

| Severity | Technique | Subject | Events |
|----------|-----------|---------|--------|
| HIGH | T1110 - Brute Force | `192.0.2.10` | 5 |
| HIGH | T1003 - OS Credential Dumping | `/usr/bin/cat /etc/shadow` | 1 |
| HIGH | T1136 - Create Account | `guest` | 1 |
| MEDIUM | T1548 - Abuse Elevation Control Mechanism | `n/a` | 1 |

## Evidence (Detection Phase — NIST SP 800-61 §3.2)

### brute_force — `192.0.2.10` (5 events)
```text
Oct 27 12:00:01  Oct 27 12:00:01 host sshd[1001]: Failed password for invalid user admin from 192.0.2.10 port 22 ssh2
Oct 27 12:00:05  Oct 27 12:00:05 host sshd[1002]: Failed password for invalid user admin from 192.0.2.10 port 22 ssh2
Oct 27 12:00:09  Oct 27 12:00:09 host sshd[1003]: Failed password for invalid user admin from 192.0.2.10 port 22 ssh2
Oct 27 12:00:13  Oct 27 12:00:13 host sshd[1004]: Failed password for invalid user admin from 192.0.2.10 port 22 ssh2
Oct 27 12:00:17  Oct 27 12:00:17 host sshd[1005]: Failed password for invalid user admin from 192.0.2.10 port 22 ssh2
```

### sensitive_file_access — `/usr/bin/cat /etc/shadow` (1 events)
```text
Oct 27 12:05:00  Oct 27 12:05:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
```

### unauthorized_user_creation — `guest` (1 events)
```text
Oct 27 12:10:00  Oct 27 12:10:00 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd guest
```

### privilege_escalation — `n/a` (1 events)
```text
Oct 27 12:11:00  Oct 27 12:11:00 host sudo: pam_unix(sudo:session): session opened for user root by alice(uid=1000)
```
