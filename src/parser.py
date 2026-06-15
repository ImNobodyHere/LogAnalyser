import re
from datetime import datetime

# ─── Auth.log Parser ───────────────────────────────────────────────

AUTH_PATTERN = re.compile(
    r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+(.*)'
)

FAILED_PATTERN = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\S+) port \d+'
)

SUCCESS_PATTERN = re.compile(
    r'Accepted password for (\S+) from (\S+) port \d+'
)


def parse_auth_log(filepath):
    entries = []

    with open(filepath, 'r') as f:
        for line in f:
            match = AUTH_PATTERN.match(line)
            if not match:
                continue

            timestamp_str, message = match.groups()

            entry = {
                'timestamp': timestamp_str,
                'message': message,
                'type': None,
                'user': None,
                'ip': None
            }

            failed = FAILED_PATTERN.search(message)
            success = SUCCESS_PATTERN.search(message)

            if failed:
                entry['type'] = 'failed'
                entry['user'] = failed.group(1)
                entry['ip'] = failed.group(2)

            elif success:
                entry['type'] = 'success'
                entry['user'] = success.group(1)
                entry['ip'] = success.group(2)

            entries.append(entry)

    return entries


# ─── Access.log Parser ─────────────────────────────────────────────

ACCESS_PATTERN = re.compile(
    r'(\S+) - - \[(.+?)\] "(\S+) (\S+) HTTP/\S+" (\d+) (\d+)'
)


def parse_access_log(filepath):
    entries = []

    with open(filepath, 'r') as f:
        for line in f:
            match = ACCESS_PATTERN.match(line)
            if not match:
                continue

            ip, timestamp, method, path, status, size = match.groups()

            entries.append({
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'path': path,
                'status': int(status),
                'size': int(size)
            })

    return entries


# ─── Quick test ────────────────────────────────────────────────────

if __name__ == '__main__':
    auth_entries = parse_auth_log('../logs/auth.log')
    access_entries = parse_access_log('../logs/access.log')

    print("=== AUTH LOG ===")
    for e in auth_entries:
        print(e)

    print("\n=== ACCESS LOG ===")
    for e in access_entries:
        print(e)