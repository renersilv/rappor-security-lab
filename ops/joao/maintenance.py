#!/usr/bin/env python3
"""Explicit execution hold; the existing timer keeps observing pending notices."""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile


def status(root):
    path = root / 'maintenance.json'
    if not path.exists() and not path.is_symlink():
        return 'none'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024):
            raise ValueError('invalid-maintenance-file')
        value = json.load(source)
    if (set(value) != {'schema', 'reason', 'createdAt'} or value['schema'] != 1
            or value['reason'] != 'assisted_maintenance'
            or not isinstance(value['createdAt'], str)):
        raise ValueError('invalid-maintenance-state')
    instant = datetime.datetime.fromisoformat(value['createdAt'])
    if instant.tzinfo is None or instant.utcoffset() != datetime.timedelta(0):
        raise ValueError('invalid-maintenance-time')
    return 'held'


def change(root, action):
    descriptor = os.open(root / 'run.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'r+') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('invalid-run-lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = status(root)
        path = root / 'maintenance.json'
        if action == 'hold' and current == 'none':
            fd, name = tempfile.mkstemp(prefix='.maintenance-', dir=root)
            try:
                with os.fdopen(fd, 'w') as out:
                    json.dump(dict(schema=1, reason='assisted_maintenance',
                                   createdAt=datetime.datetime.now(datetime.timezone.utc).isoformat()), out)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(name, path)
            finally:
                Path(name).unlink(missing_ok=True)
        elif action == 'release' and current == 'held':
            # An explicit release never clears operational or campaign gates.
            path.unlink()
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        return status(root)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['status', 'hold', 'release'])
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    root = args.root
    if (not root.is_absolute() or root != root.resolve() or not root.is_dir()
            or root.stat().st_uid != os.getuid() or stat.S_IMODE(root.stat().st_mode) != 0o700):
        raise ValueError('invalid-maintenance-root')
    print(status(root) if args.action == 'status' else change(root, args.action))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError):
        print('maintenance_precondition_failed')
        raise SystemExit(65)
