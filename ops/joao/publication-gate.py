#!/usr/bin/env python3
"""Read-only exact-candidate publication condition; never reads or mutates a queue."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


class GateError(ValueError):
    """A fixed diagnostic class safe for the service journal."""


def read_private(path, maximum=65536):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
            raise GateError('invalid_private_input')
        with os.fdopen(descriptor, 'r', encoding='utf-8') as source:
            descriptor = None
            return source.read(maximum + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def selected_candidate(state_root, candidate_file=None):
    if candidate_file is None:
        campaign = json.loads(read_private(state_root / 'campaign.json'))
        if not isinstance(campaign, dict) or campaign.get('schema') != 1 or campaign.get('issue') != 19:
            raise GateError('invalid_campaign_candidate')
        value = campaign.get('candidate')
        digest = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if digest != campaign.get('candidateSha256'):
            raise GateError('candidate_binding_changed')
    else:
        # An explicit candidate never replaces a candidate already bound to a campaign.
        if (state_root / 'campaign.json').exists() or (state_root / 'campaign.json').is_symlink():
            raise GateError('campaign_candidate_override_forbidden')
        value = json.loads(read_private(candidate_file))
    if (not isinstance(value, dict) or set(value) != {'version', 'sha', 'origin'} or
            not isinstance(value['version'], str) or not re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value['version']) or
            not isinstance(value['sha'], str) or not re.fullmatch('[a-f0-9]{40}', value['sha']) or
            value['origin'] != 'https://linux-ai2.taile60a95.ts.net:8443'):
        raise GateError('invalid_candidate')
    return value


def has_reservation(publication_state):
    path = publication_state / 'publication-owner'
    return path.exists() or path.is_symlink()


def evaluate(state_root, review_state, publication_state, candidate_file=None):
    lock_path = publication_state / 'main-integration.lock'
    descriptor = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise GateError('invalid_integration_lock')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise GateError('integration_in_progress') from error
        if has_reservation(publication_state):
            raise GateError('publication_reserved')
        candidate = selected_candidate(state_root, candidate_file)
        current = read_private(review_state / 'current', 128).strip()
        version = read_private(review_state / 'build-version', 128).strip()
        if current != candidate['sha'] or version != candidate['version'][1:]:
            raise GateError('selected_candidate_not_published')
        if has_reservation(publication_state):
            raise GateError('publication_reserved')
        return 'selected_candidate_published'
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser()
    state_home = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state')))
    parser.add_argument('--state-root', type=Path, default=Path(os.environ.get('JOAO_STATE_ROOT', str(state_home / 'rappor-security-lab/joao'))))
    parser.add_argument('--review-state', type=Path, default=Path.home() / 'rappor-security/.data/review')
    parser.add_argument('--publication-state', type=Path, default=state_home / 'rappor-security')
    parser.add_argument('--candidate-file', type=Path)
    args = parser.parse_args()
    try:
        paths = (args.state_root, args.review_state, args.publication_state)
        if any(not path.is_absolute() for path in paths) or (args.candidate_file is not None and not args.candidate_file.is_absolute()):
            raise GateError('invalid_input_path')
        result = evaluate(args.state_root, args.review_state, args.publication_state, args.candidate_file)
    except GateError as error:
        print('publication_gate=' + str(error))
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print('publication_gate=precondition_unavailable')
        return 1
    print('publication_gate=' + result)
    return 0


if __name__ == '__main__':
    sys.exit(main())
