#!/usr/bin/env python3
"""Classify private official-client observations without inferring owner actions."""
import argparse
import json
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit


def exact_endpoint(value, origin):
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        expected = urlsplit(origin)
        return (parsed.scheme == expected.scheme == 'https' and parsed.hostname == expected.hostname and
                parsed.port == expected.port and parsed.path == '/mcp' and not parsed.query and
                not parsed.fragment and parsed.username is None and parsed.password is None)
    except ValueError:
        return False


def select_server(status, origin):
    rows = status.get('servers') if isinstance(status, dict) else status
    if not isinstance(rows, list) or len(rows) > 100:
        return None, 'invalid_client_status'
    selected = []
    for row in rows:
        if not isinstance(row, dict):
            return None, 'invalid_client_status'
        transport = row.get('transport')
        if (row.get('enabled') is True and isinstance(transport, dict) and
                transport.get('type') == 'streamable_http' and exact_endpoint(transport.get('url'), origin)):
            selected.append(row)
    if len(selected) != 1:
        return None, 'matching_server_missing' if not selected else 'matching_server_ambiguous'
    return selected[0], 'selected'


def auth_state(server):
    if server is None:
        return 'unknown'
    if 'auth_status' in server and 'authStatus' in server and server['auth_status'] != server['authStatus']:
        return 'unknown'
    raw = server.get('auth_status', server.get('authStatus'))
    if not isinstance(raw, str):
        return 'unknown'
    value = raw.strip().casefold()
    if value in {'notloggedin', 'unauthenticated', 'logged_out', 'logged out', 'login_required'}:
        return 'unavailable'
    if value == 'oauth':
        return 'oauth_configured_unconfirmed'
    if value == 'bearertoken':
        return 'credential_configured_unconfirmed'
    return 'unknown'


def runtime_status(status, selected, origin):
    if selected is None or not isinstance(selected.get('name'), str) or not isinstance(status, dict):
        return 'unknown', False
    rows = status.get('data')
    if not isinstance(rows, list) or len(rows) > 100:
        return 'unknown', False
    matches = [row for row in rows if isinstance(row, dict) and row.get('name') == selected['name']]
    if len(matches) != 1:
        return 'unknown', False
    row = matches[0]
    if row.get('httpOrigin', origin) != origin:
        return 'unknown', False
    state = row.get('runtimeStatus')
    if state not in {'notStarted', 'starting', 'connected', 'authenticationRequired', 'failed', 'cancelled', 'disabled'}:
        return 'unknown', False
    tools = row.get('tools')
    catalog = (isinstance(tools, dict) and 1 <= len(tools) <= 500 and
               all(isinstance(name, str) and name and isinstance(tool, dict) and
                   tool.get('name') == name and 'inputSchema' in tool for name, tool in tools.items()))
    ready = (state == 'connected' and row.get('authStatus') in {'oAuth', 'bearerToken'} and
             'toolsError' in row and row['toolsError'] is None and catalog)
    return state, bool(ready)


def classify(observation):
    if not isinstance(observation, dict) or observation.get('schemaVersion') != 1:
        raise ValueError('invalid-observation')
    origin = observation.get('candidateOrigin')
    if origin != 'https://linux-ai2.taile60a95.ts.net:8443':
        raise ValueError('unexpected-candidate-origin')
    server, selection = select_server(observation.get('mcpStatus'), origin)
    auth = auth_state(server)
    connection, discovery = runtime_status(observation.get('mcpRuntimeStatus'), server, origin)
    if connection == 'authenticationRequired':
        auth = 'unavailable'
    elif discovery:
        auth = 'authenticated_connection_observed'
    packages = observation.get('appxPackages')
    if not isinstance(packages, list) or len(packages) > 100:
        raise ValueError('invalid-package-observation')
    official = [p for p in packages if isinstance(p, dict) and p.get('Name') == 'Rappor.RapporSecurity' and p.get('Status') == 'Ok']
    client_installed = len(official) == 1
    window = observation.get('windowObservation', {})
    visible = 'unknown'
    if (isinstance(window, dict) and window.get('mode') == 'interactive' and
            type(window.get('observerSessionId')) is int and window['observerSessionId'] > 0 and
            window['observerSessionId'] == window.get('interactiveSessionId') and
            type(window.get('visibleCodeWindows')) is int and window['visibleCodeWindows'] >= 0):
        visible = 'visible' if window['visibleCodeWindows'] > 0 else 'not_visible'
    renderer = observation.get('rendererStatus', 'unknown')
    if renderer not in {'ready', 'renderer_ready_timeout', 'unknown'}:
        renderer = 'unknown'
    if renderer == 'renderer_ready_timeout':
        diagnosis = 'technical_renderer_failure'
    elif server is None:
        diagnosis = selection
    elif auth == 'unavailable':
        diagnosis = 'authentication_unavailable'
    elif not client_installed:
        diagnosis = 'client_installation_unconfirmed'
    elif connection == 'failed':
        diagnosis = 'technical_mcp_failure'
    elif not discovery or visible != 'visible' or renderer != 'ready':
        diagnosis = 'readiness_inconclusive'
    else:
        diagnosis = 'local_readiness_observed'
    return dict(schemaVersion=1, diagnosis=diagnosis, enabledExactEndpointSelected=server is not None,
                authenticationState=auth, localRapporClientInstalled=client_installed,
                interactiveVisibility=visible, rendererStatus=renderer, mcpConnectionStatus=connection,
                mcpToolDiscoveryVerified=discovery, ownerActionVerified=False,
                mcpToolCallVerified=False, inferenceStarted=False,
                limitation='A connected runtime and available catalog do not prove a fresh tools/list request, a successful tool call, or an owner-only action.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-file', required=True, type=Path)
    args = parser.parse_args()
    try:
        path = args.input_file
        if not path.is_absolute() or path.is_symlink():
            raise ValueError('invalid-private-path')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'r', encoding='utf-8') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid() or info.st_size > 262144:
                raise ValueError('invalid-private-input')
            result = classify(json.load(source))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print('ide_readiness=invalid_or_unavailable_observation')
        return 65


if __name__ == '__main__':
    raise SystemExit(main())
