"""Behavior tests using official-client shaped data; no IDE, network or model."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('readiness', Path(__file__).resolve().parents[1] / 'ide-readiness.py')
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.data = dict(schemaVersion=1, candidateOrigin='https://linux-ai2.taile60a95.ts.net:8443',
            mcpStatus=[dict(name='rapporLabIssue19Windows', enabled=True, transport=dict(type='streamable_http',
                url='https://linux-ai2.taile60a95.ts.net:8443/mcp'), auth_status='oAuth')],
            mcpRuntimeStatus=dict(data=[dict(name='rapporLabIssue19Windows', authStatus='oAuth', runtimeStatus='connected',
                httpOrigin='https://linux-ai2.taile60a95.ts.net:8443', toolsError=None,
                tools={'list_products':dict(name='list_products',inputSchema={'type':'object'})})],nextCursor=None),
            appxPackages=[dict(Name='Rappor.RapporSecurity', Status='Ok')],
            windowObservation=dict(mode='interactive', observerSessionId=1, interactiveSessionId=1, visibleCodeWindows=1),
            rendererStatus='ready')

    def test_actual_alias_and_package_match_without_assumed_alias(self):
        value = R.classify(self.data)
        self.assertEqual(value['diagnosis'], 'local_readiness_observed')
        self.assertTrue(value['enabledExactEndpointSelected'])
        self.assertTrue(value['localRapporClientInstalled'])
        self.assertFalse(value['ownerActionVerified'])
        self.assertFalse(value['mcpToolCallVerified'])
        self.data['mcpStatus'][0]['name'] = 'user-selected-alias'
        self.data['mcpRuntimeStatus']['data'][0]['name'] = 'user-selected-alias'
        self.assertEqual(R.classify(self.data)['diagnosis'], 'local_readiness_observed')

    def test_missing_and_null_runtime_origin_use_exact_enabled_configuration(self):
        row = self.data['mcpRuntimeStatus']['data'][0]
        for missing in (False, True):
            with self.subTest(missing=missing):
                if missing:
                    row.pop('httpOrigin', None)
                else:
                    row['httpOrigin'] = None
                result = R.classify(self.data)
                self.assertTrue(result['enabledExactEndpointSelected'])
                self.assertTrue(result['mcpToolDiscoveryVerified'])
                self.assertEqual(result['authenticationState'], 'authenticated_connection_observed')
                self.assertFalse(result['mcpToolCallVerified'])
                self.assertFalse(result['ownerActionVerified'])

    def test_nullable_origin_cannot_override_wrong_configuration_or_runtime_identity(self):
        for changed in ('url', 'enabled', 'name'):
            with self.subTest(changed=changed):
                observation = copy.deepcopy(self.data)
                observation['mcpRuntimeStatus']['data'][0]['httpOrigin'] = None
                if changed == 'url':
                    observation['mcpStatus'][0]['transport']['url'] = 'https://unrelated.invalid/mcp'
                elif changed == 'enabled':
                    observation['mcpStatus'][0]['enabled'] = False
                else:
                    observation['mcpRuntimeStatus']['data'][0]['name'] = 'unrelated-server'
                self.assertFalse(R.classify(observation)['mcpToolDiscoveryVerified'])

    def test_non_null_runtime_origin_mismatch_remains_rejected(self):
        row = self.data['mcpRuntimeStatus']['data'][0]
        for value in ('https://unrelated.invalid', '', False, 1):
            with self.subTest(value=value):
                row['httpOrigin'] = value
                self.assertFalse(R.classify(self.data)['mcpToolDiscoveryVerified'])

    def test_unauthenticated_never_matches_authenticated(self):
        self.data.pop('mcpRuntimeStatus')
        for value in ('notLoggedIn', 'unauthenticated', 'logged_out', 'login_required'):
            with self.subTest(value=value):
                self.data['mcpStatus'][0]['auth_status'] = value
                result = R.classify(self.data)
                self.assertEqual(result['authenticationState'], 'unavailable')
                self.assertFalse(result['ownerActionVerified'])

    def test_oauth_and_file_presence_do_not_prove_authenticated(self):
        self.data['authFilePresent'] = True
        self.data.pop('mcpRuntimeStatus')
        for value, expected in [('oauth', 'oauth_configured_unconfirmed'), ('not authenticated', 'unknown'), ('authenticated maybe', 'unknown'), ('unsupported', 'unknown'), ('authenticated', 'unknown'), ('bearerToken', 'credential_configured_unconfirmed')]:
            self.data['mcpStatus'][0]['auth_status'] = value
            self.assertEqual(R.classify(self.data)['authenticationState'], expected)

    def test_disabled_and_nonboolean_enabled_servers_are_rejected(self):
        for enabled in (False, None, 'true', 1):
            self.data['mcpStatus'][0]['enabled'] = enabled
            self.assertFalse(R.classify(self.data)['enabledExactEndpointSelected'])

    def test_exact_path_scheme_credentials_query_and_fragment_required(self):
        for suffix in ('/other', '/mcp/extra', '/mcp?token=synthetic', '/mcp#fragment'):
            self.data['mcpStatus'][0]['transport']['url'] = self.data['candidateOrigin'] + suffix
            self.assertFalse(R.classify(self.data)['enabledExactEndpointSelected'])
        for url in ('http://linux-ai2.taile60a95.ts.net:8443/mcp', 'https://user@linux-ai2.taile60a95.ts.net:8443/mcp', 'https://linux-ai2.taile60a95.ts.net/mcp'):
            self.data['mcpStatus'][0]['transport']['url'] = url
            self.assertFalse(R.classify(self.data)['enabledExactEndpointSelected'])

    def test_duplicate_enabled_matches_are_ambiguous(self):
        self.data['mcpStatus'].append(copy.deepcopy(self.data['mcpStatus'][0]))
        self.assertEqual(R.classify(self.data)['diagnosis'], 'matching_server_ambiguous')

    def test_ssh_window_zero_is_unknown_not_invisible(self):
        self.data['windowObservation'].update(mode='ssh', observerSessionId=0, visibleCodeWindows=0)
        self.assertEqual(R.classify(self.data)['interactiveVisibility'], 'unknown')
        self.assertEqual(R.classify(self.data)['diagnosis'], 'readiness_inconclusive')

    def test_session_mismatch_cannot_prove_window_visibility(self):
        self.data['windowObservation']['observerSessionId'] = 2
        self.assertEqual(R.classify(self.data)['interactiveVisibility'], 'unknown')

    def test_old_invented_package_identity_cannot_select_client(self):
        self.data['appxPackages'][0]['Name'] = 'Rappor.LocalClient'
        self.assertFalse(R.classify(self.data)['localRapporClientInstalled'])

    def test_renderer_timeout_is_technical_even_if_auth_unknown(self):
        self.data['mcpStatus'][0]['auth_status'] = 'oauth'
        self.data['rendererStatus'] = 'renderer_ready_timeout'
        result = R.classify(self.data)
        self.assertEqual(result['diagnosis'], 'technical_renderer_failure')
        self.assertFalse(result['ownerActionVerified'])

    def test_conflicting_auth_fields_are_unknown(self):
        self.data.pop('mcpRuntimeStatus')
        self.data['mcpStatus'][0]['authStatus'] = 'unauthenticated'
        self.assertEqual(R.classify(self.data)['authenticationState'], 'unknown')

    def test_cached_tools_without_connected_runtime_do_not_prove_discovery(self):
        row = self.data['mcpRuntimeStatus']['data'][0]
        for status in (None, 'starting', 'notStarted', 'futureStatus'):
            row['runtimeStatus'] = status
            result = R.classify(self.data)
            self.assertFalse(result['mcpToolDiscoveryVerified'])
            self.assertEqual(result['diagnosis'], 'readiness_inconclusive')

    def test_tool_error_empty_catalog_and_wrong_runtime_name_are_unconfirmed(self):
        row = self.data['mcpRuntimeStatus']['data'][0]
        row['toolsError'] = 'Synthetic discovery failure'
        self.assertFalse(R.classify(self.data)['mcpToolDiscoveryVerified'])
        row['toolsError'] = None
        row['tools'] = {}
        self.assertFalse(R.classify(self.data)['mcpToolDiscoveryVerified'])
        row['name'] = 'another-server'
        self.assertFalse(R.classify(self.data)['mcpToolDiscoveryVerified'])

    def test_runtime_authentication_required_is_not_owner_action(self):
        row = self.data['mcpRuntimeStatus']['data'][0]
        row['runtimeStatus'] = 'authenticationRequired'
        row['authStatus'] = 'notLoggedIn'
        result = R.classify(self.data)
        self.assertEqual(result['authenticationState'], 'unavailable')
        self.assertFalse(result['ownerActionVerified'])

    def test_unadvertised_connection_status_field_is_not_assumed_runtime_status(self):
        row = self.data['mcpRuntimeStatus']['data'][0]
        row['connectionStatus'] = row.pop('runtimeStatus')
        self.assertFalse(R.classify(self.data)['mcpToolDiscoveryVerified'])

    def test_supported_servers_wrapper_and_auth_status_variant(self):
        row = self.data['mcpStatus'][0]
        row['authStatus'] = row.pop('auth_status')
        self.data['mcpStatus'] = {'servers': [row]}
        self.assertEqual(R.classify(self.data)['diagnosis'], 'local_readiness_observed')


if __name__ == '__main__':
    unittest.main()
