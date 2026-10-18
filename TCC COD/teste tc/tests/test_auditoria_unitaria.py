import inspect
import json
import unittest
from unittest.mock import patch

from core.nucleo_exec import VPNSecurityTester
from tests import test_1_isolamento_payload, test_3_privacidade, test_5_killswitch
from utils.network import obter_informacoes_redes


class FakeSniffer:
    def __init__(self, *args, **kwargs):
        self.results = []

    def start(self):
        return None

    def stop(self):
        return None


class AuditoriaUnitTests(unittest.TestCase):
    def make_tester(self):
        return VPNSecurityTester(
            {'v4': '198.51.100.1', 'v6': None},
            ['192.0.2.53'],
            'vpn.exe',
            'tun0',
            'Ethernet',
        )

    def test_policy_accepts_only_approved_states(self):
        tester = self.make_tester()
        tester.resultados = {
            'payload': {'status': 'ISOLADO'},
            'http': {'status': 'ISOLADO'},
            'privacy': {'status': 'ISOLADO'},
            'route': {'status': 'ISOLADO'},
            'kill': {'status': 'BLOQUEADO'},
        }
        self.assertEqual(tester._avaliar_politica_resultado(), 'APROVADO NO ESCOPO')

    def test_policy_rejects_inconclusive_and_failure(self):
        tester = self.make_tester()
        tester.resultados = {'privacy': {'status': 'INCONCLUSIVO'}}
        self.assertEqual(tester._avaliar_politica_resultado(), 'NAO COMPROVADO')
        tester.resultados = {'privacy': {'status': 'FALHA'}}
        self.assertEqual(tester._avaliar_politica_resultado(), 'REPROVADO')

    def test_payload_signature_matches_orchestrator(self):
        self.assertEqual(len(inspect.signature(test_1_isolamento_payload.executar).parameters), 2)
        self.assertEqual(len(inspect.signature(test_5_killswitch.executar).parameters), 3)

    def test_network_snapshot_is_json_serializable(self):
        json.dumps(obter_informacoes_redes())

    def test_ipv6_timeout_does_not_approve_privacy(self):
        timeout = test_3_privacidade.requests.exceptions.Timeout()
        with patch.object(test_3_privacidade.requests, 'get', side_effect=timeout), \
            patch.object(test_3_privacidade.requests, 'post', side_effect=timeout), \
                patch.object(test_3_privacidade, 'AsyncSniffer', FakeSniffer), \
            patch.object(test_3_privacidade.socket, 'getaddrinfo', side_effect=OSError()), \
            patch.object(test_3_privacidade.socket, 'create_connection', side_effect=OSError()):
            resultado = test_3_privacidade.executar(
                {'v4': '198.51.100.1', 'v6': None},
                ['192.0.2.53'],
                'Ethernet',
                'tun0',
            )
        self.assertEqual(resultado['status'], 'INCONCLUSIVO')


if __name__ == '__main__':
    unittest.main()
