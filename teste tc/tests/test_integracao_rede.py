import json
import os
import unittest

from utils.network import detectar_ambiente_vpn, obter_informacoes_redes, obter_ips_reais


@unittest.skipUnless(
    os.getenv('VPN_INTEGRATION') == '1',
    'Defina VPN_INTEGRATION=1 para executar testes contra o ambiente de rede real.',
)
class NetworkIntegrationTests(unittest.TestCase):
    def test_network_snapshot_is_real_and_serializable(self):
        informacoes = obter_informacoes_redes()
        self.assertIn('interfaces', informacoes)
        json.dumps(informacoes)

    def test_baseline_has_ipv4(self):
        ips = obter_ips_reais()
        self.assertTrue(ips.get('v4'))

    def test_vpn_discovery_returns_consistent_interfaces(self):
        interface_vpn, processo, _, interface_fisica, _ = detectar_ambiente_vpn()
        self.assertTrue(interface_vpn)
        self.assertTrue(interface_fisica)
        self.assertNotEqual(interface_vpn, interface_fisica)
        self.assertTrue(processo or os.getenv('ALLOW_MISSING_VPN_PROCESS') == '1')
        
if __name__ == '__main__':
    unittest.main()
