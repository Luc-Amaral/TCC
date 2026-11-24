"""Camada fina sobre o AsyncSniffer do Scapy.

Corrige três problemas da versão anterior:
  * o sniffer podia não ter iniciado (interface errada, Npcap ausente, falta de
    privilégio) e o teste concluía "ISOLADO" por ausência de dados;
  * um `stop()` que levantava exceção impedia o `stop()` do sniffer seguinte;
  * `sniffer.results` podia ser None e quebrava a iteração.
"""
import time

from scapy.all import AsyncSniffer


class Captura:
    """Um sniffer em uma interface, com início verificado e parada segura."""

    def __init__(self, iface, filtro=None, nome=None):
        self.iface = iface
        self.filtro = filtro
        self.nome = nome or str(iface)
        self.iniciou = False
        self.erro = None
        self.pacotes = []
        self._sniffer = None

    def iniciar(self, espera=3.0):
        if not self.iface:
            self.erro = "interface não informada"
            return False
        try:
            self._sniffer = AsyncSniffer(iface=self.iface, filter=self.filtro, store=True)
            self._sniffer.start()
            limite = time.time() + espera
            while time.time() < limite:
                if getattr(self._sniffer, "running", False):
                    self.iniciou = True
                    break
                thread = getattr(self._sniffer, "thread", None)
                if thread is not None and not thread.is_alive():
                    break  # a thread morreu: erro ao abrir a interface
                time.sleep(0.05)
            if not self.iniciou:
                thread = getattr(self._sniffer, "thread", None)
                if thread is not None and thread.is_alive():
                    self.iniciou = True  # versões antigas do Scapy não expõem `running`
            if not self.iniciou:
                self.erro = (
                    f"sniffer em '{self.nome}' não iniciou "
                    "(interface inexistente, Npcap ausente ou sem privilégio de administrador)"
                )
        except Exception as exc:  # noqa: BLE001
            self.erro = f"{type(exc).__name__}: {exc}"
        return self.iniciou

    def parar(self):
        if self._sniffer is None:
            return self.pacotes
        try:
            if getattr(self._sniffer, "running", False):
                self._sniffer.stop()
        except Exception as exc:  # noqa: BLE001
            self.erro = self.erro or f"erro ao parar '{self.nome}': {exc}"
        resultados = getattr(self._sniffer, "results", None)
        self.pacotes = list(resultados) if resultados else []
        self._sniffer = None
        return self.pacotes

    def __enter__(self):
        self.iniciar()
        return self

    def __exit__(self, *exc_info):
        self.parar()
        return False


class GrupoCapturas:
    """Inicia várias capturas juntas e garante que todas sejam paradas."""

    def __init__(self, *capturas, folga_inicio=0.7, folga_fim=1.0):
        self.capturas = [c for c in capturas if c is not None]
        self.folga_inicio = folga_inicio
        self.folga_fim = folga_fim

    def __enter__(self):
        for c in self.capturas:
            c.iniciar()
        time.sleep(self.folga_inicio)
        return self

    def __exit__(self, *exc_info):
        time.sleep(self.folga_fim)  # deixa os últimos pacotes chegarem
        for c in self.capturas:
            c.parar()
        return False

    @property
    def todas_iniciaram(self):
        return all(c.iniciou for c in self.capturas)

    def erros(self):
        return [c.erro for c in self.capturas if c.erro]


def pacote_ts(pkt):
    """Timestamp do pacote como float (o Scapy usa EDecimal)."""
    try:
        return float(pkt.time)
    except Exception:  # noqa: BLE001
        return 0.0
