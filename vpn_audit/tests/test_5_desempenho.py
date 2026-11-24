import socket
import statistics
import time

import speedtest

from utils.network import consultar_ipv4


def _mediana(valores):
    return round(statistics.median(valores), 2) if valores else None


def _rtt_tcp(host="1.1.1.1", porta=443, n=5):
    """Latência independente do servidor Speedtest: tempo do handshake TCP."""
    medidas = []
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, porta), timeout=3):
                medidas.append((time.perf_counter() - t0) * 1000)
        except OSError:
            pass
        time.sleep(0.2)
    return _mediana(medidas)


def executar(repeticoes=3, servidor_id=None, ip_baseline_v4=None, titulo="Impacto de Desempenho (QoS)"):
    """Mede ping, download e upload `repeticoes` vezes e reporta a MEDIANA.

    servidor_id: fixa o servidor Speedtest (use o do baseline na medição com VPN, para que a
    comparação não misture o efeito da VPN com a troca de servidor).
    ip_baseline_v4: se informado, registra se o IP de saída durante a medição já difere do real.
    """
    print(f"\n[*] 5. {titulo} ({repeticoes} repetições; pode levar alguns minutos)...")
    resultado = {
        "status": "INCONCLUSIVO", "detalhes": "Não executado",
        "ping_ms": None, "download_mbps": None, "upload_mbps": None, "rtt_tcp_ms": None,
        "amostras": {"ping_ms": [], "download_mbps": [], "upload_mbps": []},
        "servidor": None, "servidor_id": None, "servidor_fixado": bool(servidor_id),
        "repeticoes": repeticoes, "ip_saida_v4": None, "via_tunel": None,
    }
    amostras = resultado["amostras"]
    socket_timeout_anterior = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(30)
        print("        [>] Conectando aos servidores de teste...")
        st = speedtest.Speedtest(secure=True)
        if servidor_id:
            try:
                st.get_servers([int(servidor_id)])
            except Exception:  # noqa: BLE001
                print("        [!] Servidor do baseline indisponível; usando o melhor servidor atual.")
                resultado["servidor_fixado"] = False
        st.get_best_server()
        srv = st.results.server
        resultado["servidor_id"] = srv.get("id")
        resultado["servidor"] = {k: srv.get(k) for k in ("id", "name", "sponsor", "country", "host", "d")}
        print(f"        [>] Servidor: {srv.get('sponsor')} - {srv.get('name')} ({srv.get('country')})")

        for i in range(1, repeticoes + 1):
            print(f"        [>] Repetição {i}/{repeticoes}...")
            try:
                st.get_best_server()
                amostras["ping_ms"].append(round(st.results.ping, 2))
            except Exception as exc:  # noqa: BLE001
                print(f"            ping falhou: {exc}")
            try:
                amostras["download_mbps"].append(round(st.download() / 1_000_000, 2))
            except Exception as exc:  # noqa: BLE001
                print(f"            download falhou: {exc}")
            try:
                amostras["upload_mbps"].append(round(st.upload() / 1_000_000, 2))
            except Exception as exc:  # noqa: BLE001
                print(f"            upload falhou: {exc}")

        resultado["ping_ms"] = _mediana(amostras["ping_ms"])
        resultado["download_mbps"] = _mediana(amostras["download_mbps"])
        resultado["upload_mbps"] = _mediana(amostras["upload_mbps"])
        resultado["rtt_tcp_ms"] = _rtt_tcp()

        ip_saida, _ = consultar_ipv4()
        resultado["ip_saida_v4"] = ip_saida
        if ip_baseline_v4 and ip_saida:
            resultado["via_tunel"] = ip_saida != ip_baseline_v4

        if all(amostras[k] for k in amostras):
            resultado["status"] = "CONCLUIDO"
            resultado["detalhes"] = (
                f"Mediana de {repeticoes}: Ping {resultado['ping_ms']} ms | "
                f"Down {resultado['download_mbps']} Mbps | Up {resultado['upload_mbps']} Mbps"
                f" | RTT TCP {resultado['rtt_tcp_ms']} ms"
            )
            if resultado["via_tunel"] is False:
                resultado["detalhes"] += " | ATENÇÃO: IP de saída igual ao real (medição fora do túnel?)"
        else:
            resultado["status"] = "ERRO"
            resultado["detalhes"] = "Medição incompleta: " + ", ".join(k for k in amostras if not amostras[k])
            print(f"        [!] {resultado['detalhes']}")
        return resultado
    except Exception as e:  # noqa: BLE001
        resultado["status"] = "ERRO"
        resultado["detalhes"] = f"Falha de comunicação com o servidor de Speedtest: {e}"
        print(f"        [!] Erro: {resultado['detalhes']}")
        return resultado
    finally:
        socket.setdefaulttimeout(socket_timeout_anterior)
