import speedtest

def executar():
    resultado = {
        "status": "INCONCLUSIVO",
        "detalhes": "Não executado",
        "ping_ms": 0,
        "download_mbps": 0.0,
        "upload_mbps": 0.0
    }
    
    try:
        print("        [>] Conectando aos servidores de teste (Pode levar até 30s)...")
        st = speedtest.Speedtest()
        st.get_best_server()
        
        print("        [>] Medindo Latência (Ping)...")
        resultado["ping_ms"] = round(st.results.ping, 2)
        
        print("        [>] Medindo banda de Download...")
        resultado["download_mbps"] = round(st.download() / 1_000_000, 2)
        
        print("        [>] Medindo banda de Upload...")
        resultado["upload_mbps"] = round(st.upload() / 1_000_000, 2)

        resultado["detalhes"] = f"Ping: {resultado['ping_ms']}ms | Down: {resultado['download_mbps']} Mbps | Up: {resultado['upload_mbps']} Mbps"
        resultado["status"] = "CONCLUIDO"
        
        return resultado
    except Exception as e:
        resultado["status"] = "ERRO"
        resultado["detalhes"] = f"Falha de comunicação com o servidor de Speedtest: {str(e)}"
        print(f"        [!] Erro: {resultado['detalhes']}")
        return resultado