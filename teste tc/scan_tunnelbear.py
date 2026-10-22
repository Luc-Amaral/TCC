import psutil

print('=== Processos TunnelBear/Shadowsocks/V2Ray ===')
for p in psutil.process_iter(['pid', 'name']):
    try:
        n = p.info['name'].lower()
        if any(k in n for k in ('tunnel', 'bear', 'shadowsocks', 'v2ray')):
            print(f"  PID={p.info['pid']}  Nome={p.info['name']}")
    except Exception:
        pass

print()
print('=== Interfaces de Rede Ativas (com IP) ===')
stats_map = psutil.net_if_stats()
for nome, addrs in psutil.net_if_addrs().items():
    stats = stats_map.get(nome)
    if not stats or not stats.isup:
        continue
    ips = [a.address for a in addrs
           if a.family.name in ('AF_INET', 'AF_INET6') and not a.address.startswith('fe80')]
    if ips:
        print(f"  {nome:<32} IPs={ips}")

