# TGBR NETWORK ANALYZER
Analisador de Rede Doméstica - Detecção de possíveis abusos de ISP e possíveis soluções
Script interativo e autônomo para análise de segurança da rede doméstica. 
Executa varreduras, coleta informações de serviços e dispositivos conectados, detecta riscos possíveis e gera relatórios estruturados.
Linguagem Bash com chamadas Perl. 

---

[==Funcionalidades==]

-> Detecção de IP local, gateway e servidores DNS;
-> Verificação de presença de NAT duplo;
-> Descoberta de dispositivos ativos na rede; 
-> Identificação de SO/fabricante (OS fingerprinting);
-> Varredura de portas e serviços no roteador local;
-> Análise automatizada de riscos;
-> Sugestão de comandos para mitigação de danos;
-> Captura de tráfego DNS por tempo limitado (50s);
-> Verificação de possíveis conflitos ARP (spoofing);
-> Consulta ao IP público (opcional);
-> Geração de relatórios:
  - `relatorio_rede.md` 
  - `relatorio_rede.json` 

---

[==Requisitoss==}

- GNU/Linux com Bash
- Ferramentas recomendadas:
  -> `nmap`
  -> `tcpdump`
  -> `arp`
  -> `arp-scan` 
  -> `curl`
  -> `timeout`
  -> `perl`

---

[==Uso do programa==]

Tornar script executável:
```bash
chmod +x tgbr_net_analyzer.sh
```
--------------------------------------------------------------------------------------------------------------------------------------

# TGBR NETWORK ANALYZER
Home Network Analyzer - Detection of possible ISP abuse and possible solutions. Interactive and autonomous script for home network security analysis. 
Performs scans, collects information from services and connected devices, detects possible risks and generates structured reports.
Bash language with Perl calls.

---

[==Functionalities==]

-> Detection of local IP, gateway and DNS servers;
-> Double NAT presence check;
-> Discovery of active devices on the network; 
-> OS/manufacturer identification (OS fingerprinting);
-> Port and service scanning on the local router;
-> Automated risk analysis;
-> Suggestion of commands to mitigate damage;
-> DNS traffic capture for a limited time (50s);
-> Check for possible ARP conflicts (spoofing);
-> Public IP lookup (optional);
-> Report generation:
  - `relatorio_rede.md` 
  - `relatorio_rede.json` 

---

[==Requirements==}

- GNU/Linux with Bash
- Recommended tools:
  -> `nmap`
  -> `tcpdump`
  -> `arp`
  -> `arp-scan` 
  -> `curl`
  -> `timeout`
  -> `perl`


---

[==Program usage==]

Make script executable:
```bash
chmod +x tgbr_net_analyzer.sh
```










