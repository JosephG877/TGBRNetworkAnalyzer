#!/bin/bash

# [[AUDITORIA DE SEGURANÇA NA REDE===]]

# [[===ARQUIVOS DE SAÍDA===]]
REPORT_MD="relatorio_rede.md"
REPORT_JSON="relatorio_rede.json"
TMP_DATA="/tmp/analisador_dados.tmp"
ONLINE_MODE=0
BATCH_MODE=0

command_exists() { command -v "$1" >/dev/null 2>&1; }
log() { echo -e "[INFO] $1"; }
warn() { echo -e "[AVISO] $1" >&2; }
error() { echo -e "[ERRO] $1" >&2; }

# [[===MENU PRINCIPAL ===]]
menu_principal() {
    echo " _____ _____ _____ _____          _____               _       _     "
    echo "|_   _|   __| __  | __  |        |   __|_ _ ___  __ _| |_____|_|___ "
    echo "  | | |  |  | __ -|    -|        |__   | | |_ -||. | . |     | |   |"
    echo "  |_| |_____|_____|__|__|        |_____|_  |___|___|___|_|_|_|_|_|_|"
    echo "                                       |___|                        "   
    echo "=============================================="
    echo "          ANALISADOR DE REDE DOMÉSTICA        "
    echo "=============================================="
    echo "1) Executar análise completa"
    echo "2) Executar análise completa com modo online"
    echo "3) Sair"
    echo -n "Entre com as opções a seguir: "
    read opcao

    case "$opcao" in
        1)
            BATCH_MODE=1
            ONLINE_MODE=0
            ;;
        2)
            BATCH_MODE=1
            ONLINE_MODE=1
            ;;
        3)
            echo "Saindo."
            exit 0
            ;;
        *)
            echo "Opção inválida."
            menu_principal
            ;;
    esac
}

# [[=== COLETA BÁSICA DE INFORMAÇÕES ===]]
get_local_ip() {
    ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+' || hostname -I | awk '{print $1}'
}

get_gateway_ip() {
    ip route | grep default | awk '{print $3}'
}

get_gateway_mac() {
    local gwip=$(get_gateway_ip)
    arp -n | grep "$gwip" | awk '{print $3}'
}

get_dns_servers() {
    grep -E '^nameserver' /etc/resolv.conf | awk '{print $2}'
}

check_double_nat() {
    local ttl_ext=$(ping -c 1 1.1.1.1 | grep ttl= | sed -E 's/.*ttl=([0-9]+).*/\1/')
    local ttl_int=$(ping -c 1 "$(get_gateway_ip)" | grep ttl= | sed -E 's/.*ttl=([0-9]+).*/\1/')
    if [[ -n "$ttl_ext" && -n "$ttl_int" && "$ttl_ext" -lt "$ttl_int" ]]; then
        echo "Possível NAT duplo detectado: TTL externo ($ttl_ext) < TTL interno ($ttl_int)"
    else
        echo "NAT duplo não identificado (TTL externo $ttl_ext, interno $ttl_int)"
    fi
}

coleta_inicial() {
    echo "[=== INFORMAÇÕES GERAIS DA REDE ===]"
    local ip_local=$(get_local_ip)
    local gw_ip=$(get_gateway_ip)
    local gw_mac=$(get_gateway_mac)
    local dns_servers=$(get_dns_servers | paste -sd "," -)

    echo "IP da Máquina: $ip_local"
    echo "Gateway: $gw_ip"
    echo "MAC do Gateway: $gw_mac"
    echo "Servidores DNS: $dns_servers"

    check_double_nat

    {
        echo "ip_local=$ip_local"
        echo "gateway_ip=$gw_ip"
        echo "gateway_mac=$gw_mac"
        echo "dns=$dns_servers"
    } > "$TMP_DATA"
}

scan_dispositivos() {
    echo -e "\n=== DISPOSITIVOS ATIVOS NA REDE ==="
    local rede=$(get_local_ip | awk -F. '{print $1"."$2"."$3".0/24"}')
    if command_exists nmap; then
        echo "[$] USANDO NMAP PARA ESCANEAR REDE $rede..."
        sudo nmap -sn --disable-arp-ping -n -oG /tmp/nmap_hosts_raw.txt "$rede"
        grep "/Up" /tmp/nmap_hosts_raw.txt | awk '{print $2}' > /tmp/hosts_ativos.txt

        echo "[$] DISPOSITIVOS ENCONTRADOS COM DETALHES:"
        sudo nmap -O -Pn -T4 -oN /tmp/nmap_host_details.txt -iL /tmp/hosts_ativos.txt
        grep -E "^Nmap scan report|MAC Address|OS details|Device type" /tmp/nmap_host_details.txt
    elif command_exists arp-scan; then
        echo "[$] USANDO ARP-SCAN PARA DESCOBRIR HOSTS..."
        sudo arp-scan "$rede" | grep -E "([0-9a-f]{2}:){5}[0-9a-f]{2}" | awk '{print $1}' > /tmp/hosts_ativos.txt
        echo "[$] DISPOSITIVOS ENCONTRADOS:"
        cat /tmp/hosts_ativos.txt
    else
        warn "[!!] NMAP INDISPONÍVEL. Impossível executar varredura."
        return
    fi
}

scan_gateway_ports() {
    local gw_ip=$(get_gateway_ip)
    echo -e "\n[=== SERVIÇOS DETECTADOS NO ROTEADOR ($gw_ip) ===]"
    if command_exists nmap; then
        sudo nmap -sV -Pn -T4 "$gw_ip" -oN /tmp/nmap_gateway.txt
        echo "[$] RESULTADOS:"
        cat /tmp/nmap_gateway.txt
    else
        warn "[!!]IMPOSSÍVEL ESCANEAR GATEWAY: nmap indisponível."
    fi
}

analisa_servicos_gateway() {
    echo -e "\n[[=== ANÁLISE DE RISCOS NO GATEWAY ===]]"
    perl -ne '
        if (/(\d+)\/tcp\s+open\s+(\S+)\s+(.*)/) {
            my ($porta, $servico, $banner) = ($1, $2, $3);
            my $nivel = "OK";
            my $sugestao = "-";

            if ($servico =~ /telnet/i || $porta == 23) {
                $nivel = "ALTO";
                $sugestao = "Porta Telnet detectada. Sugestão: BLOQUEIO DA PORTA 23.";
            } elsif ($servico =~ /ssh/i) {
                $nivel = "MODERADO";
                if ($banner =~ /dropbear/i) {
                    $sugestao = "Dropbear detectado. Sugestão: BLOQUEIO DA PORTA 22.";
                } else {
                    $sugestao = "SSH ativo. Sugestão: SE NÃO USADO INTERNAMENTE, EFETUE O BLOQUEIO DA PORTA 22.";
                }
            } elsif ($servico =~ /upnp/i) {
                $nivel = "ALTO";
                $sugestao = "UPnP detectado. Risco de abertura automática de portas. Sugestão: BLOQUEIO DE PORTA.";
            } elsif ($banner =~ /TR-069/i || $banner =~ /ACS/) {
                $nivel = "ALTO";
                $sugestao = "TR-069 detectado (GERÊNCIA REMOTA DE ISP), pode gerar abuso. Sugestão: BLOQUEIO DE PORTA.";
            }

            printf("PORTA %s: %s (%s)\n -> NÍVEL DE RISCO: %s\n -> AÇÃO SUGERIDA: %s\n\n", $porta, $servico, $banner, $nivel, $sugestao);
        }
    ' /tmp/nmap_gateway.txt > /tmp/analise_gateway.txt
    cat /tmp/analise_gateway.txt
}

gera_comandos_sugeridos() {
    echo -e "\n[$] GERANDO COMANDOS SUGERIDOS COM BASE NA ANÁLISE..."
    local gw_ip=$(get_gateway_ip)
    > /tmp/comandos_sugeridos.txt

    grep -i "Porta" /tmp/analise_gateway.txt | while read linha; do
        porta=$(echo "$linha" | awk '{print $2}')
        servico=$(echo "$linha" | awk '{print $3}')
        risco=$(echo "$linha" | grep -A1 "Nível de risco" | grep -oP 'risco: \K.*')

        if [[ "$risco" == "ALTO" || "$servico" =~ telnet|dropbear|upnp|tr-069 ]]; then
            echo "- BLOQUEAR TRÁFEGO PARA GATEWAY NA PORTA $porta VIA IPTABLES:" >> /tmp/comandos_sugeridos.txt
            echo "  sudo iptables -A OUTPUT -p tcp --dport $porta -d $gw_ip -j REJECT" >> /tmp/comandos_sugeridos.txt
            echo "" >> /tmp/comandos_sugeridos.txt
            echo "- ALTERNATIVA::UFW:" >> /tmp/comandos_sugeridos.txt
            echo "  sudo ufw deny out to $gw_ip port $porta proto tcp" >> /tmp/comandos_sugeridos.txt
            echo "" >> /tmp/comandos_sugeridos.txt
        fi
    done
}

gera_relatorio_md() {
    echo -e "\n[$] GERANDO RELATÓRIO EM MARKDOWN: $REPORT_MD"
    echo "# RELATÓRIO DE SEGURANÇA DE REDE LOCAL" > "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "## INFORMAÇÕES GERAIS" >> "$REPORT_MD"
    cat "$TMP_DATA" | sed 's/^/- /' >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "## DISPOSITIVOS ENCONTRADOS" >> "$REPORT_MD"
    if [[ -f /tmp/hosts_ativos.txt ]]; then
        awk '{print "- " $0}' /tmp/hosts_ativos.txt >> "$REPORT_MD"
    else
        echo "- NENHUM DISPOSITIVO ENCONTRADO." >> "$REPORT_MD"
    fi
    echo "" >> "$REPORT_MD"
    echo "## ANÁLISE DE SERVIÇOS DO GATEWAY" >> "$REPORT_MD"
    cat /tmp/analise_gateway.txt >> "$REPORT_MD"
    echo "" >> "$REPORT_MD"
    echo "## COMANDOS SUGERIDOS (iptables, ufw)" >> "$REPORT_MD"
    cat /tmp/comandos_sugeridos.txt >> "$REPORT_MD"
}

gera_relatorio_json() {
    echo -e "\n[$] GERANDO RELATÓRIO EM JSON: $REPORT_JSON"
    {
        echo "{"
        echo "  \"ip_local\": \"$(get_local_ip)\"," 
        echo "  \"gateway_ip\": \"$(get_gateway_ip)\"," 
        echo "  \"gateway_mac\": \"$(get_gateway_mac)\"," 
        echo "  \"dns\": \"$(get_dns_servers | paste -sd "," -)\"," 
        echo "  \"dispositivos\": ["
        if [[ -f /tmp/hosts_ativos.txt ]]; then
            awk '{printf "    \"%s\",\n", $0}' /tmp/hosts_ativos.txt | sed '$s/,$//'
        fi
        echo "  ],"
        echo "  \"analise_gateway\": ["
        awk '/^Porta/{printf "    {\"porta\": \"%s\", \"servico\": \"%s\"},\n", $2, $3}' /tmp/analise_gateway.txt | sed '$s/,$//'
        echo "  ]"
        echo "}"
    } > "$REPORT_JSON"
}

consulta_online() {
    if [[ "$ONLINE_MODE" -eq 1 ]]; then
        echo -e "\n[$] MODO ONLINE SELECIONADO ==> COLETANDO INFORMAÇÕES PÚBLICAS......"
        if command_exists curl; then
            IPPUB=$(curl -s https://api.ipify.org)
            echo "[!!]IP PÚBLICO DETECTADO: $IPPUB"
            echo "- Para verificar possíveis abusos, acesse:"
            echo "  https://www.abuseipdb.com/check/$IPPUB"
            echo "  https://virustotal.com/gui/ip-address/$IPPUB"
            echo "" >> "$REPORT_MD"
            echo "## IP PÚBLICO E CHECAGENS ONLINE" >> "$REPORT_MD"
            echo "- IP Público: $IPPUB" >> "$REPORT_MD"
            echo "- AbuseIPDB: https://www.abuseipdb.com/check/$IPPUB" >> "$REPORT_MD"
            echo "- VirusTotal: https://virustotal.com/gui/ip-address/$IPPUB" >> "$REPORT_MD"
        else
            warn "[!!] CURL INDISPONÍVEL PARA CONSULTA. POR FAVOR, VERIFIQUE."
        fi
    fi
}

monitorar_trafego_dns() {
    echo -e "\n[$] CAPTURANDO TRÁFEGO DNS por 50 segundos..."
    if command_exists tcpdump; then
        sudo timeout 50 tcpdump -n port 53 -vv -i any > /tmp/dns_trafego.txt
        echo "[$] RESUMO DE REQUISIÇÕES DNS DURANTE O PERÍODO:
"
        grep "A?" /tmp/dns_trafego.txt | awk '{print $NF}' | sort | uniq -c | sort -nr | head
    else
        warn "[!!] TCPDUMP INDISPONÍVEL. IMPOSSÍVEL CAPTURAR TRÁFEGO DNS."
    fi
}

verificar_arp_spoofing() {
    echo -e "\n[$] VERIFICANDO POSSÍVEIS CONFLITOS ARP (SPOOFING)....."
    arp -a | awk '{print $1, $2, $3}' | sort | uniq -d > /tmp/arp_conflicts.txt
    if [[ -s /tmp/arp_conflicts.txt ]]; then
        echo "[!!] POSSÍVEIS CONFLITOS OU SPOOFING DETECTADOS:"
        cat /tmp/arp_conflicts.txt
    else
        echo "[$] NENHUM CONFLITO ARP EVIDENTE DETECTADO."
    fi
}

main() {
    menu_principal
    echo "[$] INICIANDO ANÁLISE DA REDE LOCAL......"
    coleta_inicial
    scan_dispositivos
    scan_gateway_ports
    analisa_servicos_gateway
    gera_comandos_sugeridos
    monitorar_trafego_dns
    verificar_arp_spoofing
    gera_relatorio_md
    gera_relatorio_json
    consulta_online
    echo "[$] ANÁLISE FINALIZADA."
    echo "[$] RELATÓRIOS GERADOS:"
    echo "   → $REPORT_MD"
    echo "   → $REPORT_JSON"
}

main "$@"
