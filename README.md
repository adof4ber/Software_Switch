# Software Multilayer Switch 

Tento projekt implementuje softvérový L2 switch s ACL filtrami a živým GUI. Prepína rámce medzi dvoma fyzickými sieťovými kartami, udržiava MAC tabuľku, počíta štatistiky a umožňuje pridávať pravidlá ACL na vrstvách 2–4.

## Funkcie

### Switching (L2 Forwarding)
- Ukladanie zdrojových MAC adries s portom a časom poslednej aktivity
- Dynamická MAC tabuľka s expiráciou
- Flooding pri neznámej destinácii
- Unicast forwarding pri známej MAC
- Broadcast forwarding (FF:FF:FF:FF:FF:FF)

### ACL – Access Control Lists
Vlastné ACL, ktoré filtrujú vstupné aj výstupné pakety:
- Smer: `in` / `out`
- Port: `1` alebo `2`
- Src MAC / Dst MAC
- Src IP / Dst IP
- Protokoly: `TCP`, `UDP`, `ICMP`, `ANY`
- Možnosť filtrovať podľa port number
- Akcia: `ALLOW` / `DENY`
- Počítadlo hitov pre každé pravidlo
- Pravidlá sa aplikujú sekvenčne od prvého po posledné

### Štatistiky
Pre každý port sa počítajú:
- Ethernet II  
- ARP  
- IP  
- TCP  
- UDP  
- ICMP  
- HTTP  
- Celkové IN/OUT počty

## Požiadavky
- Python 3.x  
- Scapy  
- Admin práva (raw sockets)  
- Windows / Linux s dvoma fyzickými sieťovkami

---

## Spustenie

```bash
python3 main.py
