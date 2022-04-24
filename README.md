# VUT FIT 2021/22 IPK Projekt 2 - variant Zeta: Sniffer Packetov
Tento program je napísaný v jazyku C a slúži na analýzu packetov na sieti. Program podporuje IPv4 aj IPv6 a umožňuje filtrovanie na základe čísla portu a typu packetov. 

# Preklad programu
Na preklad programu je pripravený súbor Makefile a teda stačí spustiť nasledujúci príkaz:
```make```

# Spúšťanie programu
Nakoľko je možné, že na sledovanie packetov na sieti budú potrebné super user práva, je odporúčané ho spúšťať so `sudo`. Pre samotné spustenie použite:

```./ipk-sniffer [-i rozhranie | --interface rozhranie] {-p číslo_portu} {[--tcp|-t] [--udp|-u] [--arp] [--icmp]} {-n číslo}```

Popis prepínačov je nasledovný:
* -i / --interface rozhranie    - Slúži na výber rozhrania, na ktorom budú packety sledované. Ak nie je uvedený, na štandardný výstup budú vypísané dostupné aktívne rozhrania.
* -p číslo_portu                - Voliteľný prepínač na zvolenie čísla portu pre filtrovanie.
* --tcp/-t                      - Voliteľný prepínač na pridanie protokolu TCP do filtru.
* --udp/-u                      - Voliteľný prepínač na pridanie protokolu UDP do filtru. 
* --arp                         - Voliteľný prepínač na pridanie protokolu ARP do filtru. 
* --icmp                        - Voliteľný prepínač na pridanie protokolu ICMP do filtru.
* --n číslo                     - Voliteľný prepínač na nastavenie počtu packetov, ktoré by mali byť zachytené pred ukončením programu. Default hodnota je 1.

Prepínače na úpravu filtrovania môžu byť ľubovoľne kombinované, a ak nie je zadaný žiaden z nich, získavajú sa všetky packety.

# Zoznam odovzdaných súborov
* Makefile      - Súbor, umožňujúci automatizovaný preklad pomocou `make`
* ipk_sniffer.h - Hlavičkový súbor obsahujúci deklarácie pre program
* ipk_sniffer.c - Súbor obsahujúci samotnú implementáciu programu
* README.md     - Tento súbor
* manual.pdf    - Dokumentácia ku projektu

