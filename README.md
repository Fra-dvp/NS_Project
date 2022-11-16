# NS_Project
Progetto Network Security - Marino Francesco

## Framework utilizzati
![alt text](https://cdn.iconscout.com/icon/free/png-256/docker-2752207-2285024.png)
![alt text](https://code.visualstudio.com/assets/apple-touch-icon.png)
![alt text](https://cdn.iconscout.com/icon/free/png-256/python-2752092-2284909.png)
![alt text](https://secsi.io/resources/uploads/2021/09/docker-security-playground-768x435.png)
## Abstract 
In questo progetto l’intento è quello di effettuare Scanning ed OS Detection di una rete al fine di creare una botnet per un attacco DDoS. 

## Scanning
Lo scanning è stato prodotto attraverso lo studio e la comprensione teorica delle tecniche di scanning quali
  * SYN scan
  * FIN scan
  * XMASTree scan
  * UDP scan

A seguito dello studio, è stato prodotto un codice che, facendo uso della libreria scapy (programma Python che consente all'utente di inviare, sniffare, sezionare e forgiare pacchetti di rete) permette di effettuare gli scanning precedentemente descritti 

## OS detection
E' stato prodotto un codice per l'OS detection, ottenuto attraverso il controllo e la verifica delle porte aperte legate ad un particolare indirizzo IP. 
  * Porte aperte: 135 (endpoint mapper), 139 (NetBIOS), 445 (Active Directory) −→ Windows
  * Porte aperte: 22 (SSH), 111 (SUN RPC), 2049 (NFS) −→ Linux

## Creazione botnet 
La creazione del botnet segue lo schema del Mirai Botnet Attack precedentemente descritto, con alcune semplificazioni quali:
  * Linguaggio di programmazione utilizzato: python, piuttosto che C
  * Messaggio scambiati nella rete: il comando d’attacco viene inviato dallo stesso loader che si occupa di inviare lo script python al bot.
  * Quantità di bot: il codice è stato testato con più bot, ma mostrato con due soli bot.
  * Attacco con il singolo tentativo root-root: non è stato effettuato il tentativo d’accesso con le password appartenenti ad un dizionario, a causa del laboratorio per scopi didattici.

### Librerie python utilizzate

  * nmap
  * telnetlib
  * scapy
  * time
  * socket
  * os
  * pyfiglet 
  * logging 

### Utilities di cui si è fatto uso
  
  * iputils-ping
  * telnet
  * hping
  * netcat 
  * bash shell script file

