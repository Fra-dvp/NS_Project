FROM ubuntu:latest

RUN apt-get update -y && apt-get install -y --no-install-recommends apt-utils 
RUN apt-get install hping3 -y && apt install nano -y && apt install telnet -y && apt-get install python3 -y && apt-get install scapy -y 
RUN apt-get install python3-pip -y && apt-get install nmap -y && apt-get install netcat
RUN pip install --pre scapy[complete] && pip install pyfiglet && pip install python-nmap && apt-get install net-tools -y && apt-get install iputils-ping -y

ADD Scanning.py /
ADD pyscript.py /
