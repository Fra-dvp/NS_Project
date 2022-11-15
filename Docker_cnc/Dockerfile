FROM ubuntu:latest

#RUN apt-get update && apt-get install -y --no-install-recommends apt-utils && apt-get upgrade
#RUN apt-get install ufw -y
#RUN apt-get install iptables sudo -y
#RUN apt-get install hping3 -y
#RUN apt-get install nano -y
#RUN apt-get install telnetd xinetd telnet update-inetd net-tools -y 
#RUN apt-get install netcat -y

RUN apt-get update && apt-get install -y --no-install-recommends apt-utils && apt-get upgrade && apt-get install ufw -y && apt-get install iptables sudo -y && apt-get install hping3 -y && apt-get install nano -y && apt-get install telnetd xinetd telnet update-inetd net-tools -y  && apt-get install netcat -y

#mi metto in ascolto sulla porta 1025 con netcat e salvo sul file vulnerableIP.txt (in append, perciò doppio >>) -> il -k è per lasciare sempre in attesa 
#di nuovi messaggi, la parte finale per scrivere nel file di testo

#CMD nc -l -k -p 1025 >> vulnerableIP.txt 

