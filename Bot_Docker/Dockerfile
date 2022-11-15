FROM ubuntu:20.04


RUN apt-get update && apt-get install -y --no-install-recommends apt-utils
RUN apt-get install systemctl -y
RUN apt-get install ufw -y
RUN apt-get install iptables sudo -y
RUN apt-get install hping3 -y
RUN apt-get install nano -y
RUN apt-get install telnetd xinetd telnet update-inetd net-tools -y 
RUN apt-get install python3 -y
RUN apt-get install pip -y 
RUN apt-get install apache2 -y
RUN apt-get install netcat -y 
RUN apt-get clean

RUN adduser -gecos -disabled-password --shell /bin/bash telnet 

#RUN systemctl status xinetd.service
#ADD telnet /etc/xinetd.d
#RUN systemctl restart xinetd.service
#RUN ufw allow 23 
#RUN ufw reload

RUN echo "root:root" | chpasswd
EXPOSE 23

ADD telnet /etc/xinetd.d
RUN systemctl restart xinetd.service
RUN ufw allow 23 
RUN ufw reload
RUN systemctl start xinetd.service

#CMD systemctl start xinetd.service
#CMD [ "systemctl",  "start", "xinetd.service" ]
#CMD systemctl start xinetd.service
#dopo l'avvio fare run dell'ultimo comando e telnet server funziona.






