systemctl disable Persistence_Service
systemctl stop Persistence_Service && rm -Rf /srv/Persistence_Service && rm -f /etc/systemd/system/Persistence_Service.service
systemctl daemon-reload
