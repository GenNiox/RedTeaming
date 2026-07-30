Requirements:
  [ ] Configure /etc/proxychains4.conf
      [ ] Comment-out "strict_chain"
      [ ] Enable "dynamic_chain"
      [ ] sudo systemctl restart proxychains
  [ ] Install tor and enable it
      [ ] sudo apt install tor -y
      [ ] sudo systemctl start tor
          NOTE: This is a requirement each time that you reboot Kali, unless you want the Tor listener on at all times!
              [ ] Alternative: sudo systemctl enable --now tor

To Install:
  [ ] sudo mkdir /opt/torminal
  [ ] Copy files into /opt/torminal
  [ ] sudo chown root:root /opt/torminal
  [ ] sudo chmod +x /opt/torminal
  [ ] sudo ln -s /opt/torminal/torminal.sh /usr/bin/torminal
  [ ] You can just type-in "torminal" at this point and it'll take over from there.

  Anything executed within this window as that user (i.e. kali@kali or root@kali) will be within the Tor network!
  To get root permissions, just "sudo torminal" so it starts within root@kali instead of kali@kali.
  No more needing to type-in "proxychains" before everything. 
