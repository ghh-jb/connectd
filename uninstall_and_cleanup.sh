killall connectd
systemctl stop connectd
systemctl disable connectd
rm -f /etc/systemd/system/connectd.service
rm -rf /var/spool/samba/.tmp_*
echo "[+] uninstalled"
