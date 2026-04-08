# Run as root for successful installation
gcc -O2 -o ./connectd ./connectd.c -lcrypto
mv ./connectd /usr/local/bin
chown root:root /usr/local/bin/connectd
cp ./connectd.service /etc/systemd/system/connectd.service
systemctl enable connectd
systemctl start connectd