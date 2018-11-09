#!/bin/bash

# sudo cp nse/ms-sql-instance /usr/share/nmap/scripts
# sudo nmap --script-updatedb
sudo nmap -T4 -p1433 -sS --open X.X.X-X.X-X | grep -P 'Nmap scan report for' |  sed -n 's/.*(\(.*\)).*/\1/p' | xargs -L1 sudo nmap -p 1433 --script ms-sql-instance $1
