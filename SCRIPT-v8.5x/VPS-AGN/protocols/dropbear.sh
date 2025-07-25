#!/bin/bash
#25/01/2021
clear
clear
SCPdir="/etc/VPS-AGN"
SCPfrm="${SCPdir}/tools" && [[ ! -d ${SCPfrm} ]] && exit
SCPinst="${SCPdir}/protocols"&& [[ ! -d ${SCPinst} ]] && exit
declare -A cor=( [0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m" )
mportas () {
unset portas
portas_var=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" |grep -v "COMMAND" | grep "LISTEN")
while read port; do
var1=$(echo $port | awk '{print $1}') && var2=$(echo $port | awk '{print $9}' | awk -F ":" '{print $2}')
[[ "$(echo -e $portas|grep "$var1 $var2")" ]] || portas+="$var1 $var2\n"
done <<< "$portas_var"
i=1
echo -e "$portas"
}
fun_ip () {
if [[ -e /etc/VPS-AGN/MEUIPvps ]]; then
IP="$(cat /etc/VPS-AGN/MEUIPvps)"
else
MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
[[ "$MEU_IP" != "$MEU_IP" ]] && IP="$MEU_IP2" || IP="$MEU_IP"
echo "$MEU_IP" > /etc/VPS-AGN/MEUIPvps
fi
}
fun_eth () {
eth=$(ifconfig | grep -v inet6 | grep -v lo | grep -v 127.0.0.1 | grep "encap:Ethernet" | awk '{print $1}')
    [[ $eth != "" ]] && {
    msg -bar
    echo -e "${cor[3]} $(fun_trans "Apply Enhancements to Improve SSH Packets?")"
    echo -e "${cor[3]} $(fun_trans "Option For Advanced Users")"
    msg -bar
    read -p " [S/N]: " -e -i n sshsn
           [[ "$sshsn" = @(s|S|y|Y) ]] && {
           echo -e "${cor[1]} $(fun_trans "Correction of packet problems in SSH...")"
           echo -e " $(fun_trans "What is the RX rate")"
           echo -ne "[ 1 - 999999999 ]: "; read rx
           [[ "$rx" = "" ]] && rx="999999999"
           echo -e " $(fun_trans "What is the TX rate")"
           echo -ne "[ 1 - 999999999 ]: "; read tx
           [[ "$tx" = "" ]] && tx="999999999"
           apt-get install ethtool -y > /dev/null 2>&1
           ethtool -G $eth rx $rx tx $tx > /dev/null 2>&1
           }
     msg -bar
     }
}

fun_bar () {
comando="$1"
 _=$(
$comando > /dev/null 2>&1
) & > /dev/null
pid=$!
while [[ -d /proc/$pid ]]; do
echo -ne " \033[1;33m["
   for((i=0; i<20; i++)); do
   echo -ne "\033[1;31m##"
   sleep 0.8
   done
echo -ne "\033[1;33m]"
sleep 1s
echo
tput cuu1 && tput dl1
done
echo -ne " \033[1;33m[\033[1;31m########################################\033[1;33m] - \033[1;32m100%\033[0m\n"
sleep 1s
}
fun_dropbear () {
 [[ -e /etc/default/dropbear ]] && {
 msg -bar
 echo -e "\033[1;32m $(fun_trans ${id} "REMOVING DROPBEAR")"
 msg -bar
 service dropbear stop & >/dev/null 2>&1
 fun_bar "apt-get remove dropbear -y"
 msg -bar
 echo -e "\033[1;32m $(fun_trans "Dropbear Removed")"
 msg -bar
 [[ -e /etc/default/dropbear ]] && rm /etc/default/dropbear
 return 0
 }
msg -bar
msg -tit
echo -e "\033[1;32m $(fun_trans "   DROPBEAR INSTALLER | VPS-AGN By @kooroshmoradi")"
msg -bar
echo -e "\033[1;31m $(fun_trans "Select Validated Ports in sequential order:\n")\033[1;32m 22 80 81 82 85 90\033[1;37m"
msg -bar
echo -ne "\033[1;31m $(fun_trans "Type Ports"): \033[1;37m" && read DPORT
tput cuu1 && tput dl1
TTOTAL=($DPORT)
    for((i=0; i<${#TTOTAL[@]}; i++)); do
        [[ $(mportas|grep "${TTOTAL[$i]}") = "" ]] && {
        echo -e "\033[1;33m $(fun_trans  "Chosen Port:")\033[1;32m ${TTOTAL[$i]} OK"
        PORT="$PORT ${TTOTAL[$i]}"
        } || {
        echo -e "\033[1;33m $(fun_trans  "Chosen Port:")\033[1;31m ${TTOTAL[$i]} FAIL"
        }
   done
  [[  -z $PORT ]] && {
  echo -e "\033[1;31m $(fun_trans  "No Valid Port Was Chosen")\033[0m"
  return 1
  }
sysvar=$(cat -n /etc/issue |grep 1 |cut -d' ' -f6,7,8 |sed 's/1//' |sed 's/      //' | grep -o Ubuntu)
[[ ! $(cat /etc/shells|grep "/bin/false") ]] && echo -e "/bin/false" >> /etc/shells
[[ "$sysvar" != "" ]] && {
echo -e "Port 22
Protocol 2
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes" > /etc/ssh/sshd_config
msg -bar
echo -e "${cor[2]} $(fun_trans ${id} "Installing dropbear")"
msg -bar
fun_bar "apt-get install dropbear -y"
apt-get install dropbear -y > /dev/null 2>&1
msg -bar
touch /etc/dropbear/banner
msg -bar
echo -e "${cor[2]} $(fun_trans ${id} "Configuring dropbear")"
cat <<EOF > /etc/default/dropbear
NO_START=0
DROPBEAR_EXTRA_ARGS="VAR"
DROPBEAR_BANNER="/etc/dropbear/banner"
DROPBEAR_RECEIVE_WINDOW=65536
EOF
for dpts in $(echo $PORT); do
sed -i "s/VAR/-p $dpts VAR/g" /etc/default/dropbear
done
sed -i "s/VAR//g" /etc/default/dropbear
} || {
echo -e "Port 22
Protocol 2
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes" > /etc/ssh/sshd_config
echo -e "${cor[2]} $(fun_trans  "Installing dropbear")"
msg -bar
fun_bar "apt-get install dropbear -y"
touch /etc/dropbear/banner
msg -bar
echo -e "${cor[2]} $(fun_trans  "Configuring dropbear")"
msg -bar
cat <<EOF > /etc/default/dropbear
NO_START=0
DROPBEAR_EXTRA_ARGS="VAR"
DROPBEAR_BANNER="/etc/dropbear/banner"
DROPBEAR_RECEIVE_WINDOW=65536
EOF
for dpts in $(echo $PORT); do
sed -i "s/VAR/-p $dpts VAR/g" /etc/default/dropbear
done
sed -i "s/VAR//g" /etc/default/dropbear
}
fun_eth
service ssh restart > /dev/null 2>&1
service dropbear restart > /dev/null 2>&1
echo -e "${cor[3]} $(fun_trans "Your dropbear has been configured SUCCESSFULLY")"
msg -bar
#UFW
for ufww in $(mportas|awk '{print $2}'); do
ufw allow $ufww > /dev/null 2>&1
done
}
fun_dropbear