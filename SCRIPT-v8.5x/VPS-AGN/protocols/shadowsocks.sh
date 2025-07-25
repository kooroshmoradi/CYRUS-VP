#!/bin/bash
#25/01/2021
clear
clear
declare -A cor=( [0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m" )
SCPdir="/etc/VPS-AGN"
SCPfrm="${SCPdir}/tools" && [[ ! -d ${SCPfrm} ]] && exit
SCPinst="${SCPdir}/protocols"&& [[ ! -d ${SCPinst} ]] && exit
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
MEU_IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
MEU_IP2=$(wget -qO- ipv4.icanhazip.com)
[[ "$MEU_IP" != "$MEU_IP2" ]] && IP="$MEU_IP2" || IP="$MEU_IP"
}
fun_eth () {
eth=$(ifconfig | grep -v inet6 | grep -v lo | grep -v 127.0.0.1 | grep "encap:Ethernet" | awk '{print $1}')
    [[ $eth != "" ]] && {
    msg -bar
    echo -e "${cor[3]} $(fun_trans ${id} "Apply System To Enhance SSH Packets?")"
    echo -e "${cor[3]} $(fun_trans ${id} "Option For Advanced Users")"
    msg -bar
    read -p " [S/N]: " -e -i n sshsn
           [[ "$sshsn" = @(s|S|y|Y) ]] && {
           echo -e "${cor[1]} $(fun_trans ${id} "Fix packet problems in SSH...")"
           echo -e " $(fun_trans ${id} "What is the RX Rate")"
           echo -ne "[ 1 - 999999999 ]: "; read rx
           [[ "$rx" = "" ]] && rx="999999999"
           echo -e " $(fun_trans ${id} "What is the TX Rate")"
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
   for((i=0; i<10; i++)); do
   echo -ne "\033[1;31m##"
   sleep 0.2
   done
echo -ne "\033[1;33m]"
sleep 1s
echo
tput cuu1
tput dl1
done
echo -e " \033[1;33m[\033[1;31m####################\033[1;33m] - \033[1;32m100%\033[0m"
sleep 1s
}
fun_shadowsocks () {
[[ -e /etc/shadowsocks.json ]] && {
[[ $(ps x|grep ssserver|grep -v grep|awk '{print $1}') != "" ]] && kill -9 $(ps x|grep ssserver|grep -v grep|awk '{print $1}') > /dev/null 2>&1 && ssserver -c /etc/shadowsocks.json -d stop > /dev/null 2>&1
echo -e "\033[1;33m $(fun_trans ${id} "SHADOWSOCKS STOPPED")"
msg -bar
rm /etc/shadowsocks.json
return 0
}
       while true; do
	   msg -bar
	   msg -tit
	   msg -ama "        SHADOWSOCKS INSTALLER By @kooroshmoradi"
	   msg -bar
       echo -e "\033[1;33m $(fun_trans ${id} "Select a Crypto")"
	   msg -bar
       encript=(aes-256-gcm aes-192-gcm aes-128-gcm aes-256-ctr aes-192-ctr aes-128-ctr aes-256-cfb aes-192-cfb aes-128-cfb camellia-128-cfb camellia-192-cfb camellia-256-cfb chacha20-ietf-poly1305 chacha20-ietf chacha20 rc4-md5)
       for((s=0; s<${#encript[@]}; s++)); do
       echo -e " [${s}] - ${encript[${s}]}"
       done
       msg -bar
       while true; do
       unset cript
       read -p "Choose a Crypto: " -e -i 0 cript
       [[ ${encript[$cript]} ]] && break
       echo -e "$(fun_trans ${id} "Invalid Option")"
       done
       encriptacao="${encript[$cript]}"
       [[ ${encriptacao} != "" ]] && break
       echo -e "$(fun_trans ${id} "Invalid Option")"
      done
#ESCOLHENDO LISTEN
msg -bar
      echo -e "\033[1;33m $(fun_trans ${id} "Select port for the Shadowsocks Listen")\033[0m"
	  msg -bar
      while true; do
      unset Lport
      read -p " Port: " Lport
      [[ $(mportas|grep "$Lport") = "" ]] && break
      echo -e " ${Lport}: $(fun_trans ${id} "invalid port")"      
      done
#INICIANDO
msg -bar
echo -e "\033[1;33m $(fun_trans ${id} "Enter the password Shadowsocks")\033[0m"
read -p" Password: " Pass
msg -bar
echo -e "\033[1;33m $(fun_trans ${id} "Starting Installation")"
msg -bar
fun_bar 'sudo apt-get install shadowsocks -y'
fun_bar 'sudo apt-get install libsodium-dev -y'
fun_bar 'sudo apt-get install python-pip -y'
fun_bar 'sudo pip install --upgrade setuptools'
fun_bar 'pip install --upgrade pip -y'
fun_bar 'pip install https://github.com/shadowsocks/shadowsocks/archive/master.zip -U'
echo -ne '{\n"server":"' > /etc/shadowsocks.json
echo -ne "0.0.0.0" >> /etc/shadowsocks.json
echo -ne '",\n"server_port":' >> /etc/shadowsocks.json
echo -ne "${Lport},\n" >> /etc/shadowsocks.json
echo -ne '"local_port":1080,\n"password":"' >> /etc/shadowsocks.json
echo -ne "${Pass}" >> /etc/shadowsocks.json
echo -ne '",\n"timeout":600,\n"method":"' >> /etc/shadowsocks.json
echo -ne "${encriptacao}" >> /etc/shadowsocks.json
echo -ne '"\n}' >> /etc/shadowsocks.json
msg -bar
echo -e "\033[1;31m STARTING\033[0m"
ssserver -c /etc/shadowsocks.json -d start > /dev/null 2>&1
value=$(ps x |grep ssserver|grep -v grep)
[[ $value != "" ]] && value="\033[1;32mSTARTED SUCCESSFULLY" || value="\033[1;31mERROR"
msg -bar
echo -e "${value}"
msg -bar
return 0
}
fun_shadowsocks