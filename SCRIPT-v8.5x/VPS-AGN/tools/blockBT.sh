#!/bin/bash
 #19/12/19
 PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
 export PATH
 declare -A cor=( [0]="\033[1;37m" [1]="\033[1;34m" [2]="\033[1;31m" [3]="\033[1;33m" [4]="\033[1;32m" )
 SCPdir="/etc/VPS-AGN" && [[ ! -d ${SCPdir} ]] && exit 1
 SCPusr="${SCPdir}/controller" && [[ ! -d ${SCPusr} ]] && mkdir ${SCPusr}
 SCPfrm="${SCPdir}/tools" && [[ ! -d ${SCPfrm} ]] && mkdir ${SCPfrm}
 SCPinst="${SCPdir}/protocols" && [[ ! -d ${SCPfrm} ]] && mkdir ${SCPfrm}
 
 sh_ver="1.0.11"
 Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
 Info="${Green_font_prefix}[Info]${Font_color_suffix}"
 Error="${Red_font_prefix}[Error]${Font_color_suffix}"
 
 smtp_port="25,26,465,587"
 pop3_port="109,110,995"
 imap_port="143,218,220,993"
 other_port="24,50,57,105,106,158,209,1109,24554,60177,60179"
 bt_key_word="torrent
 .torrent
 peer_id=
 announce
 info_hash
 get_peers
 find_node
 BitTorrent
 announce_peer
 BitTorrent protocol
 announce.php?passkey=
 magnet:
 xunlei
 sandai
 Thunder
 XLLiveUD"
 
 check_sys(){
 	if [[ -f /etc/redhat-release ]]; then
 		release="centos"
 	elif cat /etc/issue | grep -q -E -i "debian"; then
 		release="debian"
 	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
 		release="ubuntu"
 	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
 		release="centos"
 	elif cat /proc/version | grep -q -E -i "debian"; then
 		release="debian"
 	elif cat /proc/version | grep -q -E -i "ubuntu"; then
 		release="ubuntu"
 	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
 		release="centos"
     fi
 	bit=`uname -m`
 }
 check_BT(){
 	Cat_KEY_WORDS
 	BT_KEY_WORDS=$(echo -e "$Ban_KEY_WORDS_list"|grep "torrent")
 }
 check_SPAM(){
 	Cat_PORT
 	SPAM_PORT=$(echo -e "$Ban_PORT_list"|grep "${smtp_port}")
 }
 Cat_PORT(){
 	Ban_PORT_list=$(iptables -t filter -L OUTPUT -nvx --line-numbers|grep "REJECT"|awk '{print $13}')
 }
 Cat_KEY_WORDS(){
 	Ban_KEY_WORDS_list=""
 	Ban_KEY_WORDS_v6_list=""
 	if [[ ! -z ${v6iptables} ]]; then
 		Ban_KEY_WORDS_v6_text=$(${v6iptables} -t mangle -L OUTPUT -nvx --line-numbers|grep "DROP")
 		Ban_KEY_WORDS_v6_list=$(echo -e "${Ban_KEY_WORDS_v6_text}"|sed -r 's/.*\"(.+)\".*/\1/')
 	fi
 	Ban_KEY_WORDS_text=$(${v4iptables} -t mangle -L OUTPUT -nvx --line-numbers|grep "DROP")
 	Ban_KEY_WORDS_list=$(echo -e "${Ban_KEY_WORDS_text}"|sed -r 's/.*\"(.+)\".*/\1/')
 }
 View_PORT(){
 	Cat_PORT
 	echo -e "========${Red_background_prefix} Port Currently Blocked ${Font_color_suffix}========="
 	echo -e "$Ban_PORT_list" && echo && echo -e "==============================================="
 }
 View_KEY_WORDS(){
 	Cat_KEY_WORDS
 	echo -e "============${Red_background_prefix} Currently Banned ${Font_color_suffix}============"
 	echo -e "$Ban_KEY_WORDS_list" && echo -e "==============================================="
 }
 View_ALL(){
 	echo
 	View_PORT
 	View_KEY_WORDS
 	echo
 	msg -bar2
 }
 Save_iptables_v4_v6(){
 	if [[ ${release} == "centos" ]]; then
 		if [[ ! -z "$v6iptables" ]]; then
 			service ip6tables save
 			chkconfig --level 2345 ip6tables on
 		fi
 		service iptables save
 		chkconfig --level 2345 iptables on
 	else
 		if [[ ! -z "$v6iptables" ]]; then
 			ip6tables-save > /etc/ip6tables.up.rules
 			echo -e "#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules" > /etc/network/if-pre-up.d/iptables
 		else
 			echo -e "#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules" > /etc/network/if-pre-up.d/iptables
 		fi
 		iptables-save > /etc/iptables.up.rules
 		chmod +x /etc/network/if-pre-up.d/iptables
 	fi
 }
 Set_key_word() { $1 -t mangle -$3 OUTPUT -m string --string "$2" --algo bm --to 65535 -j DROP; }
 Set_tcp_port() {
 	[[ "$1" = "$v4iptables" ]] && $1 -t filter -$3 OUTPUT -p tcp -m multiport --dports "$2" -m state --state NEW,ESTABLISHED -j REJECT --reject-with icmp-port-unreachable
 	[[ "$1" = "$v6iptables" ]] && $1 -t filter -$3 OUTPUT -p tcp -m multiport --dports "$2" -m state --state NEW,ESTABLISHED -j REJECT --reject-with tcp-reset
 }
 Set_udp_port() { $1 -t filter -$3 OUTPUT -p udp -m multiport --dports "$2" -j DROP; }
 Set_SPAM_Code_v4(){
 	for i in ${smtp_port} ${pop3_port} ${imap_port} ${other_port}
 		do
 		Set_tcp_port $v4iptables "$i" $s
 		Set_udp_port $v4iptables "$i" $s
 	done
 }
 Set_SPAM_Code_v4_v6(){
 	for i in ${smtp_port} ${pop3_port} ${imap_port} ${other_port}
 	do
 		for j in $v4iptables $v6iptables
 		do
 			Set_tcp_port $j "$i" $s
 			Set_udp_port $j "$i" $s
 		done
 	done
 }
 Set_PORT(){
 	if [[ -n "$v4iptables" ]] && [[ -n "$v6iptables" ]]; then
 		Set_tcp_port $v4iptables $PORT $s
 		Set_udp_port $v4iptables $PORT $s
 		Set_tcp_port $v6iptables $PORT $s
 		Set_udp_port $v6iptables $PORT $s
 	elif [[ -n "$v4iptables" ]]; then
 		Set_tcp_port $v4iptables $PORT $s
 		Set_udp_port $v4iptables $PORT $s
 	fi
 	Save_iptables_v4_v6
 }
 Set_KEY_WORDS(){
 	key_word_num=$(echo -e "${key_word}"|wc -l)
 	for((integer = 1; integer <= ${key_word_num}; integer++))
 		do
 			i=$(echo -e "${key_word}"|sed -n "${integer}p")
 			Set_key_word $v4iptables "$i" $s
 			[[ ! -z "$v6iptables" ]] && Set_key_word $v6iptables "$i" $s
 	done
 	Save_iptables_v4_v6
 }
 Set_BT(){
 	key_word=${bt_key_word}
 	Set_KEY_WORDS
 	Save_iptables_v4_v6
 }
 Set_SPAM(){
 	if [[ -n "$v4iptables" ]] && [[ -n "$v6iptables" ]]; then
 		Set_SPAM_Code_v4_v6
 	elif [[ -n "$v4iptables" ]]; then
 		Set_SPAM_Code_v4
 	fi
 	Save_iptables_v4_v6
 }
 Set_ALL(){
 	Set_BT
 	Set_SPAM
 }
 Ban_BT(){
 	check_BT
 	[[ ! -z ${BT_KEY_WORDS} ]] && echo -e "${Error} Blocked Torrent and Keywords, no need to ban them again !" && msg -bar2 && exit 0
 	s="A"
 	Set_BT
 	View_ALL
 	echo -e "${Info} Torrent bloqueados y Palabras Claves !"
 	msg -bar2
 }
 Ban_SPAM(){
 	check_SPAM
 	[[ ! -z ${SPAM_PORT} ]] && echo -e "${Error} Blocked SPAM port detected, no need to block again !" && msg -bar2 && exit 0
 	s="A"
 	Set_SPAM
 	View_ALL
 	echo -e "${Info} SPAM Ports Blocked !"
 	msg -bar2
 }
 Ban_ALL(){
 	check_BT
 	check_SPAM
 	s="A"
 	if [[ -z ${BT_KEY_WORDS} ]]; then
 		if [[ -z ${SPAM_PORT} ]]; then
 			Set_ALL
 			View_ALL
 			echo -e "${Info} Blocked Torrent, Keywords and SPAM Ports !"
 			msg -bar2
 		else
 			Set_BT
 			View_ALL
 			echo -e "${Info} Blocked Torrent and Keywords !"
 		fi
 	else
 		if [[ -z ${SPAM_PORT} ]]; then
 			Set_SPAM
 			View_ALL
 			echo -e "${Info} SPAM port (spam) prohibited !"
 		else
 			echo -e "${Error} Blocked Torrent, Keywords and SPAM Ports,\nno need to ban again !" && msg -bar2 && exit 0
 		fi
 	fi
 }
 UnBan_BT(){
 	check_BT
 	[[ -z ${BT_KEY_WORDS} ]] && echo -e "${Error} Torrent and Keywords not blocked, check !"&& msg -bar2 && exit 0
 	s="D"
 	Set_BT
 	View_ALL
 	echo -e "${Info} Unlocked Torrent and Keywords !"
 	msg -bar2
 }
 UnBan_SPAM(){
 	check_SPAM
 	[[ -z ${SPAM_PORT} ]] && echo -e "${Error} SPAM port not detected, check !" && msg -bar2 && exit 0
 	s="D"
 	Set_SPAM
 	View_ALL
 	echo -e "${Info} SPAM Ports Unblocked !"
 	msg -bar2
 }
 UnBan_ALL(){
 	check_BT
 	check_SPAM
 	s="D"
 	if [[ ! -z ${BT_KEY_WORDS} ]]; then
 		if [[ ! -z ${SPAM_PORT} ]]; then
 			Set_ALL
 			View_ALL
 			echo -e "${Info} Torrent, Keywords and SPAM Ports Unblocked !"
 			msg -bar2
 		else
 			Set_BT
 			View_ALL
 			echo -e "${Info} Torrent, Keywords Unlocked !"
 			msg -bar2
 		fi
 	else
 		if [[ ! -z ${SPAM_PORT} ]]; then
 			Set_SPAM
 			View_ALL
 			echo -e "${Info} SPAM Ports Unblocked !"
 			msg -bar2
 		else
 			echo -e "${Error} Torrent not detected, Keywords and SPAM Ports Blocked, check !" && msg -bar2 && exit 0
 		fi
 	fi
 }
 ENTER_Ban_KEY_WORDS_type(){
 	Type=$1
 	Type_1=$2
 	if [[ $Type_1 != "ban_1" ]]; then
 		echo -e "Por favor seleccione un tipo de entrada：
 		
  1. Manual entry (only unique keywords are supported)
  
  2. Local reading of files (supports batch reading of keywords, one keyword per line)
  
  3. Network address reading (supports batch reading of keywords, one keyword per line)" && echo
 		read -e -p "(Default: 1. Manual entry):" key_word_type
 	fi
 	[[ -z "${key_word_type}" ]] && key_word_type="1"
 	if [[ ${key_word_type} == "1" ]]; then
 		if [[ $Type == "ban" ]]; then
 			ENTER_Ban_KEY_WORDS
 		else
 			ENTER_UnBan_KEY_WORDS
 		fi
 	elif [[ ${key_word_type} == "2" ]]; then
 		ENTER_Ban_KEY_WORDS_file
 	elif [[ ${key_word_type} == "3" ]]; then
 		ENTER_Ban_KEY_WORDS_url
 	else
 		if [[ $Type == "ban" ]]; then
 			ENTER_Ban_KEY_WORDS
 		else
 			ENTER_UnBan_KEY_WORDS
 		fi
 	fi
 }
 ENTER_Ban_PORT(){
 	echo -e "Enter the port to Block:\n(segment Single Port / Multiple Port / Continuous Port)\n"
 	if [[ ${Ban_PORT_Type_1} != "1" ]]; then
 	echo -e "
 	${Green_font_prefix}======== Example Description ========${Font_color_suffix}
 	
  -Single port: 25 (single port)
  
  -Multiport: 25, 26, 465, 587 (multiple ports are separated by commas)
 
  -Continuous port segment: 25:587 (all ports between 25-587)" && echo
 	fi
 	read -e -p "(Enter is canceled by default):" PORT
 	[[ -z "${PORT}" ]] && echo "Cancelled..." && View_ALL && exit 0
 }
 ENTER_Ban_KEY_WORDS(){
     msg -bar2
 	echo -e "intro the keywords to be banned\n(domain name etc, only supports single keyword)"
 	if [[ ${Type_1} != "ban_1" ]]; then
 	echo ""
 	echo -e "${Green_font_prefix}======== Example Description ========${Font_color_suffix}
 	
 -Keywords: youtube, which prohibits access to any domain name containing the keyword youtube.
  
 -Keywords: youtube.com, which prohibits access to any domain name (pan-domain name mask) that contains the keyword youtube.com.
 
 -Keywords: www.youtube.com, which prohibits access to any domain name (subdomain mask) that contains the keyword www.youtube.com.
 
 -Self-testing of more effects (such as the .zip keyword can be used to disable downloading of any .zip suffix files)." && echo
 	fi
 	read -e -p "(intro is canceled by default):" key_word
 	[[ -z "${key_word}" ]] && echo "Cancelled ..." && View_ALL && exit 0
 }
 ENTER_Ban_KEY_WORDS_file(){
 	echo -e "Enter the local keyword file to be banned/unblocked (use absolute path)" && echo
 	read -e -p "(Default is to read key_word.txt in the same directory as the script):" key_word
 	[[ -z "${key_word}" ]] && key_word="key_word.txt"
 	if [[ -e "${key_word}" ]]; then
 		key_word=$(cat "${key_word}")
 		[[ -z ${key_word} ]] && echo -e "${Error} The file content is empty. !" && View_ALL && exit 0
 	else
 		echo -e "${Error} File not found ${key_word} !" && View_ALL && exit 0
 	fi
 }
 ENTER_Ban_KEY_WORDS_url(){
 	echo -e "Enter the address of the keyword network file to be banned/unblocked (eg http: //xxx.xx/key_word.txt)" && echo
 	read -e -p "(Intro is canceled by default):" key_word
 	[[ -z "${key_word}" ]] && echo "Cancelled ..." && View_ALL && exit 0
 	key_word=$(wget --no-check-certificate -t3 -T5 -qO- "${key_word}")
 	[[ -z ${key_word} ]] && echo -e "${Error} El contenido del archivo de red está vacío o se agotó el tiempo de acceso !" && View_ALL && exit 0
 }
 ENTER_UnBan_KEY_WORDS(){
 	View_KEY_WORDS
 	echo -e "Enter the keyword you want to unlock (enter the complete and accurate keyword according to the list above)" && echo
 	read -e -p "(Intro is canceled by default):" key_word
 	[[ -z "${key_word}" ]] && echo "Cancelled ..." && View_ALL && exit 0
 }
 ENTER_UnBan_PORT(){
 	echo -e "Enter the port you want to unpack:\n(enter the complete and precise port according to the list above, including commas, colon)" && echo
 	read -e -p "(Intro is canceled by default):" PORT
 	[[ -z "${PORT}" ]] && echo "Cancelled ..." && View_ALL && exit 0
 }
 Ban_PORT(){
 	s="A"
 	ENTER_Ban_PORT
 	Set_PORT
 	echo -e "${Info} Blocked port [ ${PORT} ] !\n"
 	Ban_PORT_Type_1="1"
 	while true
 	do
 		ENTER_Ban_PORT
 		Set_PORT
 		echo -e "${Info} Blocked port [ ${PORT} ] !\n"
 	done
 	View_ALL
 }
 Ban_KEY_WORDS(){
 	s="A"
 	ENTER_Ban_KEY_WORDS_type "ban"
 	Set_KEY_WORDS
 	echo -e "${Info} Blocked keywords[ ${key_word} ] !\n"
 	while true
 	do
 		ENTER_Ban_KEY_WORDS_type "ban" "ban_1"
 		Set_KEY_WORDS
 		echo -e "${Info} Blocked keywords [ ${key_word} ] !\n"
 	done
 	View_ALL
 }
 UnBan_PORT(){
 	s="D"
 	View_PORT
 	[[ -z ${Ban_PORT_list} ]] && echo -e "${Error} Any non-blocked port is detected !" && exit 0
 	ENTER_UnBan_PORT
 	Set_PORT
 	echo -e "${Info} Decapsulated port [ ${PORT} ] !\n"
 	while true
 	do
 		View_PORT
 		[[ -z ${Ban_PORT_list} ]] && echo -e "${Error} Blocked ports not detected !" && msg -bar2 && exit 0
 		ENTER_UnBan_PORT
 		Set_PORT
 		echo -e "${Info} Decapsulated port[ ${PORT} ] !\n"
 	done
 	View_ALL
 }
 UnBan_KEY_WORDS(){
 	s="D"
 	Cat_KEY_WORDS
 	[[ -z ${Ban_KEY_WORDS_list} ]] && echo -e "${Error} No lock detected !" && exit 0
 	ENTER_Ban_KEY_WORDS_type "unban"
 	Set_KEY_WORDS
 	echo -e "${Info} Keywords unblocked [ ${key_word} ] !\n"
 	while true
 	do
 		Cat_KEY_WORDS
 		[[ -z ${Ban_KEY_WORDS_list} ]] && echo -e "${Error}  No lock detected !" && msg -bar2 && exit 0
 		ENTER_Ban_KEY_WORDS_type "unban" "ban_1"
 		Set_KEY_WORDS
 		echo -e "${Info} Keywords unblocked [ ${key_word} ] !\n"
 	done
 	View_ALL
 }
 UnBan_KEY_WORDS_ALL(){
 	Cat_KEY_WORDS
 	[[ -z ${Ban_KEY_WORDS_text} ]] && echo -e "${Error} No key detected, please check !" && msg -bar2 && exit 0
 	if [[ ! -z "${v6iptables}" ]]; then
 		Ban_KEY_WORDS_v6_num=$(echo -e "${Ban_KEY_WORDS_v6_list}"|wc -l)
 		for((integer = 1; integer <= ${Ban_KEY_WORDS_v6_num}; integer++))
 			do
 				${v6iptables} -t mangle -D OUTPUT 1
 		done
 	fi
 	Ban_KEY_WORDS_num=$(echo -e "${Ban_KEY_WORDS_list}"|wc -l)
 	for((integer = 1; integer <= ${Ban_KEY_WORDS_num}; integer++))
 		do
 			${v4iptables} -t mangle -D OUTPUT 1
 	done
 	Save_iptables_v4_v6
 	View_ALL
 	echo -e "${Info} All keywords have been unlocked !"
 }
 check_iptables(){
 	v4iptables=`iptables -V`
 	v6iptables=`ip6tables -V`
 	if [[ ! -z ${v4iptables} ]]; then
 		v4iptables="iptables"
 		if [[ ! -z ${v6iptables} ]]; then
 			v6iptables="ip6tables"
 		fi
 	else
 		echo -e "${Error}iptables firewall is not installed !
 Please install iptables firewall：
 CentOS System： yum install iptables -y
 Debian / Ubuntu System： apt-get install iptables -y"
 	fi
 }
 Update_Shell(){
 	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://www.dropbox"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
 	[[ -z ${sh_new_ver} ]] && echo -e "${Error} No se puede vincular a Github !" && exit 0
 	wget https://www.dropbox.com/s/xle -O /etc/ger-frm/blockBT.sh &> /dev/null
 	chmod +x /etc/ger-frm/blockBT.sh
 	echo -e "The script has been updated to the latest version.[ ${sh_new_ver} ]"
 	msg -bar2 
 	exit 0
 }
 check_sys
 check_iptables
 action=$1
 if [[ ! -z $action ]]; then
 	[[ $action = "banbt" ]] && Ban_BT && exit 0
 	[[ $action = "banspam" ]] && Ban_SPAM && exit 0
 	[[ $action = "banall" ]] && Ban_ALL && exit 0
 	[[ $action = "unbanbt" ]] && UnBan_BT && exit 0
 	[[ $action = "unbanspam" ]] && UnBan_SPAM && exit 0
 	[[ $action = "unbanall" ]] && UnBan_ALL && exit 0
 fi
 clear
 clear
 msg -bar
 echo  -e "$(msg -tit) " 
 echo -e "  VPS•AGN firewall panel By @kooroshmoradi ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}"
 msg -bar2
 echo -e "  ${Green_font_prefix}0.${Font_color_suffix} See the current banned list
 ————————————
   ${Green_font_prefix}1.${Font_color_suffix} Block Torrent, Keywords
   ${Green_font_prefix}2.${Font_color_suffix} Block SPAM Ports 
   ${Green_font_prefix}3.${Font_color_suffix} Block Torrent, Keywords + SPAM Ports
   ${Green_font_prefix}4.${Font_color_suffix} Block custom port
   ${Green_font_prefix}5.${Font_color_suffix} Block Custom Keywords
 ————————————
   ${Green_font_prefix}6.${Font_color_suffix} Unblock Torrent, Keywords
   ${Green_font_prefix}7.${Font_color_suffix} Unblock SPAM Ports
   ${Green_font_prefix}8.${Font_color_suffix} Unblock Torrent, Keywords, SPAM Ports
   ${Green_font_prefix}9.${Font_color_suffix} Unblock Custom Port
  ${Green_font_prefix}10.${Font_color_suffix} Unblock Custom Keyword
  ${Green_font_prefix}11.${Font_color_suffix} Unblock All Custom Keywords
 ————————————
  ${Green_font_prefix}12.${Font_color_suffix} Update script" && msg -bar2
 read -e -p " Please enter a number [0-12]:" num && msg -bar2
 case "$num" in
 	0)
 	View_ALL
 	;;
 	1)
 	Ban_BT
 	;;
 	2)
 	Ban_SPAM
 	;;
 	3)
 	Ban_ALL
 	;;
 	4)
 	Ban_PORT
 	;;
 	5)
 	Ban_KEY_WORDS
 	;;
 	6)
 	UnBan_BT
 	;;
 	7)
 	UnBan_SPAM
 	;;
 	8)
 	UnBan_ALL
 	;;
 	9)
 	UnBan_PORT
 	;;
 	10)
 	UnBan_KEY_WORDS
 	;;
 	11)
 	UnBan_KEY_WORDS_ALL
 	;;
 	12)
 	Update_Shell
 	;;
 	*)
 	echo "Please enter the correct number [0-12]"
 	;;
 esac 