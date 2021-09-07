#!/bin/bash
#
# https://github.com/Nyr/openvpn-install
#
# Copyright (c) 2013 Nyr. Released under the MIT License.

server=10.0.0.0
submask=255.255.0.0
protocol=udp
port=1194
days_cert=36500
server_number=$(printf "%03.0f" $(cut -d'.' -f 2 <<< $server))
public_ip=8.209.64.85

if [[ $submask =~ 255.255.255.0 ]]; then 
	subnet=24
elif [[ $submask =~ 255.255.0.0 ]]; then 
	subnet=16
else
  echo "Errore nell'individuazione della sotto rete"
  exit
fi
echo "$subnet"

echo "Indirizzo IP del server VPN: "$server
echo "Indirizzo IP della maschera VPN: "$submask
echo "Sottorete: "$subnet
echo "Protocollo : "$protocol
echo "Porta: "$port
echo "Giorni validità certificato: "$days_cert
echo "Indirizzo IP pubblico: "$public_ip

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The system is running an old kernel, which is incompatible with this installer."
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distributions are Ubuntu, Debian, CentOS, and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	exit
fi

new_client () {
	echo
	echo "Nome del client:"
	read -p "Name: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
		echo "$client: nome non valido."
		read -p "Name: " unsanitized_client
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	done
	echo "Definisci l'indirizzo IPv4 (non usato) per il client (del tipo '${server:0:2}.123.123.1'):"
	read -p "IP: " client_ip
	until [[ $client_ip =~ ^${server:0:2}(\.[0-9]{1,3}){3}$ && $(grep -rnw '/etc/openvpn/server/ccd/' -e $client_ip | wc -l) -eq 0 ]]; do
		echo "$client_ip: IPv4 non valido o già in uso."
		read -p "IP: " client_ip
	done
	echo
	cd /etc/openvpn/server/easy-rsa/
	EASYRSA_CERT_EXPIRE=$days_cert ./easyrsa build-client-full "$client" nopass
	# Generates the custom client.ovpn
	server_number=$(printf "%03.0f" $(cut -d'.' -f 2 <<< $client_ip))
	port=$((1194+ $(cut -d'.' -f 2 <<< $client_ip) ))
	{
	echo "client
dev tun_TLC_$server_number
proto $protocol
remote $public_ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3
<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > /root/openVPN/"$client".ovpn
	echo "ifconfig-push $client_ip 255.255.0.0
iroute ${client_ip:0:${#client_ip}-1}0 255.255.255.0" > /etc/openvpn/server/ccd/"$client"
	echo
	if [[ $(grep -rnw '/etc/openvpn/server/' -e "server $(cut -d'.' -f 1 <<< $client_ip)\.$(cut -d'.' -f 2 <<< $client_ip).0.0" | wc -l) -eq 0 ]]; then
		server=$(cut -d'.' -f 1 <<< $client_ip)\.$(cut -d'.' -f 2 <<< $client_ip).0.0
		new_server
	fi
	echo "$client con IP $client_ip è stato aggiunto in " /root/openVPN/"$client.ovpn"
}

new_server () {
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}' | grep -vEc "${server:0:2}(\.[0-9]{1,3}){3}") -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | grep -vE "${server:0:2}(\.[0-9]{1,3}){3}" | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}' | grep -vEc "${server:0:2}(\.[0-9]{1,3}){3}")
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | grep -vE "${server:0:2}(\.[0-9]{1,3}){3}" | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | grep -vE "${server:0:2}(\.[0-9]{1,3}){3}" | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# Generate server.conf
	echo "port $port
proto $protocol
dev tun_TLC_$server_number
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server $server $submask
client-config-dir ccd
ifconfig-pool-persist ipp.txt" >> /etc/openvpn/server/server$server_number.conf
echo 'push "route 10.0.0.0 255.0.0.0"' >> /etc/openvpn/server/server$server_number.conf
echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
status openvpn-status$server_number.log
log openvpn$server_number.log
verb 3
crl-verify crl.pem
explicit-exit-notify" >> /etc/openvpn/server/server$server_number.conf
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source="$server"/"$subnet"
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source="$server"/"$subnet"
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s "$server"/"$subnet" ! -d "$server"/"$subnet" -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s "$server"/"$subnet" ! -d "$server"/"$subnet" -j SNAT --to "$ip"
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
		fi
		if [[ ! -e /etc/systemd/system/openvpn-iptables.service ]]; then
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s $server/$subnet ! -d $server/$subnet -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s $server/$subnet -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s $server/$subnet ! -d $server/$subnet -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s $server/$subnet -j ACCEPT" > /etc/systemd/system/openvpn-iptables$server_number.service
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables$server_number.service
		systemctl enable --now openvpn-iptables$server_number.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# Enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server$server_number.service
}

if [[ ! -e /etc/openvpn/server/ ]]; then
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	#clear
	echo 'Welcome to this OpenVPN installer!'
	echo
	echo "OpenVPN installation is ready to begin."
	# Install a firewall in the rare case where one is not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server$server_number.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server$server_number.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		# Else, OS must be Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa init-pki
	EASYRSA_CA_EXPIRE="$days_cert" ./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE="$days_cert" ./easyrsa build-server-full server nopass
	EASYRSA_CRL_DAYS="$days_cert" ./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	# Generate key for tls-crypt
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# crea la cartella ccd dove il server salva l'indirizzo IP statico che ogni certificato deve avere
	mkdir -p /etc/openvpn/server/ccd/
	new_server
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Generates the custom client.ovpn
	new_client
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in:" /root/openVPN/"$client.ovpn"
	echo "New clients can be added by running this script again."
else
	#clear
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Revoke an existing client"
	echo "   3) Remove OpenVPN"
	echo "   4) Servizio OpenVPN - IPTables "
	echo "   5) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-5]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			new_client
			exit
		;;
		2)
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to revoke:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client revocation? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: invalid selection."
				read -p "Confirm $client revocation? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=$days_cert ./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				echo "$client revoked!"
			else
				echo
				echo "$client revocation aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm OpenVPN removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm OpenVPN removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				for s in /etc/openvpn/server/*.conf; do
					echo "Rimuovo l'instanza server: $s"
					port=$(grep '^port ' $s | cut -d " " -f 2)
					protocol=$(grep '^proto ' $s | cut -d " " -f 2)
					server=$(grep '^server ' $s | cut -d " " -f 2)
					server_number=$(printf "%03.0f" $(cut -d'.' -f 2 <<< $server))
					if systemctl is-active --quiet firewalld.service; then
						ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s "$server"/"$subnet" '"'"'!'"'"' -d "$server"/"$subnet"' | grep -oE '[^ ]+$')
						# Using both permanent and not permanent rules to avoid a firewalld reload.
						firewall-cmd --remove-port="$port"/"$protocol"
						firewall-cmd --zone=trusted --remove-source="$server"/"$subnet"
						firewall-cmd --permanent --remove-port="$port"/"$protocol"
						firewall-cmd --permanent --zone=trusted --remove-source="$server"/"$subnet"
						firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s "$server"/"$subnet" ! -d "$server"/"$subnet" -j SNAT --to "$ip"
						firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s "$server"/"$subnet" ! -d "$server"/"$subnet" -j SNAT --to "$ip"
					else
						systemctl disable --now openvpn-iptables$server_number.service
						rm -f /etc/systemd/system/openvpn-iptables$server_number.service
					fi
					if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
						semanage port -d -t openvpn_port_t -p "$protocol" "$port"
					fi
					systemctl disable --now openvpn-server@server$server_number.service
					rm -f /etc/systemd/system/openvpn-server@server$server_number.service.d/disable-limitnproc.conf
				done
				systemctl disable --now openvpn-iptables.service
				rm -f /etc/systemd/system/openvpn-iptables.service
				rm -rf /etc/openvpn/server
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y openvpn
				fi
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "OpenVPN removal aborted!"
			fi
			exit
		;;
		4)
			echo "Operazione sul servizio OpenVPN - IPTables "
			echo
			echo "Seleziona un optione:"
			echo "   1) Status"
			echo "   2) Stop"
			echo "   3) Start"
			echo "   4) Riavvio"
			echo "   5) Exit"
			read -p "Option: " option
			until [[ "$option" =~ ^[1-5]$ ]]; do
				echo "$option: invalid selection."
				read -p "Option: " option
			done
			case "$option" in
				1)
					for s in /etc/openvpn/server/*.conf; do
						echo "Stato dell'instanza server $s"
						server=$(grep '^server ' $s | cut -d " " -f 2)
						server_number=$(printf "%03.0f" $(cut -d'.' -f 2 <<< $server))
						systemctl status openvpn-server@server$server_number.service --no-pager
						echo "Stato dell'IPTables dell'instanza"
						systemctl status openvpn-iptables$server_number.service --no-pager
						echo
					done
					exit
				;;
				2)
					for s in /etc/openvpn/server/*.conf; do
						echo "Stop dell'instanza server $s"
						server=$(grep '^server ' $s | cut -d " " -f 2)
						server_number=$(printf "%03.0f" $(cut -d'.' -f 2 <<< $server))
						systemctl stop openvpn-server@server$server_number.service
						echo "Stop dell'IPTables dell'instanza"
						systemctl stop openvpn-iptables$server_number.service
						echo
					done
					exit
				;;
				3)
					for s in /etc/openvpn/server/*.conf; do
						echo "Start dell'instanza server $s"
						server=$(grep '^server ' $s | cut -d " " -f 2)
						server_number=$(printf "%03.0f" $(cut -d'.' -f 2 <<< $server))
						systemctl start openvpn-server@server$server_number.service
						echo "Start dell'IPTables dell'instanza"
						systemctl start openvpn-iptables$server_number.service
						echo
					done
					exit
				;;
				4)
					for s in /etc/openvpn/server/*.conf; do
						echo "Riavvio dell'instanza server $s"
						server=$(grep '^server ' $s | cut -d " " -f 2)
						server_number=$(printf "%03.0f" $(cut -d'.' -f 2 <<< $server))
						systemctl restart openvpn-server@server$server_number.service
						echo "Riavvio dell'IPTables dell'instanza"
						systemctl restart openvpn-iptables$server_number.service
						echo
					done
					exit
				;;
			esac
			exit
		;;
		5)
			exit
		;;
	esac
fi
