#!/bin/bash

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install
# translate by https://github.com/zAlwaysTheSun

RED='\033[0;31m'
ORANGE='\033[0;33m'
NC='\033[0m'

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "Ce script a besoin d'être exécuté avec les permissions root user pour fonctionner !"
		exit 1
	fi
}

function checkOS() {
	# Check OS version
	if [[ -e /etc/debian_version ]]; then
		source /etc/os-release
		OS="${ID}" # debian or ubuntu
		if [[ ${ID} == "debian" || ${ID} == "raspbian" ]]; then
			if [[ ${VERSION_ID} -lt 10 ]]; then
				echo "Votre version de Debian (${VERSION_ID}) n'est pas supportée ! Merci d'utiliser Debian 10 au minimum !"
				exit 1
			fi
			OS=debian # overwrite if raspbian
		fi
	elif [[ -e /etc/fedora-release ]]; then
		source /etc/os-release
		OS="${ID}"
	elif [[ -e /etc/centos-release ]]; then
		source /etc/os-release
		OS=centos
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Je vois que tu n'utilises pas une version du kernel Linux compatible..."
		exit 1
	fi
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function installQuestions() {
	echo "Bienvenue sur l'installateur de WireGuard !"
	echo "Le lien Git est disponible à cet URL : https://github.com/zAlwaysTheSun/wireguard-autoinstaller-french"
	echo ""
	echo "Le script original est développé par angristan et traduit par zAlwaysTheSun !"
	echo ""
	echo "Afin de commencer, j'ai besoin de vous poser une question avant de démarrer l'installation.."
	echo "Vous pouvez laisser les options par défaut et appuyer simplement sur Entrer si vous êtes d'accord."

	# Détecter l'adresse IPv4 ou IPv6 publique et pré-remplir pour l'utilisateur
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Détecter l'IPv6 publique
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "IPv4/v6 du VPS : " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Interface publique : " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "Nom de l'interface WireGuard : " -e -i wg0 SERVER_WG_NIC
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "IPv4 du réseau local WireGuard: " -e -i 10.66.66.1 SERVER_WG_IPV4
	done

	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "IPv6 du réseau local WireGuard: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Port d'écoute du serveur WireGuard [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Adguard DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Entrez un serveur DNS (optimisation) : " -e -i 8.8.8.8 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Entrez un second serveur DNS (option de secours, pas obligatoire): " -e -i 8.8.4.4 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	echo ""
	echo "ça roule, c'est tout ce dont j'ai besoin."
	echo "Je vais procéder à l'installation de mon côté, vous pouvez faire autre chose à côté ! (pss, préparez WireGuard sur le second poste/serveur)"
	read -n1 -r -p "Appuyez sur une touche pour démarrer la procédure..."
}

function installWireGuard() {
	# Run setup questions first
	installQuestions

	# Install WireGuard tools and module
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt update
		apt-get install -y iptables resolvconf qrencode
		apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]]; then
		yum -y install epel-release elrepo-release
		if [[ ${VERSION_ID} -eq 7 ]]; then
			yum -y install yum-plugin-elrepo
		fi
		yum -y install kmod-wireguard wireguard-tools iptables qrencode
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}" >/etc/wireguard/params

	# Add server interface
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -A FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	sysctl --system

	systemctl start "wg-quick@${SERVER_WG_NIC}"
	systemctl enable "wg-quick@${SERVER_WG_NIC}"

	newClient
	echo "Si vous souhaitez ajouter plus de clients, il vous suffit de lancer ce script une autre fois !"

	# Check if WireGuard is running
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}AVERTISSEMENT : WireGuard ne semble pas être lancé.${NC}"
		echo -e "${ORANGE}Vous pouvez vérifier si votre WireGuard est initialisé : systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		echo -e "${ORANGE}Si vous avez \"Cannot find device ${SERVER_WG_NIC}\", merci de reboot la machine !${NC}"
	fi
}

function newClient() {
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Donne moi le nom de l'utilisateur"
	echo "Le nom doit être composé de caractères alphanumériques. Il peut également inclure un trait de soulignement ou un tiret et ne peut pas dépasser 15 caractères."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Nom du client : " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} == '1' ]]; then
			echo ""
			echo "Un client avec le nom spécifié a déjà été créé, veuillez choisir un autre nom."
			echo ""
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "Le sous-réseau configuré ne prend en charge que 253 clients."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "Client's WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/24" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} == '1' ]]; then
			echo ""
			echo "Un client avec cette IP version 4 est déjà utilisé. Merci d'en choisir une différente."
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "Client's WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/64" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV6_EXISTS} == '1' ]]; then
			echo ""
			echo "Un client avec cette IP version 6 est déjà utilisé. Merci d'en choisir une différente."
			echo ""
		fi
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0,::/0" >>"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	echo -e "\nHere is your client config file as a QR Code:"

	qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	echo "It is also available in ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "Il n'y a pas de clients existants !"
		exit 1
	fi

	echo ""
	echo "Sélectionnez le client existant que vous souhaitez révoquer"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	rm -f "${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	echo ""
	read -rp "Voulez-vous vraiment déinstaller WireGuard ? [y/n]: " -e -i n REMOVE
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		systemctl stop "wg-quick@${SERVER_WG_NIC}"
		systemctl disable "wg-quick@${SERVER_WG_NIC}"

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get autoremove --purge -y wireguard qrencode
		elif [[ ${OS} == 'debian' ]]; then
			apt-get autoremove --purge -y wireguard qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
			dnf autoremove -y
		elif [[ ${OS} == 'centos' ]]; then
			yum -y remove kmod-wireguard wireguard-tools qrencode
			yum -y autoremove
		elif [[ ${OS} == 'oracle' ]]; then
			yum -y remove wireguard-tools qrencode
			yum -y autoremove
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		# Reload sysctl
		sysctl --system

		# Check if WireGuard is running
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard ne s'est pas désinstallé normalement..."
			exit 1
		else
			echo "WireGuard a bien été supprimé."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function manageMenu() {
	echo "Bienvenue sur le script français d'installation de WireGuard automatique !"
	echo "Le script a été développé originalement par : https://github.com/angristan/wireguard-install"
	echo "Le script a été traduit et modifié par : https://github.com/zAlwaysTheSun"
	echo ""
	echo "Il me semble que Wireguard est déjà installé, voici donc les choses que tu peux faire :"
	echo ""
	echo "Que veut-tu faire ?"
	echo "   1) Ajouter un nouvel utilisateur"
	echo "   2) Supprimer un client"
	echo "   3) Désinstaller WireGuard"
	echo "   4) Quitter le script"
	until [[ ${MENU_OPTION} =~ ^[1-4]$ ]]; do
		read -rp "Sélectionner une option [1-4]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		uninstallWg
		;;
	4)
		exit 0
		;;
	esac
}

# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed and load params
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
	manageMenu
else
	installWireGuard
fi
