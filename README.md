# WireGuard installer
This is a WireGuard automatic installer for French users. The original script being created by angristan, I respect his work and you can find his projects at this link: [Original Link](https://github.com/angristan/wireguard-install)

## Requis

Distributions Linux testées et disponibles à l'installation :

- Ubuntu >= 16.04
- Debian >= 10
- Fedora
- CentOS
- Arch Linux
- Oracle Linux

Barème : >= : supérieur ou égal à

## Utilisation

Téléchargez et lancez le script. Répondez aux questions posées par le script et il s'occupera du reste.

```bash
curl -O https://raw.githubusercontent.com/zAlwaysTheSun/wireguard-autoinstaller-french/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh
```

Il installera WireGuard (module kernel et tools) sur le serveur, le configurera, créera un service systemd et un fichier de configuration client.

Vous souhaitez ajouter des utilisateurs ? Relancez le script ! ;)

## Fournisseurs réseau/machine virtuelle

Je recommande ces hébergeurs pour l'hébergement de machines virtuelles accompagnées d'un bon réseau :

- [Pristis](https://goo.gl/Xyd1Sc): IPv4 uniquement, hébergeur avec un service client et après-vente irréprochable, VPS à seulement \3.99€/m
- [Hetzner](https://hetzner.cloud/?ref=ywtlvZsjgeDq): Allemagne et Finland, serveurs dédiés à prix très bas !
- [AdkyNet](https://goo.gl/qXrNLK): VPS accompagné d'un réseau 10Gbps, en France et service client assez rapide !
