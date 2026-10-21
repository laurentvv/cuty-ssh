<div align="center">

# Cuty-SSH

### Gestionnaire de connexions Windows natif et rapide en pur Rust : SSH2, SFTP, Telnet, Raw TCP & ConPTY

![Bannière Cuty-SSH](assets/cuty_ssh_hero.png)

[![Release](https://img.shields.io/github/v/release/laurentvv/cuty-ssh?style=flat-square&logo=github&color=00b4d8)](https://github.com/laurentvv/cuty-ssh/releases)
[![Statut CI](https://img.shields.io/github/actions/workflow/status/laurentvv/cuty-ssh/ci.yml?branch=main&style=flat-square&logo=githubactions&label=CI)](https://github.com/laurentvv/cuty-ssh/actions)
[![Rust 2024](https://img.shields.io/badge/Rust-2024_Edition-f74c00?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Plateforme](https://img.shields.io/badge/Plateforme-Windows_10_%2F_11_(x64)-0078d4?style=flat-square&logo=windows)](https://github.com/laurentvv/cuty-ssh/releases)
[![GUI](https://img.shields.io/badge/GUI-egui_0.37_(DirectX_12)-8a2be2?style=flat-square)](https://github.com/emilk/egui)
[![Moteur SSH](https://img.shields.io/badge/SSH2-russh_0.64-2ea043?style=flat-square)](https://crates.io/crates/russh)
[![Bilingue](https://img.shields.io/badge/Interface-Fran%C3%A7ais_%2F_English-ffb703?style=flat-square)](#5-interface-bilingue-fr--en--guide-dutilisateur-illustr-intgr)
[![Licence : MIT](https://img.shields.io/badge/Licence-MIT-success?style=flat-square)](LICENSE)

<p align="center">
  <img src="assets/cuty_ssh_icon.png" width="88" alt="Icône Cuty-SSH" style="border-radius: 18px;" />
</p>

[**Télécharger la dernière version (`v0.6.0`)**](https://github.com/laurentvv/cuty-ssh/releases/latest) · [**🇬🇧 English Version**](README.md) · [**Visite animée**](#visite-guide-anime--aperu-du-cockpit) · [**Fonctionnalités**](#fonctionnalits-cls) · [**`ssh-copy-id` en 1 clic**](#dploiement-de-cl-ssh-copy-id-en-1-clic--migration-automatique-mot-de-passe--cl) · [**Bastion (`-J`)**](#bastion-ssh--hte-de-rebond--j--proxyjump) · [**Architecture**](#architecture) · [**Compiler depuis les sources**](#compiler-depuis-les-sources)

</div>

---

## Vue d'ensemble

**Cuty-SSH** (`v0.6.0`) est un émulateur de terminal et cockpit d'administration système tout-en-un pour Windows, mono-binaire, portable et accéléré par GPU (**DirectX 12 / wgpu**), écrit en **Rust 100% sûr et asynchrone (`russh` + `egui` + `tokio`)**, sans **aucune dépendance binaire externe** (aucun emballage de `putty.exe` ou `kitty.exe`).

Il réconcilie l'écosystème classique **PuTTY / KiTTY** avec les méthodes de travail modernes **OpenSSH** :
- Chargement natif des clés privées **PuTTY `.ppk` v2 et v3** (incluant le chiffrement par mot de passe **Argon2id**) en plus des formats OpenSSH et PEM.
- Authentification automatique et transparente via **Pageant** (mémoire partagée Windows) **et** le service natif **Windows OpenSSH Agent** (`\\.\pipe\openssh-ssh-agent`).
- Provisionnement de serveurs en **1 clic (`ssh-copy-id`)** : connectez-vous une première fois avec identifiant et mot de passe, déployez votre clé principale dans `~/.ssh/authorized_keys`, et laissez Cuty-SSH basculer automatiquement la session en authentification par clé sans mot de passe tout en effaçant le mot de passe stocké.
- Routage sécurisé via **Bastions SSH / Jump Hosts (`-J` / `ProxyJump`)**, gestion TOFU des empreintes de serveurs **`known_hosts` SHA-256**, chiffrement local des secrets par le **coffre Windows DPAPI**, transferts de fichiers par glisser-déposer **SFTP en streaming**, et surveillance en direct de la télémétrie serveur (`charge CPU`, `RAM`, `Disque`, `Uptime`).
- Gestion de parc, sondes de santé TCP automatiques toutes les 45s, passerelles Zero-Trust (ShellHub, Tailscale), enregistrement de sessions **Asciinema v2 (`.cast`)** avec lecteur interactif, diffusion des frappes (**`📡 Broadcast`**), et journal d'audit local sécurisé (**`📜 Audit`**).

---

## Visite guidée animée & Aperçu du Cockpit

### Démonstration animée (`assets/cuty_ssh_demo.gif`)
> Découverte pas à pas du **Cockpit SysAdmin**, de l'**Éditeur de session Bastion / Jump Host (`-J`)**, du **Guide illustré intégré (`📖 Aide`)**, de la **Boîte à outils Réseau & CIDR**, du **Gestionnaire TOFU (`🛡 Hosts`)**, et de l'**Inspecteur de clés PuTTY `.ppk` & Pageant** :

![Démonstration animée Cuty-SSH](assets/cuty_ssh_demo.gif)

### Cockpit d'administration système (`assets/screenshot_cockpit.png`)

![Capture d'écran du Cockpit Cuty-SSH](assets/screenshot_cockpit.png)

---

## Tableau comparatif : Pourquoi Cuty-SSH ?

| Fonctionnalité | PuTTY / KiTTY classique | Windows Terminal + `ssh.exe` | **Cuty-SSH (`v0.6.0`)** |
| :--- | :---: | :---: | :---: |
| **Moteur SSH2 pur Rust asynchrone (`russh`)** | ❌ Code C historique | ❌ Processus externe | ✅ **Intégré (`russh 0.64`)** |
| **Clés PuTTY `.ppk` v2 & v3 (Argon2id) natives** | ✅ | ❌ Conversion requise | ✅ **Lecture & inspection directes** |
| **Double Agent : Pageant + Windows OpenSSH Agent** | Pageant uniquement | OpenSSH Agent uniquement | ✅ **Interrogation des deux agents** |
| **`ssh-copy-id` 1-clic + bascule auto mot de passe ➡ clé** | ❌ | ❌ Ligne de commande manuelle | ✅ **Bouton 1-clic + migration de profil** |
| **Bastion SSH / Hôte de rebond (`-J` / `ProxyJump`)** | Commande proxy complexe | ✅ Option `-J` | ✅ **Sélecteur visuel + `ProxyJump`** |
| **Explorateur SFTP en streaming + Glisser-Déposer** | ❌ `psftp` séparé | ❌ | ✅ **Panneau intégré + flux 64 Ko** |
| **Télémétrie serveur en direct (`Load` / `RAM` / `Disque`)** | ❌ | ❌ | ✅ **Bandeau d'en-tête non intrusif** |
| **Chiffrement matériel des secrets (Windows DPAPI)** | ❌ Registre en clair | ❌ | ✅ **`CryptProtectData` + `zeroize`** |
| **Gestionnaire d'empreintes TOFU `known_hosts` SHA-256** | Popup registre | Fichier texte seul | ✅ **Modale `Outils ▾ → Known Hosts` + alerte MITM** |
| **Écran scindé (`◫ Split V` / `⊟ Split H`)** | ❌ | ✅ | ✅ **Panneaux côte-à-côte et haut/bas** |
| **Diffusion des frappes clavier (`📡 Broadcast`)** | ❌ | ❌ | ✅ **Saisie simultanée avec badge de sécurité** |
| **Enregistrement de session (`🔴 REC`) & Lecteur (`▶ Replay`)** | Journal texte brut | ❌ | ✅ **Asciinema v2 (`.cast`) + lecteur GUI** |
| **Préréglages Passerelles Zero-Trust (ShellHub / Tailscale)** | ❌ | ❌ | ✅ **Intégration native & formatage auto** |
| **Sondes de santé du parc & Déploiement groupé de clés** | ❌ | ❌ | ✅ **Ping TCP auto 45s + `ssh-copy-id` en lot** |
| **Journal d'Audit local (`📜 Audit`) avec export CSV/JSON** | ❌ | ❌ | ✅ **Traçabilité locale + zéro secret en clair** |
| **Outils SysAdmin (Scanner de ports, CIDR, Ping)** | ❌ | ❌ | ✅ **Boîte à outils `🛠 Diagnostic & CIDR`** |
| **Interface bilingue (`🌐 FR / EN`) + Guide illustré** | ❌ | ❌ | ✅ **Bascule instantanée + export HTML** |

---

## Fonctionnalités clés

### 1. Clés PuTTY natives (`.ppk`), Pageant & Windows OpenSSH Agent
- **Support direct des clés `.ppk` v2 et v3** : Ouvrez directement vos fichiers de clés PuTTY sans aucune conversion préalable.
  - Algorithmes supportés : **Ed25519**, **RSA**, **ECDSA (`nistp256` / `nistp384` / `nistp521`)**, et **DSA**.
  - Clés non chiffrées ou chiffrées par mot de passe (`aes256-cbc`, dérivation KDF **Argon2id / Argon2d / Argon2i** pour `.ppk` v3, SHA-1 pour `.ppk` v2).
  - Nettoyage sécurisé de la mémoire vive (`zeroize`) dès la fin de l'utilisation des clés.
- **Double support d'agents SSH (Pageant + Windows OpenSSH Agent)** :
  - Connexion sans saisie de mot de passe via l'agent **Pageant** en cours d'exécution (IPC mémoire partagée Windows).
  - Détection et bascule automatique sur le service natif **Windows OpenSSH Authentication Agent** (`\\.\pipe\openssh-ssh-agent`).
  - Lanceur Pageant intégré et chargement groupé en 1 clic de l'ensemble des clés des sessions enregistrées.
- **Inspecteur, convertisseur et générateur de clés intégré** :
  - Inspection détaillée de clés `.ppk`, OpenSSH, PEM, PKCS#8 ou `.pub` (format, algorithme, KDF, empreinte SHA-256, commentaire, ligne publique `authorized_keys`).
  - Conversion bidirectionnelle `.ppk` ↔ OpenSSH (`id_ed25519` / `id_rsa`).
  - Génération de nouvelles paires de clés Ed25519, ECDSA-P256 ou RSA-2048 directement au format PuTTY `.ppk` v3.

#### Déploiement de clé `ssh-copy-id` en 1 clic & Migration automatique Mot de passe ➡ Clé
Le déploiement manuel d'une clé publique sur un nouveau serveur Linux implique souvent des étapes fastidieuses. Cuty-SSH automatise l'ensemble du flux en 1 clic :
1. **Depuis l'éditeur de session (première connexion Login + Mot de passe)** :
   - Renseignez l'hôte, le nom d'utilisateur et le mot de passe, puis cliquez sur **`🔑➡🖥 Connecter (Mdp) & Copier Clé Principale (ssh-copy-id)`** (ou cochez **`🔑➡🖥 Copier ma Clé Principale à la 1ère connexion`**).
2. **Ou depuis n'importe quel onglet de terminal SSH actif** :
   - Cliquez sur **`🔑➡🖥 Copier Ma Clé (ssh-copy-id)`** dans la barre d'outils du terminal.
3. **Fonctionnement sous le capot** :
   - Cuty-SSH résout votre **Clé SSH Principale** (ou en génère une dédiée `id_cuty_primary.ppk` si vous n'en possédez pas encore).
   - Via un canal SSH sécurisé en arrière-plan, il crée `~/.ssh` (`chmod 700`), ajoute votre clé publique à `~/.ssh/authorized_keys` (`chmod 600`) avec déduplication stricte `grep -qxF`, et valide son installation.
   - Dès confirmation par le serveur, Cuty-SSH **bascule automatiquement le profil de session de `Password` vers `PrivateKeyFile`**, **efface et met à zéro le mot de passe stocké**, et enregistre la configuration. Les prochaines connexions se feront à 100% par clé publique sans mot de passe.

---

### 2. Moteur multi-protocoles, Bastion (`ProxyJump`) & Coffre de sécurité
- **SSH2** (`russh 0.64`) : PTY et shell interactif, clé publique (`.ppk` / OpenSSH / certificats OpenSSH `-cert.pub`), Pageant & Windows OpenSSH Agent, mot de passe, clavier-interactif (PAM / 2FA / TOTP), transfert d'agent SSH, keepalive, et tunnels de redirection de ports locaux (`-L`) et distants (`-R`).

#### Bastion SSH / Hôte de rebond (`-J` / `ProxyJump`)
Connectez-vous à vos serveurs privés ou en DMZ à travers un serveur intermédiaire Bastion grâce au tunnel de flux chiffré `direct-tcpip` :
1. Ouvrez l'éditeur de session (`➕ Session` ou cliquez sur `⚙` sur une carte de session).
2. Dans l'onglet **🔌 Connexion & Clé .PPK / Pageant** (SSH2 sélectionné), accédez à la section **🏰 Bastion / Jump Host SSH (-J / ProxyJump)**.
3. Choisissez une session Bastion enregistrée dans la liste déroulante ou renseignez un hôte inline (`user@bastion.corp:22`), puis cliquez sur **💾 Enregistrer**.
4. Les sessions passant par un Bastion affichent un badge violet **`Bastion` / `-J`** sur le Cockpit et dans la barre latérale.

- **Vérification TOFU des clés d'hôtes & Gestionnaire `known_hosts` (`Outils ▾ → 🛡 Known Hosts`)** :
  - Validation automatique Trust-On-First-Use (TOFU) des empreintes SHA-256 des serveurs dans `cuty-ssh-portable/known_hosts.json`.
  - Protection stricte anti-MITM : blocage immédiat avec alerte de sécurité si la clé publique d'un serveur change, avec modale dédiée (`Outils ▾ → Known Hosts`) pour inspecter, copier ou révoquer une empreinte.
- **Coffre de stockage chiffré par Windows DPAPI** :
  - Les mots de passe et passphrases enregistrés sont chiffrés sur disque via l'API Windows **DPAPI** (`CryptProtectData` / `CryptUnprotectData`, lié à votre compte utilisateur Windows) avec préfixe `"dpapi:<base64>"` et protection `zeroize` en mémoire.
- **Télémétrie serveur en direct** :
  - Collecte légère en tâche de fond affichant le nom d'hôte, le noyau Linux, l'uptime, la charge moyenne (`Load`), l'utilisation de la RAM (`free -m`) et l'espace disque racine (`df -P -h /`).
- **Telnet (RFC 854), Raw TCP & Shell local ConPTY Windows** :
  - Négociation Telnet IAC (`NAWS`, `TTYPE` `xterm-256color`, `SGA`, `ECHO`) et connexion automatique.
  - Socket TCP brut pour le débogage d'équipements réseau.
  - ConPTY Windows local (`portable-pty 0.9`) pour lancer PowerShell, CMD ou WSL directement dans des onglets à côté de vos serveurs distants.

---

### 3. Écran scindé (Split View), SFTP Glisser-Déposer & Moteur de rendu
- **Affichage en écran scindé (`◫ Split V` / `⊟ Split H`)** :
  - Affichez et utilisez deux terminaux simultanément en mode vertical (côte-à-côte) ou horizontal (haut/bas) dès que 2 onglets sont ouverts, avec redimensionnement indépendant du PTY et activation au clic.
- **Explorateur SFTP avec glisser-déposer & barre de progression** :
  - Glissez-déposez des fichiers depuis l'Explorateur Windows directement sur la fenêtre de Cuty-SSH pour les téléverser dans le dossier SFTP distant actif.
  - Streaming asynchrone par blocs de 64 Ko pour les gros fichiers avec barre de progression de transfert en direct.
  - Tri interactif par colonnes (Nom, Taille, Date, bascule `📁⬆ Dossiers 1ers`) et ouverture externe dans WinSCP en 1 clic.
- **Rendu graphique haute performance par lots (Run-Length Text Batching)** :
  - Rendu par séquences de texte contiguës partageant la même couleur pour garantir 60+ FPS constants.
  - Cellules de terminal compactes (`TerminalCell` avec drapeaux binaires sur 1 octet), écran alternatif (`?1049h` pour `vim`, `htop`, `tmux`), couleurs 256 et 24-bit TrueColor, et ouverture d'URLs au Ctrl+Clic.

---

### 4. Organisation des sessions, Tags (`#tag`) & Boîte à outils Réseau
- **Recherche multicritère instantanée & Tags de sessions (`#tag`)** :
  - Filtrez instantanément par Nom, Hôte / IP, Port, Utilisateur, Protocole, Dossier ou `#tag`.
  - Associez des tags personnalisés (`prod`, `dmz`, `db`, `linux`, etc.) ou gérez les tags en lot sur plusieurs sessions via le **Gestionnaire (`📁 Gestionnaire`)**.
- **Importateur automatique `~/.ssh/config` (`Import ▾ → Sync`) & Synchronisation PuTTY** :
  - Analyse des fichiers `~/.ssh/config` standards (`Host`, `HostName`, `User`, `Port`, `IdentityFile`, `ProxyJump`, `LocalForward`, `RemoteForward`) avec import des tags et des tunnels.
  - Importation automatique ou manuelle depuis le Registre PuTTY (`HKCU\Software\SimonTatham\PuTTY\Sessions`).
  - **Menu `Import ▾ → KiTTY…`** : choisissez un dossier KiTTY portable (celui qui contient `Sessions/`) pour importer toutes ses sessions ; `Import ▾ → Sync` le ré-importe ensuite.
- **Boîte à outils Diagnostic Réseau (`🛠 Diagnostic & CIDR`) & Palette rapide (`Ctrl+K`)** :
  - Lanceur rapide de commandes et de sessions (`Ctrl+K`).
  - Scanner de ports TCP multi-threadé asynchrone & capture de bannières SSH.
  - Test de santé de l'ensemble du parc de serveurs (mesure de latence TCP en millisecondes).
  - Calculateur de sous-réseau IPv4 CIDR (masque, wildcard, adresse réseau, broadcast, plage d'hôtes).
  - Générateur de commandes CLI en 1 clic pour OpenSSH, PuTTY et WinSCP.

---

### 5. Interface bilingue (`FR / EN`) & Guide d'utilisateur illustré intégré
- **Traduction intégrale Français / Anglais (`🌐 FR` / `🌐 EN`)** :
  - Basculez l'ensemble de l'interface en direct via le bouton de langue dans la barre supérieure, dans l'éditeur de session ou dans la fenêtre d'aide.
  - Persistance automatique du choix de langue dans `cuty-ssh-portable/config.json`.
- **Guide illustré intégré (`📖 Aide`) & Export HTML autonome** :
  - Parcourez **9 chapitres illustrés** avec captures d'écran haute résolution, explications pas à pas et bouton d'exportation en 1 clic vers une page Web autonome (`cuty-ssh-portable/user-guide.html`).

---

### 6. Gestion de parc, Passerelles Zero-Trust, Enregistrement & Journal d'Audit
- **Diffusion des frappes clavier (`📡 Broadcast`)** :
  - En mode écran scindé (Vertical ou Horizontal), activez le mode Broadcast pour dupliquer vos commandes simultanément sur tous les terminaux ouverts.
  - Badge de sécurité orange explicite `📡 BROADCAST ON` dans l'en-tête de chaque terminal actif pour éviter les erreurs de saisie involontaires.
- **Enregistrement de session (`🔴 REC`) & Lecteur Replay (`▶ Replay`)** :
  - Enregistrez vos sessions actives en direct au format standard **Asciinema v2 (`.cast`)** dans `cuty-ssh-portable/recordings/`.
  - Rejouez vos enregistrements à tout moment via le lecteur Replay intégré avec barre de défilement temporelle, pause/lecture et sélecteur de vitesse (`0.5x`, `1x`, `2x`, `4x`).
  - 100% compatible avec les outils externes comme `asciinema play` ou `agg`.
- **Préréglages Passerelles Zero-Trust / Edge (ShellHub & Tailscale)** :
  - Prise en charge native de **ShellHub** pour l'accès aux équipements IoT et serveurs distants derrière pare-feu ou NAT (routage par UUID de device sur instance Cloud ou auto-hébergée) et **Tailscale** (adresses IP MagicDNS).
  - Formatage automatique de la cible SSH selon les spécifications de chaque passerelle.
- **Sondes de santé automatiques du parc & Déploiement groupé `ssh-copy-id`** :
  - Sondes TCP non-bloquantes toutes les 45 secondes sur l'ensemble de vos serveurs enregistrés.
  - Pastilles colorées en temps réel (`🟢 En ligne`, `🔴 Injoignable`, `⏳ Timeout`) sur les cartes du Cockpit et dans la liste latérale.
  - Boutons de filtre `● En ligne` / `● Hors ligne` sur le Cockpit pour n'afficher que les serveurs joignables ou injoignables ; les mêmes boutons dans le Gestionnaire permettent de sélectionner et supprimer en masse les VMs disparues.
  - Bouton `📡 Ping` dans la barre d'outils du Cockpit pour forcer un rafraîchissement immédiat de la disponibilité de la flotte.
  - Dans le `📁 Gestionnaire`, sélectionnez plusieurs serveurs et cliquez sur `🔑 Déployer Clé Principale` pour installer votre clé publique en lot sur l'ensemble du parc.
- **Journal d'Audit local (`📜 Audit`)** :
  - Journalisation locale de tous les événements (`CONNECT`, `DISCONNECT`, `ERROR`, `DEPLOY_KEY`, durées de session).
  - Recherche en direct et filtres par type d'événement.
  - Exportation en 1 clic en **CSV** ou **JSON** pour les rapports de conformité et de sécurité.
  - Conforme à notre politique stricte **Zéro Secret en clair** (aucun mot de passe ni clé privée n'est enregistré dans l'audit).

### 7. Résilience, scripts & tunnels

- **Reconnexion automatique** : cochez *Reconnexion automatique* dans l'éditeur de session, ou utilisez le bouton `↻ Auto-reconnexion` d'un onglet. Une connexion perdue est retentée avec un délai croissant (2 s → 30 s, 10 essais) ; la barre d'état affiche le compte à rebours et `↻ Reconnecter` force un essai immédiat.
- **Ligne de commande** : `cuty-ssh --session "Prod Web"` ouvre une session enregistrée au démarrage (nom, fragment de nom unique ou UUID) ; `cuty-ssh --list` liste les sessions.
- **Proxy SOCKS5 / HTTP en un clic** : le bouton `SOCKS5/HTTP` d'un onglet SSH démarre un proxy local (port modifiable, `1080` par défaut) qui accepte les clients SOCKS5 et HTTP `CONNECT` via la session ; une règle `SOCKS5 (-D)` peut aussi être enregistrée dans l'onglet *Redirection de ports*.
- **Repli keyboard-interactive** : si le serveur refuse `password` mais propose keyboard-interactive (PAM / 2FA), Cuty-SSH poursuit automatiquement avec cette méthode.
- **Propriétés SFTP & miroir** : `…` sur un élément distant ouvre chmod (grille rwx + octal), création de lien symbolique et SHA-256 ; `Miroir` prévisualise et lance une synchronisation à sens unique local/distant.
- **Import Bitvise** : `Import > Bitvise…` lit les profils `.tlp` / `.bscp` (hôte, port, utilisateur).
- **Transferts SFTP reprenables** : envois et téléchargements écrivent dans `<nom>.cutypart`, renommé à la fin ; relancer un transfert interrompu reprend à l'octet déjà transféré.

| Propriétés SFTP (chmod, lien, SHA-256) | Miroir SFTP (aperçu puis synchro) | Reconnexion automatique |
|---|---|---|
| ![Propriétés SFTP](assets/screenshot_sftp_properties.png) | ![Miroir SFTP](assets/screenshot_sftp_mirror.png) | ![Reconnexion automatique](assets/screenshot_auto_reconnect.png) |

---

## Raccourcis clavier & souris

| Raccourci / Interaction | Action |
| :--- | :--- |
| **`Double-clic`** | Sélectionne instantanément le mot, token, adresse IP, chemin ou URL sous le curseur (copie automatique si l'option est active) |
| **`Triple-clic`** | Sélectionne la ligne entière du terminal |
| **`Clic droit`** | Colle le contenu du presse-papier (style PuTTY, ou copie le texte si une sélection est active) |
| **`Ctrl + K`** | Ouvre la **Palette rapide** (recherche de sessions, filtre par `#tag`, lancement `ssh user@host:port`) |
| **`Ctrl + Shift + C`** | Copie la sélection dans le presse-papier |
| **`Ctrl + Shift + V`** | Colle le texte du presse-papier dans le terminal actif |
| **`Ctrl + F`** | Affiche/masque la barre de recherche dans le terminal |
| **`Ctrl + Clic`** | Ouvre une URL détectée (`http://` ou `https://`) dans votre navigateur par défaut |

---

## Téléchargement & Démarrage rapide

### Option 1 — Installateur Windows (.msi) & WinGet (Recommandé)
- **Téléchargement direct** : Téléchargez et exécutez [**`cuty-ssh-v0.6.0-windows-x64.msi`**](https://github.com/laurentvv/cuty-ssh/releases/download/v0.6.0/cuty-ssh-v0.6.0-windows-x64.msi).
  - S'installe proprement dans `%LOCALAPPDATA%\Programs\Cuty-SSH` sans demande d'élévation administrateur (sans popup UAC).
  - Crée automatiquement un raccourci dans le Menu Démarrer avec l'icône de l'application.
  - Désinstallation propre en 1 clic depuis les Paramètres Windows / Applications installées.
- **Via le gestionnaire de paquets Windows (`winget`)** :
  ```powershell
  winget install LaurentVolff.Cuty-SSH
  ```

### Option 2 — Binaire autonome portable
1. Téléchargez **`cuty-ssh.exe`** (ou **`cuty-ssh-v0.6.0-windows-x64.zip`**) depuis la page des [**Releases GitHub**](https://github.com/laurentvv/cuty-ssh/releases/latest).
2. Déposez `cuty-ssh.exe` dans le dossier de votre choix et lancez-le — aucune installation requise.
3. Cuty-SSH crée automatiquement un dossier local **`cuty-ssh-portable/`** à côté de l'exécutable :
   - `config.json` (profils de session chiffrés DPAPI, dossiers, tags, snippets, langue et thème)
   - `known_hosts.json` (empreintes de serveurs TOFU SHA-256)
   - `keys/` (clés `.ppk` ou OpenSSH générées ou importées, incluant votre clé principale)
   - `recordings/` (enregistrements de session Asciinema `.cast`)
   - `audit.jsonl` (journal d'audit des connexions)

### Option 3 — Compiler depuis les sources
Nécessite la chaîne de compilation **Rust 2024** (`rustup` stable sur Windows 10/11 x64) :

```powershell
git clone https://github.com/laurentvv/cuty-ssh.git
cd cuty-ssh

# Vérification du formatage, linter Clippy et suite de tests unitaires (21 tests)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

# Compilation du binaire release optimisé (Thin LTO + symboles épurés)
cargo build --release
```

L'exécutable compilé est généré dans `target/release/cuty-ssh.exe`.
- **Rendu graphique** : DirectX 12 par défaut via `wgpu` sur Windows (personnalisable avec `WGPU_BACKEND=vulkan` ou `WGPU_BACKEND=gl` si nécessaire).

---

## Architecture

| Module | Fichier | Rôle & Responsabilité |
| :--- | :--- | :--- |
| **Point d'entrée & Fenêtre native** | [`src/main.rs`](src/main.rs) | Démarrage de la fenêtre native `eframe 0.37` (`1320×820`), moteur DirectX 12 `wgpu`, icône cyber-cat intégrée, runtime Tokio et tests d'intégration. |
| **Configuration, Coffre DPAPI & Audit** | [`src/config/mod.rs`](src/config/mod.rs) | `SessionProfile`, `AppConfig`, bilinguisme `UiLanguage`, chiffrement Windows DPAPI (`CryptProtectData`), magasin TOFU `known_hosts.json`, moteur d'audit `AuditLogEntry`, préréglages Edge, importateur `~/.ssh/config` et PuTTY Registre. |
| **Clés PuTTY `.ppk`, Agents & `ssh-copy-id`** | [`src/ssh/ppk.rs`](src/ssh/ppk.rs) | Inspection des clés `.ppk` v2/v3 et OpenSSH/PEM/`.pub`, décodage sécurisé par `zeroize`, encodeur `.ppk` v3, résolveur/générateur de clé principale, script POSIX `ssh-copy-id`, et clients Pageant / OpenSSH Agent. |
| **Moteur de terminal VT100 & Sélection rapide** | [`src/terminal/mod.rs`](src/terminal/mod.rs) | Grille de terminal basée sur `vte 0.15`, attributs compacts `TerminalCell` sur 1 octet, écran alternatif (`?1049h`), couleurs 256/TrueColor, défilement historique, double-clic mot/token et triple-clic ligne, recherche et URLs. |
| **Enregistreur & Lecteur Asciinema v2** | [`src/terminal/recording.rs`](src/terminal/recording.rs) | Moteur d'enregistrement `.cast` JSON Lines standard, parseur d'événements et lecteur de session interactif. |
| **Protocoles asynchrones, Bastion & SFTP** | [`src/protocols/mod.rs`](src/protocols/mod.rs) | SSH2 asynchrone (`russh`), `ProxyJump` (`direct-tcpip`), vérification TOFU, déploiement de clé publique `DeployPublicKey`, SFTP en streaming (`russh-sftp`), Telnet RFC 854, Raw TCP, ConPTY local (`portable-pty`), télémétrie SSH et calculateur CIDR. |
| **Interface graphique & Cockpit SysAdmin** | [`src/ui/mod.rs`](src/ui/mod.rs) | Interface `egui 0.37` / `eframe 0.37` : thème Dark-Tech, bilinguisme FR/EN, tableau de bord Cockpit, Palette rapide (`Ctrl+K`), migration 1-clic Mot de passe vers Clé, sondes de santé de la flotte, Outils Réseau et panneau SFTP. |
| **Rendu Terminal par lots & Écran scindé** | [`src/ui/terminal_view.rs`](src/ui/terminal_view.rs) | Rendu optimisé par séquences de texte contiguës (batching), écran scindé horizontal/vertical, mode Broadcast et encodeur VT clavier/souris. |
| **Journal d'Audit local** | [`src/ui/audit_modal.rs`](src/ui/audit_modal.rs) | Modale d'exploration du journal d'audit, filtres par événement, suivi des durées et exports 1-clic CSV / JSON. |
| **Lecteur Replay Asciinema** | [`src/ui/replay_modal.rs`](src/ui/replay_modal.rs) | Lecteur Replay de sessions enregistrées avec barre de navigation temporelle et vitesse réglable (`0.5x` à `4x`). |
| **Modale TOFU Known Hosts** | [`src/ui/known_hosts_modal.rs`](src/ui/known_hosts_modal.rs) | Gestionnaire d'empreintes SHA-256 de serveurs TOFU et dialogue d'importation `~/.ssh/config`. |
| **Guide d'utilisateur illustré intégré** | [`src/ui/help_modal.rs`](src/ui/help_modal.rs) | Modale du guide d'utilisateur bilingue (`📖 Aide`), 9 chapitres illustrés, capture d'écran du Cockpit intégrée et exportateur HTML autonome. |

---

## Licence

Distribué sous la [**Licence MIT**](LICENSE).
