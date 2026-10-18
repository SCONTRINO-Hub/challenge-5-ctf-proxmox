# Challenge : 5 CTF pour Proxmox VE

Un script Bash interactif qui crée, en une fois, les **conteneurs CTF de toute une classe** sur
**Proxmox VE 8.x ou 9.x** : un conteneur LXC Debian 12 neuf par étudiant, le CTF choisi installé
dedans, des flags propres à chaque étudiant et **identiques d'une année sur l'autre**, pour que la
feuille de correction de l'enseignant resserve.

| CTF | Thème |
|---|---|
| CTF1 | Messagerie et SSH : découverte et exploitation de services réseau |
| CTF2 | Site web intranet : élévation de privilèges |
| CTF3 | Base de données : hachages et mots de passe faibles |
| CTF4 | Camelot : scénario complet autour d'un serveur web vulnérable |
| CTF5 | Ports et serveur de calcul : port-knocking et scripting Bash |

> ⚠️ **À l'attention des enseignants** : ce dépôt est public et les scénarios des CTF y sont
> lisibles. Il est destiné aux collègues, pas aux étudiants.

## Installation

```bash
cd /root
wget https://github.com/SCONTRINO-Hub/challenge-5-ctf-proxmox/releases/latest/download/ctf_creer.sh
bash ctf_creer.sh
```

Ranger le script dans `/root`, ou dans un autre dossier qui n'appartient qu'à root, et pas dans
`/tmp` (vidé au redémarrage) : les fiches des étudiants sont rapatriées à côté, et la progression
automatique relance le script depuis cet endroit.

`bash ctf_creer.sh --version` affiche la version et l'empreinte sha256 du fichier, à comparer avec
celle de la page de la release.

## Prérequis

- Proxmox VE 8.x ou 9.x, nœud seul ou cluster, quel que soit le nom des nœuds ; lancement en root.
- Un pont réseau qui donne accès à Internet : chaque CTF installe ses paquets.
- Rien à installer : bash, coreutils et les outils Proxmox suffisent. L'image Debian 12 est
  téléchargée si elle manque (il faut un stockage qui accepte les « Modèles de conteneur »).

## Déroulé du menu

1. **Choix du CTF.**
1b. **Conteneurs d'un autre CTF trouvés** : les laisser, retirer leur adresse IP, les supprimer,
   n'en remplacer que certains (numéros séparés par des espaces), ou seulement les supprimer.
2. **Paramètres** : base des ID, stockage, pont, adresses, plage d'étudiants (1 à 38).
2b. **Progression automatique** (facultative, voir plus bas).
3. **Résumé et confirmation** : rien n'est créé, débranché ni supprimé avant.
4. **Création**, puis 5. **Bilan**.

Étudiant *n* : conteneur `BASE + n`, nommé `CTFx-Etudiantnn`, adresse `<préfixe>.1nn`. Un ID ou une
adresse déjà pris sur le cluster est sauté, jamais écrasé. Relancer sur une plage plus large ne crée
que les conteneurs manquants.

Les identifiants et flags de chaque étudiant sont rapatriés dans `ctf_resultats/<CTF>/` (root
seulement). Journal : `/var/log/ctf_creer.log` (en 600, il contient les flags).

## Progression automatique (facultative)

Proposée à l'étape 2b pour les CTF 1 à 4. Une fois armée, un minuteur systemd fait une passe par
minute. Quand un étudiant a affiché **tous** les flags de son CTF (constaté par la date d'accès des
fichiers, sans jamais les lire), et que c'est confirmé une minute plus tard :

1. la configuration et les clés SSH de son conteneur sont sauvegardées ;
2. le conteneur est **détruit** ;
3. le CTF suivant est créé au même ID, à la même adresse, avec les mêmes clés SSH (l'étudiant ne voit
   pas d'alerte « host key » en se reconnectant).

Rien n'est détruit tant que la création suivante n'est pas prête, sans accès Internet, sans quorum, ni
pour un conteneur éteint, verrouillé (sauvegarde en cours) ou protégé. Au plus deux créations par
passe, et une création ratée arrête les enchaînements jusqu'à ce que l'enseignant regarde.

```bash
touch /var/lib/ctf-progression/STOP        # suspendre
rm /var/lib/ctf-progression/STOP           # reprendre
bash ctf_creer.sh --progression-retirer    # retirer le minuteur
bash ctf_creer.sh --progression --essai    # banc d'essai, dans un bac à sable
```

Réglages : `/etc/ctf-progression.conf`. Journal : `/var/log/ctf_progression_creer.log`. Sauvegardes :
`/var/backups/ctf-progression/`.

## Options

| Option | Effet |
|---|---|
| `--help` | aide |
| `--version` | version et empreinte du fichier |
| `--progression` | une passe réelle (celle que lance le minuteur) |
| `--progression --essai` | banc d'essai de la progression, sans aucune commande Proxmox réelle |
| `--progression-retirer` | retire le minuteur (réglages et journaux conservés) |

Codes de sortie : `0` tout est prêt ou abandon choisi ; `1` erreur, étudiant en échec, armement raté
ou Ctrl+D ; `130` interruption (Ctrl+C).

## Licence

**[CC BY-NC-SA 4.0](LICENSE)** : réutilisation et modification libres à des fins pédagogiques,
attribution, pas d'usage commercial, partage dans les mêmes conditions.

## Auteur

Damien SCONTRINO — BTS SIO, lycée Louis Armand (Nogent-sur-Marne).
Retours et suggestions bienvenus via les *issues* du dépôt.
