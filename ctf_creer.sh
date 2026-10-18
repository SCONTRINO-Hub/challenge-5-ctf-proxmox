#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
#
#   CHALLENGE : 5 CTF POUR PROXMOX VE
#
# ═══════════════════════════════════════════════════════════════════
#
# Nom          : ctf_creer.sh
# Description  : Crée en une fois les conteneurs CTF de toute une classe :
#                un conteneur LXC Debian 12 neuf par étudiant, le CTF
#                choisi installé dedans, des flags propres à chaque
#                étudiant et identiques d'une année sur l'autre, pour que
#                le corrigé resserve. Les fiches de chaque étudiant (flags,
#                identifiants) sont rapatriées dans ctf_resultats/, à côté
#                du script. En option, une progression automatique fait
#                passer chaque étudiant au CTF suivant quand il a fini.
#                Ranger le script dans /root (pas /tmp, vidé au
#                redémarrage) : le minuteur de la progression le relance
#                depuis cet endroit.
#
# Auteur       : Damien SCONTRINO
#                Professeur en BTS SIO - SLAM/SISR
#                Lycée Louis Armand — Nogent-sur-Marne (94)
#
# Version      : 1.2.1
# Date         : Octobre 2026
#
# Compatibilité: Proxmox VE 8.x et 9.x, nœud seul ou cluster, quel que
#                soit le nom des nœuds. La progression suit les conteneurs
#                du nœud où elle est armée.
# Dépendances  : rien à installer. bash 4.4+, coreutils, awk, sed, grep,
#                util-linux (flock) et les outils Proxmox (pct, pvesh,
#                pvesm, pveam). python3 est proposé à l'installation
#                s'il manque. Progression : systemd, un stockage qui
#                date les lectures (relatime, le réglage par défaut), et
#                sendmail, facultatif, pour le compte rendu.
# Réseau       : chaque conteneur installe ses paquets depuis Internet :
#                le pont choisi doit y donner accès.
# Usage        : ./ctf_creer.sh              en root, menu interactif
#                ./ctf_creer.sh --help       cette aide
#                ./ctf_creer.sh --version    version et empreinte
#                ./ctf_creer.sh --progression [--essai]
#                                            passe du minuteur / banc d'essai
#                ./ctf_creer.sh --progression-retirer
#                                            retire le minuteur
#
# Codes de sortie :
#                0    tout est prêt, rien à faire, ou abandon choisi
#                1    erreur, au moins un étudiant en échec, armement
#                     raté, ou Ctrl+D ; en --progression : un étudiant
#                     n'a pas pu passer au CTF suivant (voir le journal) ;
#                     en --progression --essai : un essai a échoué
#                130  interruption (Ctrl+C)
#
# ═══════════════════════════════════════════════════════════════════
#
#   LICENCE
#
#   © 2026 Damien SCONTRINO
#   BTS SIO — Lycée Louis Armand, Nogent-sur-Marne (94)
#
#   Réutilisation, modification et partage libres à des fins
#   PÉDAGOGIQUES, sous licence Creative Commons BY-NC-SA 4.0 :
#
#     - attribution : citer l'auteur d'origine ;
#     - pas d'usage commercial ;
#     - partage dans les mêmes conditions (même licence).
#
#   Texte complet de la licence :
#   https://creativecommons.org/licenses/by-nc-sa/4.0/deed.fr
#
#   Le nom de l'auteur et cette mention de licence doivent être
#   conservés dans toute copie ou version dérivée.
#
#   Ce script est fourni "en l'état", sans garantie d'aucune
#   sorte. L'auteur ne saurait être tenu responsable de tout
#   dommage direct ou indirect lié à son utilisation.
#
#   Contact : damien.scontrino@ac-creteil.fr
#             Lycée Louis Armand, Nogent-sur-Marne (94)
#
# ═══════════════════════════════════════════════════════════════════
#
#   DÉROULÉ
#
#   1.  Choix du CTF (1 à 5).
#   1b. Conteneurs d'étudiants d'un AUTRE CTF trouvés sur le cluster :
#       les laisser, les débrancher (adresse retirée, ancien réglage
#       noté), les supprimer tous, n'en remplacer que certains, ou
#       seulement les supprimer. Le choix est noté : rien n'est fait
#       avant la confirmation du résumé.
#   2.  Paramètres : base des ID, stockage, pont, adresses, étudiants.
#   2b. Progression automatique (facultative, CTF1 à CTF4).
#   3.  Résumé et confirmation.
#   4.  Création. Étudiant n : conteneur BASE+n, nom CTFx-Etudiantnn,
#       adresse <préfixe>.1nn. Un étudiant qui a déjà son conteneur
#       de ce CTF est sauté : on peut relancer sur une plage plus large.
#       Puis, si elle a été choisie, la progression est armée.
#   5.  Bilan.
#
#   Conteneurs non privilégiés, root verrouillé (accès enseignant par
#   « pct enter »), sans pool ni étiquette. Le numéro de l'étudiant est
#   passé SANS zéro devant au script d'installation : « 08 » serait lu
#   en octal et le ferait planter.
#   Journal : /var/log/ctf_creer.log, en 600 car il contient les flags.
#   Suppressions du menu : si destructions_en_attente.py est à côté du
#   script, elles passent par lui (il redemande confirmation) ; sinon
#   pvesh, après « SUPPRIMER » tapé au résumé.
#   Progression automatique : un minuteur systemd fait une passe par
#   minute. Quand un étudiant a affiché tous les flags de son CTF,
#   confirmé une minute plus tard, son conteneur est DÉTRUIT sans autre
#   question (configuration et clés SSH gardées dans
#   /var/backups/ctf-progression) et le CTF suivant créé au même ID.
#   Réglages /etc/ctf-progression.conf, journal
#   /var/log/ctf_progression_creer.log ; suspendre :
#   touch /var/lib/ctf-progression/STOP.
#
# ═══════════════════════════════════════════════════════════════════
#
# Ces trois lignes doivent rester les PREMIÈRES commandes du fichier : un
# fichier passé par Windows arrive en CRLF et bash donnerait une erreur
# incompréhensible. Chacune tient sur une ligne qui finit par une chaîne
# entre guillemets, pour qu'un « \r » final ne la casse pas ; c'est aussi
# pour ça que l'en-tête n'a aucune ligne vide. Écrites pour sh : lancé par
# « sh ctf_creer.sh », le script se relance avec bash. Lancé par « ./ctf_creer.sh »,
# un fichier en CRLF échoue avant même ces lignes (« bad interpreter ») :
# « bash ctf_creer.sh » affiche alors ce message.
[ -f "$0" ] && grep -q "$(printf '\r')" "$0" 2>/dev/null && printf '%s\n' >&2 "Ce fichier a été abîmé par un transfert Windows (retours à la ligne CRLF)." "Le réparer puis relancer :  sed -i 's/\r\$//' $0"
[ -f "$0" ] && grep -q "$(printf '\r')" "$0" 2>/dev/null && exec /bin/false "fichier en CRLF"
[ -n "${BASH_VERSION:-}" ] || exec bash "$0" "$@"

# Pas de « set -e » : chaque étape faillible est testée, et un étudiant en
# échec ne doit pas empêcher de créer les suivants.
set -u
# Locale UTF-8 : ${#texte} doit compter « é » pour un caractère (cadres alignés).
export LC_ALL=C.UTF-8


###################################################################
#                      SECTION 1 : CONSTANTES                     #
###################################################################

readonly VERSION="1.2.1"
# Numéros d'étudiants acceptés : 1 à 38, donc adresses .101 à .138.
readonly ETUDIANT_MAX=38
readonly JOURNAL="/var/log/ctf_creer.log"
readonly VERROU="/run/ctf_creer.lock"       # /run : réservé à root, contrairement à /run/lock
CHEMIN_SCRIPT="$(readlink -f "$0")"
readonly CHEMIN_SCRIPT
ICI="$(dirname "$CHEMIN_SCRIPT")"
readonly ICI
readonly RESULTATS="$ICI/ctf_resultats"
readonly DESTRUCTIONS="$ICI/destructions_en_attente.py"
# Réglages communs à tous les conteneurs
readonly CT_MEMOIRE=512 CT_SWAP=512 CT_COEURS=1 CT_DISQUE_GO=8
readonly LARG=78

# Couleurs coupées si la sortie n'est pas un terminal ou si NO_COLOR est défini.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_0=$'\e[0m'; C_GRAS=$'\e[1m'; C_PALE=$'\e[2m'
    C_ROUGE=$'\e[31m'; C_VERT=$'\e[32m'; C_JAUNE=$'\e[33m'; C_BLEU=$'\e[34m'; C_CYAN=$'\e[36m'
else
    C_0=""; C_GRAS=""; C_PALE=""; C_ROUGE=""; C_VERT=""; C_JAUNE=""; C_BLEU=""; C_CYAN=""
fi
readonly C_0 C_GRAS C_PALE C_ROUGE C_VERT C_JAUNE C_BLEU C_CYAN


###################################################################
#                 SECTION 2 : VARIABLES DE TRAVAIL                #
###################################################################

# Remplies au fil des étapes, lues par les suivantes.
NOEUD="" PVE_VER="" MODE_INFRA=""
IMAGE="" A_TELECHARGER=""                 # image Debian 12 (et son nom si à télécharger)
N_CTF="" NOM_CTF="" PREFIXE_NOM="" SUFFIXE_NOM=""
declare -A ETAT=()                        # vmid -> running / stopped
declare -A MEME_CTF=()                    # étudiant n -> « id|nœud|nom » de son conteneur de ce CTF
AUTRES_CTF=()                             # « id|nœud|nom|net0 » des conteneurs d'un autre CTF
ACTION_1B="rien"                          # rien, debrancher, supprimer, remplacer, supprimer_seul
A_DEBRANCHER=() A_SUPPRIMER=()            # même format que AUTRES_CTF
BASE_ID="" STOCKAGE="" PONT="" PREFIXE_IP="" MASQUE="" PASSERELLE="" DNS=""
ETUDIANTS=() ETU_TXT=""                   # numéros sans zéro devant
A_CREER=() DEJA_CREES=() INCOMPLETS=()
PRETS=() ECHECS=()                        # échecs : « nn:raison »
TMP_SCRIPT=""
EN_COURS=""                               # ce qui est en train d'être modifié (pour le trap)
# Progression automatique : variables en section 13.


###################################################################
#                 SECTION 3 : AFFICHAGE ET SAISIE                 #
###################################################################

# bash pur et séquences ANSI : rien à installer.
_rep() { local s="" i; for ((i = 0; i < $2; i++)); do s+="$1"; done; printf '%s' "$s"; }
# Complète à n caractères.
_pad() { local s="$1" n=$2; printf '%s%s' "$s" "$(_rep ' ' $(( n > ${#s} ? n - ${#s} : 0 )))"; }

bandeau() {
    local t g
    echo ""
    printf '%s╔%s╗%s\n' "$C_BLEU$C_GRAS" "$(_rep '═' $((LARG - 2)))" "$C_0"
    for t in "$@"; do
        (( ${#t} > LARG - 4 )) && t="${t:0:$((LARG - 5))}…"     # jamais de débordement du cadre
        g=$(( (LARG - 2 - ${#t}) / 2 ))
        printf '%s║%s%s%s║%s\n' "$C_BLEU$C_GRAS" "$(_rep ' ' "$g")" "$t" "$(_rep ' ' $((LARG - 2 - g - ${#t})))" "$C_0"
    done
    printf '%s╚%s╝%s\n' "$C_BLEU$C_GRAS" "$(_rep '═' $((LARG - 2)))" "$C_0"
}
section()     { echo ""; printf '%s %s %s%s\n' "$C_BLEU$C_GRAS" "▌ $1" "$(_rep '─' $((LARG - ${#1} - 4)))" "$C_0"; }
boite_debut() {
    printf '  %s┌─ %s %s┐%s\n' "$C_PALE" "$C_0$C_GRAS$1$C_0$C_PALE" "$(_rep '─' $((LARG - ${#1} - 7)))" "$C_0"
}
boite_ligne() { printf '  %s│%s %s %s│%s\n' "$C_PALE" "$C_0" "$(_pad "$1" $((LARG - 6)))" "$C_PALE" "$C_0"; }
boite_fin()   { printf '  %s└%s┘%s\n' "$C_PALE" "$(_rep '─' $((LARG - 4)))" "$C_0"; }

# choix_grille ÉLÉMENT... : liste numérotée [1] [2]... en colonnes, dans une boîte
choix_grille() {
    local -a it=("$@")
    local n=${#it[@]} lg=0 s i cle ligne vis
    for s in "${it[@]}"; do (( ${#s} > lg )) && lg=${#s}; done
    local cell=$(( lg + 8 )) cols rows r c
    cols=$(( (LARG - 6) / cell )); (( cols < 1 )) && cols=1
    rows=$(( (n + cols - 1) / cols ))
    for ((r = 0; r < rows; r++)); do
        ligne=""; vis=0
        for ((c = 0; c < cols; c++)); do
            i=$(( c * rows + r )); (( i < n )) || continue
            cle=$(_pad "[$((i + 1))]" 5)
            ligne+="$C_CYAN$C_GRAS$cle$C_0 $(_pad "${it[$i]}" $((cell - 6)))"
            vis=$(( vis + cell ))
        done
        printf '  %s│%s %s%s %s│%s\n' "$C_PALE" "$C_0" "$ligne" \
            "$(_rep ' ' $(( LARG - 6 - vis > 0 ? LARG - 6 - vis : 0 )))" "$C_PALE" "$C_0"
    done
}

# choix_ligne CLÉ LIBELLÉ [DÉTAIL] : « [1] libellé   détail » aligné dans une boîte
choix_ligne() {
    local cle="[$1]" lib="$2" det="${3:-}" brut vide
    brut="$(_pad "$cle" 5) $(_pad "$lib" 24) $det"
    vide=$(( LARG - 6 - ${#brut} )); (( vide < 0 )) && vide=0
    printf '  %s│%s %s%s%s %s %s%s%s%s│%s\n' "$C_PALE" "$C_0" "$C_CYAN$C_GRAS" "$(_pad "$cle" 5)" "$C_0" \
        "$(_pad "$lib" 24)" "$C_PALE" "$det" "$(_rep ' ' "$vide")" " " "$C_0"
}

ok()        { printf '  %s✔%s %s\n' "$C_VERT$C_GRAS" "$C_0" "$*"; }
# Erreurs et avertissements sur stderr : « ./ctf_creer.sh > trace.txt » les montre encore.
ko()        { printf '  %s✘ %s%s\n' "$C_ROUGE$C_GRAS" "$*" "$C_0" >&2; }
attention() { printf '  %s⚠ %s%s\n' "$C_JAUNE$C_GRAS" "$*" "$C_0" >&2; }
info()      { printf '  %s➜%s %s\n' "$C_CYAN" "$C_0" "$*"; }

# demander VARIABLE « question » : saisie lue telle quelle. La question part sur
# stderr, même sans terminal (« ssh » sans -t) : « read -p » ne l'afficherait pas.
# Ctrl+D = abandon : sans ça, chaque boucle de saisie tournerait sans fin.
demander() {
    printf '  %s?%s %s%s%s ' "$C_CYAN$C_GRAS" "$C_0" "$C_GRAS" "$2" "$C_0" >&2
    read -r "$1" && return 0
    echo ""
    info "Saisie interrompue (Ctrl+D) : abandon."
    exit 1
}

# plages 18 19 20 22 -> « 18-20 22 » (numéros triés) : tient dans les cadres
plages() {
    local out="" deb="" prec="" n
    for n in "$@"; do
        if [[ -z "$deb" ]]; then
            deb=$n
        elif (( n != prec + 1 )); then
            if (( deb == prec )); then out+="$deb "; else out+="$deb-$prec "; fi
            deb=$n
        fi
        prec=$n
    done
    if [[ -n "$deb" ]]; then
        if (( deb == prec )); then out+="$deb"; else out+="$deb-$prec"; fi
    fi
    echo "${out% }"
}

# num_de NOM : numéro d'étudiant (sans zéro devant) lu dans « CTFx-Etudiantnn… »
num_de() { [[ "$1" =~ -Etudiant([0-9]+) ]] && echo $((10#${BASH_REMATCH[1]})); }

# ipv4_valide ADRESSE : quatre nombres de 0 à 255, sans zéro devant (Proxmox refuse « 036 »)
ipv4_valide() {
    local o='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
    [[ "$1" =~ ^$o\.$o\.$o\.$o$ ]]
}

# statut_ct NŒUD ID : running, stopped, ou vide si le conteneur ne répond pas
statut_ct() {
    pvesh get "/nodes/$1/lxc/$2/status/current" --output-format json 2>/dev/null \
        | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' 2>/dev/null
}


###################################################################
#               SECTION 4 : OPTIONS ET VÉRIFICATIONS              #
###################################################################

afficher_aide() {
    cat <<EOF
ctf_creer.sh $VERSION : crée les conteneurs CTF des étudiants sur Proxmox VE.

Usage : ./ctf_creer.sh              (en root) menu interactif
        ./ctf_creer.sh --help       cette aide
        ./ctf_creer.sh --version    version et empreinte du fichier

Le menu demande le CTF (1 à 5), la base des ID, le stockage, le pont,
les adresses et la plage d'étudiants (1 à $ETUDIANT_MAX), montre un résumé,
puis crée un conteneur Debian 12 neuf par étudiant.
Étudiant n : conteneur BASE+n, adresse <préfixe>.1nn.

Fiches des étudiants : $RESULTATS/<CTF>/
Journal              : $JOURNAL

Progression automatique (facultative, proposée par le menu, CTF 1 à 4) :
        ./ctf_creer.sh --progression          une passe réelle (le minuteur)
        ./ctf_creer.sh --progression --essai  banc d'essai dans un bac à sable
        ./ctf_creer.sh --progression-retirer  retire le minuteur

Une fois armée, une passe par minute regarde si un étudiant a affiché tous
les flags de son CTF ; si oui, elle garde la configuration et les clés SSH
de son conteneur, le détruit et crée le CTF suivant, même ID, même adresse.
Suspendre : touch $PROG_STOP
Reprendre : rm $PROG_STOP
Réglages  : $PROG_CONF
Journal   : $PROG_JOURNAL

Codes de sortie : 0 tout est prêt ou abandon choisi ; 1 erreur, étudiant
en échec, armement raté ou Ctrl+D ; 130 interruption.
EOF
}

afficher_version() {
    local empreinte
    empreinte=$(sha256sum "$CHEMIN_SCRIPT" 2>/dev/null | cut -c1-12)
    echo "ctf_creer.sh $VERSION (empreinte sha256 : ${empreinte:-?})"
}

lire_options() {
    case "${1:-}" in
        "")             return 0 ;;
        -h|--help)      afficher_aide; exit 0 ;;
        -v|-V|--version) afficher_version; exit 0 ;;
        --progression)
            # Appelé par le minuteur : une passe, sans menu ni question.
            case "${2:-}" in
                "")      prog_lancer_passe; exit $? ;;
                --essai) prog_essai; exit $? ;;
                *)       echo "Option inconnue après --progression : $2 (voir --help)" >&2; exit 1 ;;
            esac ;;
        --progression-retirer)
            (( EUID == 0 )) || { ko "À lancer en root."; exit 1; }
            prog_retirer; exit $? ;;
        *)              echo "Option inconnue : $1 (voir --help)" >&2; exit 1 ;;
    esac
}

verifier_prerequis() {
    local cmd reponse
    if (( EUID != 0 )); then
        ko "Ce script doit être lancé en root (il crée des conteneurs avec pct)."; exit 1
    fi
    if ! command -v pct >/dev/null 2>&1 || ! command -v pvesh >/dev/null 2>&1 || [[ ! -d /etc/pve/nodes ]]; then
        ko "Ce script doit tourner sur un nœud Proxmox VE (pct, pvesh et /etc/pve introuvables)."; exit 1
    fi
    for cmd in pvesm pveam base64 readlink flock sha256sum; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            ko "Commande « $cmd » introuvable : installation Proxmox incomplète ?"; exit 1
        fi
    done
    if ! command -v python3 >/dev/null 2>&1; then
        if (( PROG_MODE )); then
            prog_journal "python3 absent : passe abandonnée"; exit 1
        fi
        attention "python3 est absent de ce serveur ; le script s'en sert pour lire les réponses de l'API Proxmox."
        demander reponse "L'installer maintenant avec apt (paquet python3) ? (o/N) :"
        if [[ "${reponse,,}" == o* ]] && apt-get install -y python3 >/dev/null 2>&1 \
                && command -v python3 >/dev/null 2>&1; then
            ok "python3 installé."
        else
            ko "python3 est nécessaire : apt-get install python3, puis relancer."; exit 1
        fi
    fi
    # Un seul menu à la fois : deux créations en parallèle se disputeraient ID,
    # adresses et journal. Le minuteur prend le même verrou, mais seulement pour
    # détruire et créer (prog_prendre_verrou) : gardé tout le menu, il suspend
    # les enchaînements tant que le menu est ouvert.
    if (( ! PROG_MODE )); then
        exec 9>"$VERROU" || { ko "Impossible de créer le verrou $VERROU."; exit 1; }
        if ! flock -n 9; then
            ko "ctf_creer.sh tourne déjà (autre session, ou progression automatique en train de" \
               "créer) : attendre qu'il ait fini."
            exit 1
        fi
    fi
    if ! touch "$JOURNAL" || ! chmod 600 "$JOURNAL"; then
        ko "Journal $JOURNAL impossible à créer."; exit 1
    fi
}

# Nœud local = cible du lien /etc/pve/local (le nom que Proxmox utilise, même si
# hostname rend un nom complet) ; repli sur hostname -s.
detecter_infra() {
    local json cluster nb
    NOEUD=$(basename "$(readlink -f /etc/pve/local 2>/dev/null)" 2>/dev/null)
    [[ -n "$NOEUD" && "$NOEUD" != "local" && -d "/etc/pve/nodes/$NOEUD" ]] || NOEUD=$(hostname -s)
    (( PROG_MODE )) && return 0           # le reste ne sert qu'au bandeau du menu
    PVE_VER=$(pveversion 2>/dev/null | sed -n 's#^pve-manager/\([0-9]*\.[0-9]*\).*#\1#p')
    json=$(pvesh get /cluster/status --output-format json 2>/dev/null)
    read -r cluster nb < <(python3 -I -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
c=next((i.get("name","") for i in d if i.get("type")=="cluster"),"")
n=sum(1 for i in d if i.get("type")=="node" and i.get("online")==1)
print(c or "-", n or 1)' <<< "$json" 2>/dev/null)
    if [[ -n "${cluster:-}" && "$cluster" != "-" ]]; then
        MODE_INFRA="cluster « $cluster », ${nb:-1} nœud(s) en ligne"
    else
        MODE_INFRA="nœud seul"
    fi
}

# Image Debian 12 : la plus récente déjà présente sur un stockage, sinon celle à
# télécharger (après le résumé). Cherchée avant les questions : sans image possible,
# inutile de tout remplir. Les scripts des CTF sont écrits pour Debian 12.
chercher_image() {
    local st stockage_image
    IMAGE=$(for st in $(pvesm status --content vztmpl 2>/dev/null | awk 'NR>1 && $3=="active"{print $1}'); do
                pvesm list "$st" --content vztmpl 2>/dev/null | awk 'NR>1{print $1}'
            done | grep '/debian-12-standard_' | sort -V | tail -1)
    [[ -n "$IMAGE" ]] && return 0
    # Minuteur : pas de téléchargement à chaque passe. L'image a servi à la création.
    if (( PROG_MODE )); then
        prog_journal "image Debian 12 absente des stockages : aucun CTF suivant ne peut être créé"
        return 1
    fi
    stockage_image=$(pvesm status --content vztmpl 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')
    pveam update >/dev/null 2>&1
    A_TELECHARGER=$(pveam available --section system 2>/dev/null | awk '{print $2}' \
        | grep '^debian-12-standard_' | sort -V | tail -1)
    if [[ -z "$stockage_image" || -z "$A_TELECHARGER" ]]; then
        ko "Aucune image Debian 12 sur ce serveur et téléchargement impossible" \
           "(stockage « Modèle de conteneur » ou accès Internet manquant)."
        exit 1
    fi
    IMAGE="$stockage_image:vztmpl/$A_TELECHARGER"
}

# La création prend plusieurs minutes par étudiant : une coupure SSH l'arrêterait.
# Simple conseil, le script continue.
conseiller_tmux() {
    [[ -t 0 && -z "${TMUX:-}" && -z "${STY:-}" ]] || return 0
    if command -v tmux >/dev/null 2>&1; then
        info "${C_PALE}Conseil : lancé dans « tmux », le script survit à une coupure SSH" \
             "(tmux attach pour revenir).${C_0}"
    else
        info "${C_PALE}Conseil : lancé dans tmux ou screen, le script survivrait à une coupure SSH" \
             "(apt install tmux).${C_0}"
    fi
}


###################################################################
#                 SECTION 5 : FIN ET INTERRUPTION                 #
###################################################################

nettoyer() {
    [[ -n "$TMP_SCRIPT" ]] && rm -f "$TMP_SCRIPT"
    return 0
}

# Ctrl+C, fermeture du terminal : dire où on en était, et le noter au journal.
interrompu() {
    trap - INT TERM HUP
    echo ""
    if [[ -n "$EN_COURS" ]]; then
        ko "Interrompu pendant : $EN_COURS."
        [[ "$EN_COURS" == création* ]] \
            && attention "Ce conteneur est incomplet : le supprimer avant de relancer, sinon il sera sauté."
        echo "=== $(date '+%F %T') INTERROMPU pendant : $EN_COURS ===" >> "$JOURNAL"
    else
        info "Interrompu : rien n'était en cours de modification."
    fi
    exit 130
}


###################################################################
#         SECTION 6 : ÉTAPE 1, CHOIX DU CTF ET INVENTAIRE         #
###################################################################

choisir_ctf() {
    local c
    bandeau "CRÉATION DES CONTENEURS CTF DES ÉTUDIANTS" \
            "nœud ${NOEUD} — Proxmox VE ${PVE_VER:-?} — ${MODE_INFRA}" "conteneurs neufs Debian 12"
    conseiller_tmux
    section "1. Quel CTF veux-tu créer ?"
    boite_debut "CTF disponibles"
    for c in 1 2 3 4 5; do
        choix_ligne "$c" "${CTF_NOM[$c]}" "${CTF_DESC[$c]}"
    done
    choix_ligne "q" "Quitter"
    boite_fin
    while true; do
        demander N_CTF "Ton choix :"
        [[ "$N_CTF" == [qQ] ]] && { info "Annulé."; exit 0; }
        [[ "$N_CTF" =~ ^[1-5]$ ]] && break
        ko "Choix invalide (1 à 5, ou q)."
    done
    regler_ctf "$N_CTF"
    ok "CTF choisi : ${C_GRAS}${NOM_CTF}${C_0} (${CTF_DESC[$N_CTF]})"
}

# regler_ctf N : CTF courant, et nom de ses conteneurs :
# CTF3-SQL -> CTF3-Etudiant07-SQL ; CTF1 -> CTF1-Etudiant07
regler_ctf() {
    N_CTF=$1
    NOM_CTF="${CTF_NOM[$1]}"
    PREFIXE_NOM="${NOM_CTF%%-*}"
    SUFFIXE_NOM=""
    [[ "$NOM_CTF" == *-* ]] && SUFFIXE_NOM="-${NOM_CTF#*-}"
    return 0
}

# Conteneurs d'étudiants déjà présents sur tous les nœuds, repérés par leur nom
# « CTFn-Etudiantnn… » (un modèle sans « Etudiant » dans son nom n'est jamais concerné).
#  - MEME_CTF[n] : conteneur de CE CTF déjà créé pour l'étudiant n, quel que soit son ID ;
#  - AUTRES_CTF  : conteneurs d'un autre CTF, y compris d'une ancienne numérotation
#    (même numéro, autre suffixe : « CTF3-Etudiant08-knockingPorts » n'est pas le CTF3-SQL).
inventorier_conteneurs() {
    local f id st noeud_ct conf nom n
    while read -r id st; do
        ETAT[$id]="$st"
    done < <(pvesh get /cluster/resources --type vm --output-format json 2>/dev/null \
        | python3 -I -c 'import json, sys
for r in json.load(sys.stdin):
    if r.get("type") == "lxc": print(r["vmid"], r.get("status", "?"))' 2>/dev/null)
    for f in /etc/pve/nodes/*/lxc/*.conf; do
        [[ -e "$f" ]] || continue
        id=$(basename "$f" .conf)
        noeud_ct=$(basename "$(dirname "$(dirname "$f")")")
        conf=$(sed '/^\[/,$d' "$f")             # sans les instantanés
        nom=$(awk '/^hostname:/{print $2}' <<< "$conf")
        [[ "$nom" =~ ^(CTF[0-9]+)-Etudiant([0-9]+)(-.*)?$ ]] || continue
        if [[ "${BASH_REMATCH[1]}${BASH_REMATCH[3]}" == "$NOM_CTF" ]]; then
            n=$((10#${BASH_REMATCH[2]}))
            [[ -n "${MEME_CTF[$n]:-}" ]] || MEME_CTF[$n]="$id|$noeud_ct|$nom"
            continue
        fi
        AUTRES_CTF+=("$id|$noeud_ct|$nom|$(awk '/^net0:/{print $2}' <<< "$conf")")
    done
}


###################################################################
#         SECTION 7 : ÉTAPE 1b, CONTENEURS D'UN AUTRE CTF         #
###################################################################

# Le choix est seulement NOTÉ ici. Débranchements et suppressions se font après
# la confirmation du résumé (appliquer_choix_1b) : répondre non au résumé ne
# touche à rien.
choisir_action_autres() {
    local a id noeud_ct nom net ip pont st couleur choix col4 autre_noeud=0
    (( ${#AUTRES_CTF[@]} > 0 )) || return 0
    section "1b. Conteneurs d'étudiants d'AUTRES CTF trouvés (${#AUTRES_CTF[@]})"
    # 78 colonnes : la 4e colonne donne le pont, ou le nœud si des conteneurs sont ailleurs.
    for a in "${AUTRES_CTF[@]}"; do
        IFS='|' read -r id noeud_ct nom net <<< "$a"
        [[ "$noeud_ct" == "$NOEUD" ]] || autre_noeud=1
    done
    col4="Pont"; (( autre_noeud )) && col4="Nœud"
    printf '  %s%s %s %s %s %s%s\n' "$C_GRAS" "$(_pad ID 7)" "$(_pad Nom 29)" "$(_pad État 8)" \
        "$(_pad "$col4" 12)" "Adresse" "$C_0"
    printf '  %s%s%s\n' "$C_PALE" "$(_rep '─' $((LARG - 2)))" "$C_0"
    for a in "${AUTRES_CTF[@]}"; do
        IFS='|' read -r id noeud_ct nom net <<< "$a"
        ip=$(grep -o 'ip=[^,]*' <<< "$net" | cut -d= -f2)
        ip=${ip:-sans IP}
        pont=$(grep -o 'bridge=[^,]*' <<< "$net" | cut -d= -f2)
        (( autre_noeud )) && pont="$noeud_ct"
        st="${ETAT[$id]:-?}"
        couleur="$C_PALE"; [[ "$st" == "running" ]] && couleur="$C_VERT"
        printf '  %-7s %-29s %s%-8s%s %-12s %s\n' "$id" "$nom" "$couleur" "$st" "$C_0" "$pont" "${ip%/*}"
    done
    echo ""
    boite_debut "Que faire de ces conteneurs ?"
    choix_ligne "1" "Ne rien toucher" "(défaut)"
    choix_ligne "2" "Retirer l'adresse IP" "carte débranchée, conteneurs gardés"
    choix_ligne "3" "Les supprimer tous" "puis créer le ${NOM_CTF}"
    choix_ligne "4" "En remplacer certains" "numéros d'étudiants : 18 21 25"
    choix_ligne "5" "Supprimer seulement" "sans rien créer"
    boite_fin
    while true; do
        demander choix "Ton choix [1] :"
        case "${choix:-1}" in
            1) info "Rien n'est touché."; return 0 ;;
            2) ACTION_1B="debrancher"; A_DEBRANCHER=("${AUTRES_CTF[@]}"); break ;;
            3) ACTION_1B="supprimer"; A_SUPPRIMER=("${AUTRES_CTF[@]}"); break ;;
            4) ACTION_1B="remplacer"; choisir_remplacements; break ;;
            5) ACTION_1B="supprimer_seul"; A_SUPPRIMER=("${AUTRES_CTF[@]}"); break ;;
            *) ko "Choix invalide (1 à 5)." ;;
        esac
    done
    info "Noté : rien n'est fait avant la confirmation du résumé."
}

# Choix 4 : les étudiants qui ont fini l'ancien CTF passent au nouveau. Leur ancien
# conteneur est supprimé après le résumé, puis le nouveau CTF est créé pour eux seuls.
choisir_remplacements() {
    local liste x mauvais n nn a id noeud_ct nom net trouve
    local -a mots
    while true; do
        demander liste "Numéros des étudiants qui passent au ${NOM_CTF}, séparés par des espaces (ex: 18 21 25) :"
        ETUDIANTS=(); mauvais=""
        read -r -a mots <<< "${liste//,/ }"
        for x in "${mots[@]}"; do
            if [[ "$x" =~ ^[0-9]+$ ]] && (( 10#$x >= 1 && 10#$x <= ETUDIANT_MAX )); then
                ETUDIANTS+=("$((10#$x))")
            else
                mauvais+=" $x"
            fi
        done
        mapfile -t ETUDIANTS < <(printf '%s\n' "${ETUDIANTS[@]}" | sort -nu | sed '/^$/d')
        [[ -z "$mauvais" && ${#ETUDIANTS[@]} -gt 0 ]] && break
        ko "Numéros invalides :${mauvais:- aucun numéro donné} (1 à $ETUDIANT_MAX, séparés par des espaces)."
    done
    echo ""
    boite_debut "Remplacement par le ${NOM_CTF}"
    for n in "${ETUDIANTS[@]}"; do
        nn=$(printf '%02d' "$n")
        if [[ -n "${MEME_CTF[$n]:-}" ]]; then
            IFS='|' read -r id noeud_ct nom <<< "${MEME_CTF[$n]}"
            boite_ligne "Étudiant $nn : ${NOM_CTF} déjà en place (CT $id) -> pas recréé"
        fi
        trouve=0
        for a in "${AUTRES_CTF[@]}"; do
            IFS='|' read -r id noeud_ct nom net <<< "$a"
            [[ "$(num_de "$nom")" == "$n" ]] || continue
            A_SUPPRIMER+=("$a"); trouve=1
            boite_ligne "Étudiant $nn : $nom (CT $id, ${ETAT[$id]:-?}) -> supprimé"
        done
        if (( ! trouve )) && [[ -z "${MEME_CTF[$n]:-}" ]]; then
            boite_ligne "Étudiant $nn : aucun ancien conteneur -> ${NOM_CTF} créé"
        fi
    done
    boite_fin
}


###################################################################
#                 SECTION 8 : ÉTAPE 2, PARAMÈTRES                 #
###################################################################

demander_parametres() {
    local n
    local -a stockages ponts
    section "2. Paramètres"
    while true; do
        demander BASE_ID "Base pour les ID des conteneurs (ex: 300000 -> étudiant 7 = 300007) :"
        if [[ "$BASE_ID" =~ ^[0-9]{1,9}$ ]]; then
            BASE_ID=$((10#$BASE_ID))
            (( BASE_ID + 1 >= 100 && BASE_ID + ETUDIANT_MAX <= 999999999 )) && break
        fi
        ko "Nombre attendu, de 99 à $((999999999 - ETUDIANT_MAX)) (les ID Proxmox vont de 100 à 999999999)."
    done

    echo ""
    mapfile -t stockages < <(pvesm status --content rootdir 2>/dev/null | awk 'NR>1 && $3=="active" {print $1}')
    (( ${#stockages[@]} > 0 )) || { ko "Aucun stockage actif n'accepte de conteneurs sur $NOEUD."; exit 1; }
    boite_debut "Stockages acceptant des conteneurs"
    choix_grille "${stockages[@]}"
    boite_fin
    while true; do
        demander n "Numéro du stockage :"
        if [[ "$n" =~ ^[0-9]+$ ]] && n=$((10#$n)) && (( n >= 1 && n <= ${#stockages[@]} )); then
            STOCKAGE="${stockages[$((n - 1))]}"; break
        fi
        ko "Choix invalide."
    done

    echo ""
    mapfile -t ponts < <( { pvesh get "/nodes/$NOEUD/network" --type any_bridge --output-format json 2>/dev/null \
            | python3 -I -c 'import json,sys; [print(i["iface"]) for i in json.load(sys.stdin)]' 2>/dev/null
        pvesh get /cluster/sdn/vnets --output-format json 2>/dev/null \
            | python3 -I -c 'import json, sys; [print(v["vnet"]) for v in json.load(sys.stdin)]' 2>/dev/null
        } | sort -uV)
    (( ${#ponts[@]} > 0 )) || { ko "Aucun pont réseau trouvé sur $NOEUD."; exit 1; }
    boite_debut "Ponts réseau (accès Internet requis pour les paquets)"
    choix_grille "${ponts[@]}"
    boite_fin
    if [[ " ${ponts[*]} " == *" vmbr_CTF "* ]]; then
        info "${C_PALE}lycée, 1re année : vmbr_CTF, passerelle 192.36.250.1${C_0}"
    fi
    while true; do
        demander n "Numéro du pont :"
        if [[ "$n" =~ ^[0-9]+$ ]] && n=$((10#$n)) && (( n >= 1 && n <= ${#ponts[@]} )); then
            PONT="${ponts[$((n - 1))]}"; break
        fi
        ko "Choix invalide."
    done

    echo ""
    while true; do
        demander PREFIXE_IP "Préfixe IP (ex: 192.36.250) :"
        [[ "$PREFIXE_IP" =~ ^[0-9.]+$ ]] && ipv4_valide "${PREFIXE_IP}.1" && break
        ko "Format attendu : 192.36.250"
    done
    while true; do
        demander MASQUE "Masque [/24] :"
        MASQUE="${MASQUE:-/24}"; [[ "$MASQUE" == /* ]] || MASQUE="/$MASQUE"
        [[ "$MASQUE" =~ ^/([89]|[12][0-9]|30)$ ]] && break
        ko "Masque attendu : /8 à /30 (ex. /24)."
    done
    while true; do
        demander PASSERELLE "Passerelle [${PREFIXE_IP}.1] :"
        PASSERELLE="${PASSERELLE:-${PREFIXE_IP}.1}"
        ipv4_valide "$PASSERELLE" && break
        ko "Adresse attendue (ex. ${PREFIXE_IP}.1)."
    done
    while true; do
        demander DNS "Serveur DNS des conteneurs [8.8.8.8] :"
        DNS="${DNS:-8.8.8.8}"
        ipv4_valide "$DNS" && break
        ko "Adresse attendue (ex. 8.8.8.8)."
    done
}

choisir_etudiants() {
    local debut fin n
    echo ""
    if (( ${#ETUDIANTS[@]} > 0 )); then          # liste donnée au choix 4 de l'étape 1b
        ETU_TXT="$(plages "${ETUDIANTS[@]}")"
        info "Étudiants : $ETU_TXT (liste donnée à l'étape 1b)"
    else
        while true; do
            demander debut "Numéro d'étudiant de départ (ex: 1) :"
            demander fin   "Numéro d'étudiant de fin    (ex: 27) :"
            if [[ "$debut" =~ ^[0-9]+$ && "$fin" =~ ^[0-9]+$ ]]; then
                debut=$((10#$debut)); fin=$((10#$fin))
                (( debut >= 1 && debut <= fin && fin <= ETUDIANT_MAX )) && break
            fi
            ko "Plage invalide (1 à $ETUDIANT_MAX, départ <= fin)."
        done
        mapfile -t ETUDIANTS < <(seq "$debut" "$fin")
        ETU_TXT="$debut à $fin"
        (( debut == fin )) && ETU_TXT="$debut"
    fi
    # Déjà créés pour CE CTF : sautés. Sans fiche rapatriée, l'installation n'a pas
    # abouti (réseau absent, interruption...) : ils restent sautés, mais comptés à part.
    for n in "${ETUDIANTS[@]}"; do
        if [[ -z "${MEME_CTF[$n]:-}" ]]; then
            A_CREER+=("$n")
        elif compgen -G "$RESULTATS/$NOM_CTF/etudiant$(printf '%02d' "$n")_*" >/dev/null; then
            DEJA_CREES+=("$n")
        else
            INCOMPLETS+=("$n")
        fi
    done
}


###################################################################
#           SECTION 9 : ÉTAPE 3, RÉSUMÉ ET CONFIRMATION           #
###################################################################

afficher_resume() {
    local a id noeud_ct nom net
    section "3. Résumé"
    boite_debut "Ce qui va être fait"
    if [[ "$ACTION_1B" != "supprimer_seul" ]]; then
        boite_ligne "CTF          ${NOM_CTF} (${CTF_DESC[$N_CTF]})"
        boite_ligne "Conteneurs   ${PREFIXE_NOM}-EtudiantXX${SUFFIXE_NOM}"
        boite_ligne "             ID = ${BASE_ID} + n° (étudiant 7 -> $((BASE_ID + 7)))"
        boite_ligne "Image        ${IMAGE##*/}${A_TELECHARGER:+ (sera téléchargée)}"
        boite_ligne "             $CT_MEMOIRE Mo, $CT_COEURS cœur, $CT_DISQUE_GO Go, non privilégié"
        boite_ligne "Nœud         $NOEUD"
        boite_ligne "Stockage     $STOCKAGE"
        boite_ligne "Pont         $PONT"
        boite_ligne "Adresses     ${PREFIXE_IP}.1XX${MASQUE} (étudiant 7 -> ${PREFIXE_IP}.107)"
        boite_ligne "Passerelle   $PASSERELLE      DNS  $DNS"
        boite_ligne "Étudiants    $ETU_TXT"
        boite_ligne "À créer      ${#A_CREER[@]}${A_CREER[*]:+ : $(plages "${A_CREER[@]}")}"
        if [[ "$PROGRESSION" == "oui" ]]; then
            boite_ligne "Progression  AUTOMATIQUE jusqu'au CTF${PROG_DERNIER} : conteneur détruit (après"
            boite_ligne "             sauvegarde de sa configuration) et CTF suivant créé"
            boite_ligne "             étudiants surveillés : $(plages_txt "$(prog_union)")"
            if [[ -n "$PROG_COURRIEL" ]]; then
                boite_ligne "             compte rendu à $PROG_COURRIEL"
            else
                boite_ligne "             sans courriel"
            fi
        elif [[ -n "$PROG_ARMEE" ]]; then
            boite_ligne "Progression  déjà armée (base ${PROG_ARMEE%%|*}) : inchangée"
        elif prog_autre_moteur; then
            boite_ligne "Progression  assurée par ctf-progression.timer (autre moteur du serveur)"
        elif (( N_CTF < PROG_DERNIER )); then
            boite_ligne "Progression  manuelle (tu créeras les CTF suivants toi-même)"
        fi
        (( ${#DEJA_CREES[@]} > 0 )) \
            && boite_ligne "Déjà créés   ${#DEJA_CREES[@]} : $(plages "${DEJA_CREES[@]}") (sautés, pas refaits)"
        if (( ${#INCOMPLETS[@]} > 0 )); then
            a="(aucune fiche : à supprimer puis relancer)"
            boite_ligne "Incomplets   ${#INCOMPLETS[@]} : $(plages "${INCOMPLETS[@]}") $a"
        fi
    fi
    if (( ${#A_DEBRANCHER[@]} > 0 )); then
        boite_ligne "Débranchés   d'abord, ${#A_DEBRANCHER[@]} conteneur(s) d'un autre CTF (adresse retirée)"
    fi
    if (( ${#A_SUPPRIMER[@]} > 0 )); then
        boite_ligne "Supprimés    d'abord, ${#A_SUPPRIMER[@]} ancien(s) conteneur(s) :"
        for a in "${A_SUPPRIMER[@]}"; do
            IFS='|' read -r id noeud_ct nom net <<< "$a"
            boite_ligne "               CT $id  $nom"
        done
    fi
    boite_fin
    # Rien à faire du tout : on s'arrête là, sans rien demander. Seule exception :
    # la progression, qui peut être armée sur des conteneurs déjà créés.
    if (( ${#A_CREER[@]} + ${#A_DEBRANCHER[@]} + ${#A_SUPPRIMER[@]} == 0 )); then
        if [[ "$PROGRESSION" == "oui" ]]; then
            info "Rien à créer : seule la progression automatique sera armée."
            return 0
        fi
        if (( ${#INCOMPLETS[@]} > 0 )); then
            attention "Rien à créer, mais ${#INCOMPLETS[@]} conteneur(s) ${NOM_CTF} sans fiche :" \
                      "installation à vérifier."
            exit 1
        fi
        ok "Tous ces étudiants ont déjà leur conteneur ${NOM_CTF} : rien à créer."
        exit 0
    fi
}

# Sans destructions_en_attente.py pour redemander confirmation, une suppression
# se confirme en tapant le mot entier.
confirmer() {
    local reponse question="Créer ces conteneurs ? (o/N) :"
    [[ "$ACTION_1B" == "supprimer_seul" ]] && question="Supprimer ces conteneurs ? (o/N) :"
    (( ${#A_CREER[@]} + ${#A_DEBRANCHER[@]} + ${#A_SUPPRIMER[@]} == 0 )) \
        && question="Armer la progression automatique pour ces étudiants ? (o/N) :"
    if (( ${#A_SUPPRIMER[@]} > 0 )) && [[ ! -f "$DESTRUCTIONS" ]]; then
        attention "${#A_SUPPRIMER[@]} conteneur(s) vont être supprimés : irréversible."
        demander reponse "Taper SUPPRIMER pour confirmer :"
        [[ "$reponse" == "SUPPRIMER" ]] && return 0
    else
        demander reponse "$question"
        [[ "$reponse" == [oO] ]] && return 0
    fi
    info "Annulé : rien n'a été touché."
    exit 0
}


###################################################################
#      SECTION 10 : DÉBRANCHEMENTS ET SUPPRESSIONS (étape 1b)     #
###################################################################

ERREURS_1B=0

appliquer_choix_1b() {
    (( ${#A_DEBRANCHER[@]} > 0 )) && debrancher_conteneurs "${A_DEBRANCHER[@]}"
    if (( ${#A_SUPPRIMER[@]} > 0 )); then
        section "Suppression des anciens conteneurs (${#A_SUPPRIMER[@]})"
        supprimer_conteneurs "${A_SUPPRIMER[@]}"
    fi
    EN_COURS=""
}

# Adresse et passerelle retirées, carte débranchée ; l'ancienne ligne net0 est notée
# pour pouvoir la remettre.
debrancher_conteneurs() {
    local a id noeud_ct nom net neuf sauve
    section "Débranchement des conteneurs des autres CTF ($#)"
    sauve="$RESULTATS/ip_retirees_$(date +%Y%m%d-%H%M%S).txt"
    mkdir -p "$RESULTATS" && chmod 700 "$RESULTATS"
    for a in "$@"; do
        IFS='|' read -r id noeud_ct nom net <<< "$a"
        [[ -n "$net" ]] || { info "$id ($nom) : pas de carte réseau, rien à retirer."; continue; }
        [[ "$net" == *ip=* || "$net" != *link_down=1* ]] || continue     # déjà débranché
        EN_COURS="débranchement de CT $id ($nom)"
        echo "$id $noeud_ct net0: $net" >> "$sauve"
        neuf=$(sed -E 's/,?(ip|gw|ip6|gw6)=[^,]*//g; s/,?link_down=[^,]*//g' <<< "$net"),link_down=1
        if pvesh set "/nodes/$noeud_ct/lxc/$id/config" --net0 "$neuf" >/dev/null 2>&1; then
            ok "$id ($nom) : IP retirée, carte débranchée."
        else
            ko "$id ($nom) : ÉCHEC du retrait de l'IP."
            ERREURS_1B=$((ERREURS_1B + 1))
        fi
    done
    [[ -f "$sauve" ]] || return 0
    chmod 600 "$sauve"
    info "Ancien réglage réseau noté dans $sauve (pour le remettre : « pct set <ID> --net0 <ligne> »)."
}

# supprimer_conteneurs « id|nœud|nom|net0 »... : arrêt propre (forcé au bout de
# 90 + 100 s, ils vont être détruits), puis destruction : par
# destructions_en_attente.py s'il est à côté du script, sinon directement par pvesh.
supprimer_conteneurs() {
    local a id noeud_ct nom net st t
    local -a ids=()
    for a in "$@"; do
        IFS='|' read -r id noeud_ct nom net <<< "$a"
        ids+=("$id")
        EN_COURS="arrêt de CT $id ($nom) avant suppression"
        st=$(statut_ct "$noeud_ct" "$id")
        [[ "$st" == "running" ]] || continue
        info "Arrêt de $id ($nom)..."
        pvesh create "/nodes/$noeud_ct/lxc/$id/status/shutdown" --timeout 90 >/dev/null 2>&1
        for t in {1..50}; do
            st=$(statut_ct "$noeud_ct" "$id")
            [[ "$st" == "stopped" ]] && break
            sleep 2
        done
        if [[ "$st" != "stopped" ]]; then
            attention "$id ne s'arrête pas proprement : arrêt forcé (il va être supprimé)."
            pvesh create "/nodes/$noeud_ct/lxc/$id/status/stop" >/dev/null 2>&1
        fi
    done
    # /cluster/resources, que lit destructions_en_attente.py, voit l'arrêt avec ~10 s de
    # retard : sans cette attente, il croyait les conteneurs encore allumés et refusait.
    for t in {1..20}; do
        st=$(pvesh get /cluster/resources --type vm --output-format json 2>/dev/null | python3 -I -c '
import json,sys; ids={int(x) for x in sys.argv[1:]}
print(sum(1 for r in json.load(sys.stdin) if r["vmid"] in ids and r.get("status")=="running"))' "${ids[@]}" 2>/dev/null)
        [[ "$st" == "0" ]] && break
        sleep 2
    done
    EN_COURS="suppression des conteneurs ${ids[*]}"
    if [[ -f "$DESTRUCTIONS" ]]; then
        if ! inscrire_destructions "$@"; then
            ko "Liste des destructions illisible : rien n'est supprimé."
            ERREURS_1B=$((ERREURS_1B + $#))
            return 1
        fi
        echo ""
        info "Ajoutés à la liste des destructions. Lancement de la suppression" \
             "(choisis « t » puis « TOUT DÉTRUIRE »)..."
        python3 "$DESTRUCTIONS" --seulement "$(IFS=,; echo "${ids[*]}")"
        echo ""
    else
        for a in "$@"; do
            IFS='|' read -r id noeud_ct nom net <<< "$a"
            pvesh delete "/nodes/$noeud_ct/lxc/$id" --purge 1 >/dev/null 2>&1
        done
    fi
    for a in "$@"; do               # bilan : ce qui a vraiment disparu
        IFS='|' read -r id noeud_ct nom net <<< "$a"
        if compgen -G "/etc/pve/nodes/*/lxc/$id.conf" >/dev/null; then
            attention "$id ($nom) est toujours là (non supprimé)."
            ERREURS_1B=$((ERREURS_1B + 1))
        else
            ok "$id ($nom) : supprimé."
        fi
    done
}

# Ajoute les conteneurs à destructions_en_attente.json (même dossier que le script
# de destruction), sans doublon. Écriture dans un fichier temporaire puis
# renommage : une coupure ne laisse jamais une liste à moitié écrite.
inscrire_destructions() {
    DESTR="$DESTRUCTIONS" python3 -I - "$@" <<'PY'
import datetime, json, os, sys
L = os.path.join(os.path.dirname(os.environ["DESTR"]), "destructions_en_attente.json")
try:
    liste = json.load(open(L)) if os.path.exists(L) else []
except Exception as e:
    sys.exit(f"liste {L} illisible ({e})")
deja = {e["vmid"] for e in liste if not e.get("noeud")}     # entrées d'un nœud hors cluster : autre vmid
for a in sys.argv[1:]:
    vmid, noeud, nom = a.split("|")[:3]
    if int(vmid) not in deja:
        liste.append({"vmid": int(vmid), "motif": f"conteneur CTF étudiant {nom} remplacé (ctf_creer.sh)",
                      "ajoutee_le": datetime.date.today().isoformat(), "par": "ctf_creer.sh"})
json.dump(liste, open(L + ".tmp", "w"), ensure_ascii=False, indent=1)
os.replace(L + ".tmp", L)
PY
}


###################################################################
#                  SECTION 11 : ÉTAPE 4, CRÉATION                 #
###################################################################

# Tout ce qui peut échouer passe AVANT les débranchements et suppressions (menu)
# et avant la destruction (progression). Rend 1 au premier échec.
preparer_creation() {
    if [[ -n "$A_TELECHARGER" ]]; then
        info "Téléchargement de $A_TELECHARGER sur ${IMAGE%%:*}..."
        pveam download "${IMAGE%%:*}" "$A_TELECHARGER" || { ko "Téléchargement échoué."; return 1; }
        A_TELECHARGER=""
    fi
    if ! mkdir -p "$RESULTATS/$NOM_CTF" || ! chmod 700 "$RESULTATS"; then
        ko "Dossier $RESULTATS/$NOM_CTF impossible à créer."; return 1
    fi
    TMP_SCRIPT=$(mktemp) || { ko "Impossible de créer un fichier temporaire."; return 1; }
    base64 -d <<< "${CTF_B64[$N_CTF]}" > "$TMP_SCRIPT" || { ko "Script embarqué illisible."; return 1; }
}

RESEAU_VU=0     # au moins un conteneur a eu Internet : le réglage réseau est bon

creer_tous() {
    local i reste rang=0 rc
    echo "=== $(date '+%F %T') ${NOM_CTF} étudiants ${ETU_TXT} base ${BASE_ID} ===" >> "$JOURNAL"
    section "4. Création (${#A_CREER[@]} étudiant(s))"
    for i in "${A_CREER[@]}"; do
        rang=$((rang + 1))
        creer_conteneur "$i" "$rang"; rc=$?
        if (( rc == 2 )); then
            # Le premier conteneur n'a pas eu Internet : les suivants non plus.
            for reste in "${A_CREER[@]:$rang}"; do ECHECS+=("$(printf '%02d' "$reste"):non lancé (réseau)"); done
            break
        fi
    done
    EN_COURS=""
}

# Les scripts d'installation laissent certains fichiers de flags lisibles par tous
# les comptes du conteneur : on les restreint à leur propriétaire (chmod ne lit
# pas les fichiers).
restreindre_droits_flags() {
    local ctid=$1 ok_droits=0
    case "$N_CTF" in
        1) pct exec "$ctid" -- find /home -mindepth 2 -maxdepth 2 -name flag.txt \
               -exec chmod 600 {} + 2>/dev/null && ok_droits=1 ;;
        2) pct exec "$ctid" -- chmod 700 /opt/ctf_tracking 2>/dev/null \
               && pct exec "$ctid" -- chmod 600 /opt/ctf_tracking/flags.csv 2>/dev/null && ok_droits=1 ;;
        *) return 0 ;;
    esac
    if (( ok_droits )); then
        ok "Droits des flags restreints."
    else
        attention "Droits des flags NON restreints (CT $ctid) : à corriger à la main."
    fi
}

# creer_conteneur N RANG : crée, démarre et installe le conteneur de l'étudiant N.
# Rend 0 (prêt), 1 (échec, on passe au suivant), 2 (réseau faux : tout arrêter).
creer_conteneur() {
    local i=$1 rang=$2 nn ctid nom_ct ip occ rc fiches f
    nn=$(printf "%02d" "$i")
    ctid=$((BASE_ID + i))
    nom_ct="${PREFIXE_NOM}-Etudiant${nn}${SUFFIXE_NOM}"
    ip="${PREFIXE_IP}.1${nn}${MASQUE}"
    echo ""
    printf '%s[%d/%d] Étudiant %s%s  %sCT %s · %s · %s%s\n' "$C_GRAS$C_BLEU" "$rang" "${#A_CREER[@]}" "$nn" "$C_0" \
        "$C_PALE" "$ctid" "$nom_ct" "$ip" "$C_0"

    if compgen -G "/etc/pve/nodes/*/lxc/$ctid.conf" >/dev/null \
            || compgen -G "/etc/pve/nodes/*/qemu-server/$ctid.conf" >/dev/null; then
        occ=$(awk '/^(hostname|name):/{print $2; exit}' /etc/pve/nodes/*/{lxc,qemu-server}/"$ctid".conf 2>/dev/null)
        ko "L'ID $ctid est déjà pris sur le cluster${occ:+ (par « $occ »)} : ignoré (rien n'est écrasé)."
        ECHECS+=("$nn:ID pris"); return 1
    fi
    if grep -qsF "ip=${ip%/*}/" /etc/pve/nodes/*/lxc/*.conf /etc/pve/nodes/*/qemu-server/*.conf; then
        occ=$(grep -lsF "ip=${ip%/*}/" /etc/pve/nodes/*/lxc/*.conf /etc/pve/nodes/*/qemu-server/*.conf \
            | xargs -n1 basename | tr '\n' ' ')
        ko "L'adresse ${ip%/*} est déjà utilisée par : ${occ}— ignoré."
        ECHECS+=("$nn:IP prise"); return 1
    fi

    EN_COURS="création de l'étudiant $nn (CT $ctid)"
    if ! pct create "$ctid" "$IMAGE" --hostname "$nom_ct" --ostype debian \
            --rootfs "$STOCKAGE:$CT_DISQUE_GO" --memory "$CT_MEMOIRE" --swap "$CT_SWAP" --cores "$CT_COEURS" \
            --unprivileged 1 --features nesting=1 \
            --net0 "name=eth0,bridge=$PONT,ip=$ip,gw=$PASSERELLE" \
            --nameserver "$DNS" --onboot 0 \
            --description "${NOM_CTF} — étudiant ${nn} (ctf_creer.sh, $(date +%F))" >> "$JOURNAL" 2>&1; then
        ko "Échec de la création (voir $JOURNAL)."
        ECHECS+=("$nn:création"); return 1
    fi
    ok "Conteneur créé."

    if ! pct start "$ctid"; then
        ko "Échec du démarrage."; ECHECS+=("$nn:démarrage"); return 1
    fi
    ok "Conteneur démarré."
    # Chaque essai est borné à 5 s : sans réseau, une résolution DNS peut bloquer
    # près d'une minute, et 20 essais auraient duré vingt minutes.
    for _ in {1..20}; do
        timeout 5 pct exec "$ctid" -- getent hosts deb.debian.org &>/dev/null && break
        sleep 2
    done
    if ! timeout 5 pct exec "$ctid" -- getent hosts deb.debian.org &>/dev/null; then
        ko "Pas d'accès Internet depuis le conteneur (DNS $DNS, passerelle $PASSERELLE) :" \
           "script non lancé, conteneur laissé pour diagnostic."
        ECHECS+=("$nn:réseau")
        if (( ! RESEAU_VU )); then
            attention "Aucun conteneur n'a encore eu Internet : réglage réseau faux. Arrêt, pour ne pas" \
                      "en laisser un par étudiant."
            attention "Supprimer CT $ctid, corriger passerelle et DNS, puis relancer."
            return 2
        fi
        return 1
    fi
    RESEAU_VU=1
    ok "Accès Internet vérifié."

    if ! pct push "$ctid" "$TMP_SCRIPT" /root/script.sh --perms 0700; then
        ko "Impossible de déposer le script dans le conteneur : installation non lancée."
        ECHECS+=("$nn:dépôt du script"); return 1
    fi
    info "Installation du ${NOM_CTF} (d'une à une dizaine de minutes selon le CTF)..."
    printf '%s' "$C_PALE"
    # Numéro sans zéro devant, sur l'entrée standard ET en argument : selon le CTF,
    # le script d'installation le lit par read ou par $1.
    pct exec "$ctid" -- bash /root/script.sh "$i" <<< "$i" 2>&1 | tee -a "$JOURNAL"
    rc=${PIPESTATUS[0]}
    printf '%s' "$C_0"

    if (( rc == 0 )); then
        restreindre_droits_flags "$ctid"
        # Témoin de la progression automatique (section 13), lisible par root seul.
        pct exec "$ctid" -- sh -c "echo ctf > $PROG_TEMOIN && chmod 600 $PROG_TEMOIN" 2>/dev/null
    fi

    # Rapatrier ce que le script a généré (flags, identifiants) pour l'enseignant.
    # Sans fiche, le corrigé ignorerait l'étudiant : c'est un échec.
    fiches=0
    for f in /opt/ctf_tracking/flags.csv "/root/infos_tp1_${i}.txt"; do
        pct exec "$ctid" -- test -f "$f" 2>/dev/null || continue
        if pct pull "$ctid" "$f" "$RESULTATS/$NOM_CTF/etudiant${nn}_$(basename "$f")"; then
            fiches=$((fiches + 1))
        else
            attention "$f non rapatrié (CT $ctid)."
        fi
    done
    chmod 600 "$RESULTATS/$NOM_CTF"/* 2>/dev/null
    EN_COURS=""

    if (( rc != 0 )); then
        ko "Étudiant $nn : le script d'installation a échoué (code $rc, voir $JOURNAL)."
        ECHECS+=("$nn:installation"); return 1
    fi
    if (( fiches == 0 )); then
        ko "Étudiant $nn : installé, mais aucune fiche rapatriée dans $RESULTATS/$NOM_CTF."
        ECHECS+=("$nn:fiche non rapatriée"); return 1
    fi
    ok "${C_VERT}${C_GRAS}Étudiant $nn : prêt.${C_0}"
    PRETS+=("$nn")
}


###################################################################
#                   SECTION 12 : ÉTAPE 5, BILAN                   #
###################################################################

# Rend 0 si tout est prêt (progression armée comprise, si elle a été choisie), 1
# sinon : c'est le code de sortie du script.
afficher_bilan() {
    local e n prets=""
    local -a deja_nn=() incomplets_nn=()
    for n in "${DEJA_CREES[@]}"; do deja_nn+=("$(printf '%02d' "$n")"); done
    for n in "${INCOMPLETS[@]}"; do incomplets_nn+=("$(printf '%02d' "$n")"); done
    section "5. Bilan"
    if [[ "$ACTION_1B" == "supprimer_seul" ]]; then
        boite_debut "Suppression des conteneurs des autres CTF"
        boite_ligne "Supprimés    : $(( ${#A_SUPPRIMER[@]} - ERREURS_1B )) sur ${#A_SUPPRIMER[@]}"
    else
        boite_debut "${NOM_CTF} — étudiants ${ETU_TXT}"
        for n in "${PRETS[@]}"; do prets+="$((10#$n)) "; done
        boite_ligne "✔ Prêts      : ${#PRETS[@]}  $(plages_txt "$prets")"
        (( ${#deja_nn[@]} > 0 )) && boite_ligne "↷ Déjà là    : ${#deja_nn[@]}  ${deja_nn[*]} (sautés)"
        if (( ${#incomplets_nn[@]} > 0 )); then
            boite_ligne "⚠ Incomplets : ${#incomplets_nn[@]}  ${incomplets_nn[*]} (à supprimer puis relancer)"
        fi
        boite_ligne "✘ En échec   : ${#ECHECS[@]}"
        for e in "${ECHECS[@]}"; do boite_ligne "     étudiant ${e%%:*} — ${e#*:}"; done
        if (( ERREURS_1B > 0 )); then
            boite_ligne "✘ Étape 1b   : $ERREURS_1B conteneur(s) non débranché(s) ou non supprimé(s)"
        fi
        boite_ligne "Flags        : $RESULTATS/$NOM_CTF/"
        if [[ "$PROGRESSION" == "oui" ]]; then
            if (( PROG_ERREUR )); then
                boite_ligne "✘ Progression : NON armée (voir le message plus haut)"
            else
                boite_ligne "Progression  : armée, étudiants $(plages_txt "$PROG_ETUDIANTS")"
            fi
        fi
    fi
    boite_ligne "Journal      : $JOURNAL"
    boite_fin
    (( ${#A_CREER[@]} + ${#A_DEBRANCHER[@]} + ${#A_SUPPRIMER[@]} > 0 )) \
        && echo "=== $(date '+%F %T') fin : ${#PRETS[@]} prêt(s), ${#ECHECS[@]} en échec ===" >> "$JOURNAL"
    if (( ${#ECHECS[@]} + ${#INCOMPLETS[@]} + ERREURS_1B + PROG_ERREUR == 0 )); then
        if [[ "$ACTION_1B" == "supprimer_seul" ]]; then ok "Terminé."; else ok "Tout est prêt."; fi
        return 0
    fi
    attention "Des étudiants ou des conteneurs sont à reprendre (voir le journal)."
    return 1
}


###################################################################
#               SECTION 13 : PROGRESSION AUTOMATIQUE              #
###################################################################

# Un étudiant qui a affiché tous les flags de son CTF passe au suivant : son
# conteneur est détruit puis recréé avec le CTF suivant, même ID, même adresse,
# mêmes clés SSH.
#
# Flag affiché = atime > mtime : les conteneurs sont montés en « relatime », la
# première lecture d'un fichier fait passer son atime devant son mtime. « stat »
# ne change pas l'atime : le contenu d'un flag n'est jamais lu par ce script.
#
# Une passe lit la configuration de chaque conteneur dans /etc/pve et la date de
# quelques fichiers, sans lancer d'outil Proxmox : 0,3 s pour 36 conteneurs. Seule
# la première cherche le disque de chaque conteneur (une vingtaine de secondes),
# gardé ensuite en cache. Le verrou du menu n'est pris que pour détruire et créer.

# Pas en lecture seule : le banc d'essai détourne ces chemins vers un bac à sable.
PROG_CONF="/etc/ctf-progression.conf"
PROG_ETAT="/var/lib/ctf-progression"
PROG_STOP="$PROG_ETAT/STOP"
PROG_JOURNAL="/var/log/ctf_progression_creer.log"
PROG_SAUVE="/var/backups/ctf-progression"
PROG_UNITES="/etc/systemd/system"
PROG_LXC="/etc/pve/local/lxc"       # configurations des conteneurs de ce nœud
PROG_MEMBRES="/etc/pve/.members"    # état du cluster (quorum)
PROG_UNITE="ctf-progression-creer"
readonly PROG_ECART=60              # secondes entre les deux relevés des flags
readonly PROG_DERNIER=5             # le CTF5 clôt la chaîne : rien n'est détruit après
readonly PROG_MAX_CREATIONS=2       # créations par passe : une passe reste courte
# Posé à la création, lu par aucun CTF. Lu dans l'heure des flags = lecture de tout
# le disque (sauvegarde, recherche sur tout le système), pas l'étudiant.
readonly PROG_TEMOIN="/var/lib/ctf-temoin"
# Clés de /etc/ctf-progression.conf. Elles sont relues par les versions suivantes :
# ne pas en renommer une sans reprendre l'ancienne dans prog_lire_conf.
PROG_CLES="BASE_ID STOCKAGE PONT PREFIXE_IP MASQUE PASSERELLE DNS"
PROG_CLES+=" PROG_ETUDIANTS PROG_ETU_DEBUT PROG_ETU_FIN PROG_COURRIEL"
readonly PROG_CLES

PROG_SCRIPT="$CHEMIN_SCRIPT"        # fichier que lance le minuteur (le banc le détourne)
PROG_MODE=0                         # 1 : lancé par le minuteur, rien à l'écran
PROGRESSION="non"                   # réponse à la question de l'étape 2b
PROG_ETUDIANTS=""                   # numéros surveillés, séparés par des espaces
PROG_ETU_DEBUT="" PROG_ETU_FIN=""   # premier et dernier (ancien format, toujours écrits)
PROG_ANCIENS=""                     # étudiants déjà surveillés, gardés au réarmement
PROG_ARMEE=""                       # progression déjà en place : voir prog_armee
PROG_ERREUR=0                       # 1 : progression demandée mais non armée
PROG_COURRIEL=""                    # adresse facultative du compte rendu
PROG_EN_COURS=""                    # enchaînement en cours (pour le trap)
PROG_VERROU_PRIS=0
PROG_ATIME=""                       # atime du dernier flag trouvé lu

# Flag final de chaque CTF, puis les flags intermédiaires. Un intermédiaire
# présent mais jamais affiché bloque le passage ; absent, il n'est pas exigé.
# Le CTF1 nomme le compte d'après une lettre propre à chaque étudiant : l'étoile
# évite de la recalculer ici.
declare -rA PROG_FLAG_FINAL=(
    [1]="/home/*david/flag.txt"
    [2]="/root/root.txt"
    [3]="/home/scontrino/flag.txt"
    [4]="/root/flag_root.txt"
    [5]="/root/flag_calcul.txt"
)
declare -rA PROG_FLAGS_AUTRES=(
    [2]="/var/www/html/flag.txt"
    [4]="/var/www/flags/flag_www.txt"
    [5]="/home/admin/flag.txt"
)

# Le journal reçoit les sorties d'installation, flags compris : toujours en 600.
prog_journal() {
    [[ -e "$PROG_JOURNAL" ]] || ( umask 077; : >> "$PROG_JOURNAL" )
    printf '%s  %s\n' "$(date '+%F %T')" "$*" >> "$PROG_JOURNAL"
}

# prog_noter_une_fois CLÉ MESSAGE... : une seule ligne au journal tant que la
# situation dure (rend 0 la première fois) ; prog_oublier CLÉ la rouvre.
prog_noter_une_fois() {
    local cle=$1; shift
    [[ -e "$PROG_ETAT/note-$cle" ]] && return 1
    : > "$PROG_ETAT/note-$cle"
    prog_journal "$*"
    return 0
}
prog_oublier() { rm -f "$PROG_ETAT/note-$1"; }

# plages_txt « 3 4 5 9 » -> « 3-5 9 »
plages_txt() { local -a l; read -r -a l <<< "$1"; plages "${l[@]}"; }

# Un autre moteur de progression (ctf-progression.timer) suit déjà les CTF de ce
# serveur : deux minuteurs se disputeraient les mêmes conteneurs.
prog_autre_moteur() { [[ -e "$PROG_UNITES/ctf-progression.timer" ]]; }


# ── 13a. Lecture des flags ───────────────────────────────────────

# prog_conf_ct ID : « nom volume » lus dans la configuration du conteneur (sans
# les instantanés). Pas de « pct config » : une seconde de calcul par appel.
prog_conf_ct() {
    sed '/^\[/,$d' "$PROG_LXC/$1.conf" 2>/dev/null \
        | awk -F'[ ,]' '/^hostname:/{n=$2} /^rootfs:/{v=$2} END{if (n != "") print n, v}'
}

# prog_racine ID VOLUME : dossier du conteneur vu depuis l'hôte (ZFS, dossier).
# Échoue si le stockage n'est pas lisible depuis l'hôte (LVM-thin par exemple) :
# la lecture passe alors par le conteneur. Réponse gardée en cache par volume.
prog_racine() {
    local vmid=$1 volume=$2 cache="$PROG_ETAT/racine-$1" v chemin
    [[ -n "$volume" ]] || return 1
    if [[ -r "$cache" ]] && read -r v chemin < "$cache" && [[ "$v" == "$volume" ]]; then
        [[ "$chemin" != "-" && -d "$chemin" ]] || return 1
        printf '%s' "$chemin"; return 0
    fi
    chemin=$(pvesm path "$volume" 2>/dev/null)
    if [[ -z "$chemin" || ! -d "$chemin" ]]; then
        printf '%s -\n' "$volume" > "$cache"
        return 1
    fi
    printf '%s %s\n' "$volume" "$chemin" > "$cache"
    printf '%s' "$chemin"
}

# prog_dates ACCÈS MODIF : 0 = lu (et PROG_ATIME), 1 = pas lu, 2 = illisible.
prog_dates() {
    [[ "$1" =~ ^[0-9]+$ && "$2" =~ ^[0-9]+$ ]] || return 2
    (( $1 > $2 )) || return 1
    PROG_ATIME=$1
    return 0
}

# prog_flag_lu ID RACINE MOTIF : 0 = lu, 1 = pas lu, 2 = introuvable.
# RACINE vide : on passe par le conteneur, plus lent mais universel.
# Le motif n'est PAS entre guillemets : c'est ce qui ouvre l'étoile du CTF1.
prog_flag_lu() {
    local vmid=$1 racine=$2 motif=$3 fichier acces modif sortie
    if [[ -n "$racine" ]]; then
        for fichier in "$racine"$motif; do
            [[ -f "$fichier" ]] || continue
            read -r acces modif < <(stat -c '%X %Y' "$fichier" 2>/dev/null) || return 2
            prog_dates "$acces" "$modif"; return $?
        done
        return 2
    fi
    sortie=$(timeout 20 pct exec "$vmid" -- sh -c "stat -c '%X %Y' $motif 2>/dev/null | head -1" \
        2>/dev/null) || return 2
    read -r acces modif <<< "$sortie"
    prog_dates "${acces:-}" "${modif:-}"
}

# prog_ctf_fini ID RACINE CTF : 0 = tous les flags affichés, 1 = pas encore,
# 2 = flag final introuvable, 3 = lecture groupée (témoin lu dans l'heure).
prog_ctf_fini() {
    local vmid=$1 racine=$2 ctf=$3 f final rc
    prog_flag_lu "$vmid" "$racine" "${PROG_FLAG_FINAL[$ctf]}"; rc=$?
    (( rc == 0 )) || return "$rc"
    final=$PROG_ATIME
    for f in ${PROG_FLAGS_AUTRES[$ctf]:-}; do
        prog_flag_lu "$vmid" "$racine" "$f"; rc=$?
        (( rc == 1 )) && return 1          # présent mais jamais affiché
    done
    if prog_flag_lu "$vmid" "$racine" "$PROG_TEMOIN" \
            && (( PROG_ATIME - final <= 3600 && final - PROG_ATIME <= 3600 )); then
        return 3
    fi
    return 0
}


# ── 13b. Garde-fous et destruction ───────────────────────────────

# Le nom doit être celui que ce script donne au CTF (« CTF3-Etudiant07-SQL »),
# avec le numéro de l'étudiant, ET l'ID doit valoir BASE_ID + numéro.
prog_conforme() {
    local vmid=$1 nom=$2 numero=$3
    [[ "$nom" =~ ^CTF([1-5])-Etudiant([0-9]{2})(-.+)?$ ]] || return 1
    (( 10#${BASH_REMATCH[2]} == numero )) || return 1
    [[ "CTF${BASH_REMATCH[1]}${BASH_REMATCH[3]}" == "${CTF_NOM[${BASH_REMATCH[1]}]}" ]] || return 1
    (( vmid == BASE_ID + numero )) || return 1
    return 0
}

# Dernière barrière avant « pct destroy » : même appelée par erreur, cette fonction
# refuse tout conteneur qui n'est pas un CTF de ce script. La configuration et les
# clés d'hôte SSH sont gardées dans DOSSIER : le CTF suivant reprend les clés.
# Rend 0 (détruit), 1 (refusé), 3 (pas cette fois : conteneur rendu à l'étudiant).
prog_detruire() {
    local vmid=$1 nom=$2 numero=$3 dossier=$4 cle actuel
    actuel=$(prog_conf_ct "$vmid"); actuel=${actuel%% *}
    if ! prog_conforme "$vmid" "$nom" "$numero" || [[ "$actuel" != "$nom" ]]; then
        prog_journal "REFUS de détruire $vmid « $nom » : hors du périmètre autorisé"
        return 1
    fi
    if ! timeout 60 pct config "$vmid" > "$dossier/$vmid.conf" 2>/dev/null; then
        prog_journal "  configuration de $vmid illisible : rien n'est détruit cette fois"
        return 3
    fi
    chmod 600 "$dossier/$vmid.conf"
    prog_journal "  configuration sauvegardée : $dossier/$vmid.conf"
    # « pct pull » ne marche que sur un conteneur allumé : avant l'arrêt.
    mkdir -p "$dossier/ssh" && chmod 700 "$dossier/ssh"
    for cle in ssh_host_ed25519_key ssh_host_ecdsa_key ssh_host_rsa_key; do
        if ! timeout 30 pct pull "$vmid" "/etc/ssh/$cle" "$dossier/ssh/$cle" >/dev/null 2>&1 \
                || ! timeout 30 pct pull "$vmid" "/etc/ssh/$cle.pub" "$dossier/ssh/$cle.pub" >/dev/null 2>&1; then
            rm -f "$dossier/ssh/$cle" "$dossier/ssh/$cle.pub"
        fi
    done
    chmod 600 "$dossier/ssh/"* 2>/dev/null
    timeout 120 pct shutdown "$vmid" --timeout 60 >/dev/null 2>&1 \
        || timeout 60 pct stop "$vmid" >/dev/null 2>&1
    if [[ "$(timeout 60 pct status "$vmid" 2>/dev/null)" != "status: stopped" ]]; then
        prog_journal "  $vmid ne s'arrête pas : rien n'est détruit cette fois"
        prog_rallumer "$vmid"
        return 3
    fi
    prog_journal "  conteneur arrêté"
    # Sans --purge : l'ID reste dans les tâches de sauvegarde. Ses droits, son pool
    # et son pare-feu propres, eux, partent avec lui.
    if ! timeout 300 pct destroy "$vmid" >> "$PROG_JOURNAL" 2>&1; then
        prog_journal "  « pct destroy $vmid » a échoué : rien n'est créé à la place"
        prog_rallumer "$vmid"
        return 3
    fi
    if compgen -G "/etc/pve/nodes/*/lxc/$vmid.conf" >/dev/null; then
        prog_journal "  $vmid existe encore après destruction : on s'arrête là"
        return 1
    fi
    prog_journal "  supprimé, ID $vmid libre"
    return 0
}

# Rend son conteneur à l'étudiant après une destruction qui n'a pas abouti.
prog_rallumer() {
    timeout 120 pct start "$1" >/dev/null 2>&1
    if [[ "$(timeout 60 pct status "$1" 2>/dev/null)" == "status: running" ]]; then
        prog_journal "  $1 rallumé : l'étudiant le retrouve tel quel"
    else
        prog_journal "  $1 n'a PAS pu être rallumé : à faire à la main (pct start $1)"
    fi
}

# prog_reposer_cles ID DOSSIER : clés d'hôte SSH de l'ancien conteneur dans le
# nouveau. Par « pct push » : dans un conteneur non privilégié, les UID sont décalés.
prog_reposer_cles() {
    local vmid=$1 dossier=$2 f nom poses=0 droits
    for f in "$dossier"/ssh_host_*; do
        [[ -f "$f" ]] || continue
        nom=$(basename "$f")
        droits=0600; [[ "$nom" == *.pub ]] && droits=0644
        timeout 30 pct push "$vmid" "$f" "/etc/ssh/$nom" --perms "$droits" >/dev/null 2>&1 && poses=$((poses + 1))
    done
    if (( poses == 0 )); then
        prog_journal "  clés SSH non reportées : l'étudiant devra faire « ssh-keygen -R <adresse> »"
        return 1
    fi
    timeout 60 pct exec "$vmid" -- systemctl restart ssh >/dev/null 2>&1
    prog_journal "  clés SSH reportées ($poses fichiers) : l'empreinte du serveur ne change pas"
    return 0
}


# ── 13c. Une passe de contrôle ───────────────────────────────────

# Mémoire par conteneur, dans vu-<ID> : « CTF date » à la première observation des
# flags, « fini » quand le dernier CTF est terminé, « echec » quand la destruction
# a été refusée pour de bon. essais-<ID> compte les destructions qui n'ont pas
# abouti. Le fichier « disjoncte » arrête tous les enchaînements jusqu'à son retrait.
prog_vu_lire()    { cat "$PROG_ETAT/vu-$1" 2>/dev/null; }
prog_vu_ecrire()  { printf '%s %s\n' "$2" "$3" > "$PROG_ETAT/vu-$1"; }
prog_vu_effacer() { rm -f "$PROG_ETAT/vu-$1" "$PROG_ETAT/essais-$1"; }
readonly PROG_MAX_ESSAIS=5

# Sans quorum, /etc/pve est en lecture seule : pct destroy effacerait le disque
# mais laisserait la configuration.
prog_quorum() {
    grep -q '"cluster"' "$PROG_MEMBRES" 2>/dev/null || return 0      # nœud seul
    grep -q '"quorate": *1' "$PROG_MEMBRES" 2>/dev/null
}

# Le conteneur en place a le même pont, la même adresse et le même DNS que le
# suivant : s'il n'a pas Internet, le CTF suivant ne s'installerait pas.
prog_internet() {
    timeout 10 pct exec "$1" -- getent hosts deb.debian.org >/dev/null 2>&1
}

# L'adresse du CTF suivant ne doit être prise par aucune autre machine (hors
# instantanés), et le stockage doit répondre : vérifié avant de détruire.
prog_place_libre() {
    local vmid=$1 ip=$2 f
    for f in /etc/pve/nodes/*/lxc/*.conf /etc/pve/nodes/*/qemu-server/*.conf; do
        [[ -e "$f" && "$(basename "$f" .conf)" != "$vmid" ]] || continue
        sed '/^\[/,$d' "$f" | grep -qF "ip=$ip/" && return 1
    done
    pvesm status --storage "$STOCKAGE" 2>/dev/null | awk 'NR > 1 && $3 == "active" {ok = 1} END {exit !ok}'
}

# Pris pour détruire et créer seulement, gardé jusqu'à la fin de la passe.
prog_prendre_verrou() {
    (( PROG_VERROU_PRIS )) && return 0
    { exec 9>"$VERROU"; } 2>/dev/null || return 1
    flock -n 9 || return 1
    PROG_VERROU_PRIS=1
}

# prog_enchainer NUMERO ID NOM CTF : détruit le conteneur et crée le CTF suivant.
# Tout ce qui peut échouer passe AVANT la destruction. Rend :
#   0 fait ;  1 rien n'est détruit, la passe suivante réessaie ;
#   2 détruit, création en échec ;  3 pas d'Internet, rien n'est détruit ;
#   4 destruction refusée pour de bon (conteneur protégé, ou trop d'essais).
prog_enchainer() {
    local numero=$1 vmid=$2 nom=$3 ctf=$4 suivant=$(( $4 + 1 )) nn dossier conf essais rc
    nn=$(printf '%02d' "$numero")
    if ! prog_prendre_verrou; then
        prog_noter_une_fois verrou "enchaînements reportés : le menu de ctf_creer.sh est ouvert"
        return 1
    fi
    prog_oublier verrou
    conf=$(sed '/^\[/,$d' "$PROG_LXC/$vmid.conf" 2>/dev/null)
    if grep -q '^lock:' <<< "$conf"; then
        prog_noter_une_fois "lock-$vmid" "étudiant $nn : $vmid verrouillé (sauvegarde, instantané…) :" \
            "passage remis à plus tard"
        return 1
    fi
    prog_oublier "lock-$vmid"
    if grep -qx 'protection: 1' <<< "$conf"; then
        prog_journal "étudiant $nn : $vmid est protégé (protection: 1) : il n'est pas détruit"
        return 4
    fi
    if ! prog_internet "$vmid"; then
        prog_noter_une_fois internet "pas d'accès Internet depuis les conteneurs : aucun passage tant que ça dure"
        return 3
    fi
    prog_oublier internet
    regler_ctf "$suivant"
    if ! prog_place_libre "$vmid" "${PREFIXE_IP}.1${nn}"; then
        prog_noter_une_fois "place-$vmid" "étudiant $nn : adresse ${PREFIXE_IP}.1${nn} prise ailleurs," \
            "ou stockage $STOCKAGE indisponible : rien n'est détruit"
        return 1
    fi
    prog_oublier "place-$vmid"
    if ! { [[ -n "$IMAGE" ]] || chercher_image; } || ! preparer_creation >> "$PROG_JOURNAL" 2>&1; then
        prog_noter_une_fois "prepa-$vmid" "étudiant $nn : CTF$suivant impossible à préparer" \
            "(image, dossier, script) : rien n'est détruit"
        nettoyer; TMP_SCRIPT=""
        return 1
    fi
    prog_oublier "prepa-$vmid"
    dossier="$PROG_SAUVE/$(date +%Y%m%d-%H%M%S)-$vmid"
    if ! mkdir -p "$dossier" || ! chmod 700 "$PROG_SAUVE" "$dossier"; then
        prog_journal "étudiant $nn : sauvegarde impossible dans $dossier : rien n'est détruit"
        nettoyer; TMP_SCRIPT=""
        return 1
    fi
    prog_journal "étudiant $nn : CTF$ctf confirmé — destruction de $vmid « $nom » puis création du CTF$suivant"
    PROG_EN_COURS="étudiant $nn : CT $vmid « $nom » à détruire, CTF$suivant à créer"
    prog_detruire "$vmid" "$nom" "$numero" "$dossier"; rc=$?
    if (( rc != 0 )); then
        PROG_EN_COURS=""; nettoyer; TMP_SCRIPT=""
        rmdir "$dossier/ssh" "$dossier" 2>/dev/null
        (( rc == 1 )) && return 4
        essais=$(( $(cat "$PROG_ETAT/essais-$vmid" 2>/dev/null || echo 0) + 1 ))
        echo "$essais" > "$PROG_ETAT/essais-$vmid"
        (( essais >= PROG_MAX_ESSAIS )) && return 4
        return 1
    fi
    A_CREER=("$numero"); PRETS=(); ECHECS=()
    creer_conteneur "$numero" 1 >> "$PROG_JOURNAL" 2>&1
    nettoyer; TMP_SCRIPT=""
    PROG_EN_COURS=""
    if (( ${#PRETS[@]} == 0 )); then
        prog_journal "étudiant $nn : la création du CTF$suivant a ÉCHOUÉ (détail ci-dessus)"
        return 2
    fi
    prog_reposer_cles "$vmid" "$dossier/ssh"
    prog_journal "étudiant $nn : CTF$suivant prêt"
    return 0
}

# Conteneur créé par une version qui ne posait pas de témoin : on le pose une
# fois, la protection contre une lecture de tout le disque vaut ensuite.
prog_poser_temoin() {
    local vmid=$1 racine=$2
    [[ -n "$racine" && ! -e "$racine$PROG_TEMOIN" && ! -e "$PROG_ETAT/temoin-$vmid" ]] || return 0
    : > "$PROG_ETAT/temoin-$vmid"
    timeout 20 pct exec "$vmid" -- sh -c "echo ctf > $PROG_TEMOIN && chmod 600 $PROG_TEMOIN" >/dev/null 2>&1
}

# evenement TEXTE... : une ligne de plus au compte rendu de la passe en cours
# (le tableau « evenements » est local à prog_passe).
evenement() { evenements+=("$*"); }

# prog_passe : une vérification de tous les étudiants surveillés.
# Rend 1 si un étudiant n'a pas pu passer au CTF suivant (détail au journal).
prog_passe() {
    local numero nn vmid nom volume racine ctf ctf_vu depuis maintenant rc
    local echec=0 crees=0 bloque=0
    local -a liste evenements=()

    if [[ -e "$PROG_STOP" ]]; then
        prog_noter_une_fois stop "progression suspendue : interrupteur d'arrêt $PROG_STOP présent"
        return 0
    fi
    if ! prog_quorum; then
        prog_noter_une_fois quorum "passe sautée : pas de quorum (/etc/pve en lecture seule)"
        return 0
    fi
    prog_oublier quorum
    if [[ -s "$PROG_ETAT/interrompu" ]]; then
        evenements+=("passe précédente interrompue ($(<"$PROG_ETAT/interrompu")) : conteneur à vérifier à la main")
        rm -f "$PROG_ETAT/interrompu"
    fi
    if [[ -e "$PROG_ETAT/disjoncte" ]]; then
        bloque=1
        prog_noter_une_fois disjoncte "enchaînements arrêtés depuis un échec de création" \
            "($(<"$PROG_ETAT/disjoncte")) : rm $PROG_ETAT/disjoncte pour reprendre"
    else
        prog_oublier disjoncte
    fi
    read -r -a liste <<< "$PROG_ETUDIANTS"
    maintenant=$(date +%s)

    for numero in "${liste[@]}"; do
        nn=$(printf '%02d' "$numero")
        vmid=$((BASE_ID + numero))
        nom="" volume=""
        read -r nom volume < <(prog_conf_ct "$vmid")
        if [[ -z "$nom" ]]; then
            prog_vu_effacer "$vmid"; continue
        fi
        prog_conforme "$vmid" "$nom" "$numero" || continue
        ctf=${nom:3:1}
        racine=$(prog_racine "$vmid" "$volume") || racine=""
        prog_poser_temoin "$vmid" "$racine"

        prog_ctf_fini "$vmid" "$racine" "$ctf"; rc=$?
        case $rc in
            1) prog_vu_effacer "$vmid"; continue ;;            # pas encore fini
            2) continue ;;                                     # flag final introuvable : rien à décider
            3) if prog_noter_une_fois "groupe-$vmid" "étudiant $nn : tous les fichiers de $vmid lus d'un coup" \
                       "(sauvegarde ?) : rien n'est fait. Si c'est bien l'étudiant : pct exec $vmid -- rm $PROG_TEMOIN"
               then
                   evenement "étudiant $nn : lecture de tout le disque de $vmid (sauvegarde ?), rien n'est fait" \
                       "(voir $PROG_JOURNAL)"
               fi
               continue ;;
        esac
        prog_oublier "groupe-$vmid"

        read -r ctf_vu depuis <<< "$(prog_vu_lire "$vmid")"
        [[ "${depuis:-}" =~ ^[0-9]+$ ]] || ctf_vu=""          # mémoire vide ou abîmée : on repart de zéro
        # Déjà signalé : rien à réécrire, sinon le journal se répéterait chaque minute.
        [[ "$ctf_vu" == "fini" || "$ctf_vu" == "echec" ]] && continue
        if [[ "$ctf_vu" != "$ctf" ]]; then
            prog_vu_ecrire "$vmid" "$ctf" "$maintenant"
            prog_journal "étudiant $nn : flags du CTF$ctf affichés — confirmation dans ${PROG_ECART} s"
            continue
        fi
        (( maintenant - depuis >= PROG_ECART )) || continue

        if (( ctf >= PROG_DERNIER )); then
            prog_journal "étudiant $nn : CTF$ctf terminé — c'est le dernier, rien n'est détruit"
            evenements+=("étudiant $nn : CTF$ctf terminé (dernier CTF)")
            prog_vu_ecrire "$vmid" "fini" "$maintenant"
            continue
        fi
        (( bloque == 0 && crees < PROG_MAX_CREATIONS )) || continue    # à la passe suivante
        if [[ "$(timeout 60 pct status "$vmid" 2>/dev/null)" != "status: running" ]]; then
            prog_noter_une_fois "eteint-$vmid" "étudiant $nn : $vmid est éteint :" \
                "rien n'est fait tant qu'il ne tourne pas"
            continue
        fi
        prog_oublier "eteint-$vmid"

        prog_enchainer "$numero" "$vmid" "$nom" "$ctf"; rc=$?
        case $rc in
            0) crees=$((crees + 1)); prog_vu_effacer "$vmid"
               evenements+=("étudiant $nn : passé du CTF$ctf au CTF$((ctf + 1))") ;;
            2) echec=1; bloque=1; prog_vu_effacer "$vmid"
               echo "étudiant $nn, $(date '+%F %T')" > "$PROG_ETAT/disjoncte"
               evenement "étudiant $nn : CTF$ctf détruit mais création du CTF$((ctf + 1)) en échec —" \
                   "à reprendre à la main. Enchaînements arrêtés : rm $PROG_ETAT/disjoncte pour reprendre" ;;
            3) bloque=1 ;;
            4) echec=1; prog_vu_ecrire "$vmid" "echec" "$maintenant"
               evenement "étudiant $nn : destruction refusée ou échouée, CTF$((ctf + 1)) NON créé" \
                   "(pour réessayer : rm $PROG_ETAT/vu-$vmid)" ;;
        esac
    done

    (( ${#evenements[@]} > 0 )) && prog_courriel "${evenements[@]}"
    return "$echec"
}

# Compte rendu facultatif. Adresse vide ou sendmail absent : rien n'est envoyé ;
# une progression ne s'arrête jamais parce qu'un courriel ne part pas.
prog_courriel() {
    local ligne
    [[ -n "$PROG_COURRIEL" ]] || return 0
    if ! command -v sendmail >/dev/null 2>&1; then
        prog_noter_une_fois sendmail "compte rendu non envoyé : sendmail absent de ce serveur"
        return 0
    fi
    if {
        printf 'To: %s\nSubject: [CTF] progression automatique sur %s : %d message(s)\n' \
            "$PROG_COURRIEL" "$NOEUD" "$#"
        printf 'MIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n'
        for ligne in "$@"; do printf -- '- %s\n' "$ligne"; done
        printf '\nJournal   : %s\nSuspendre : touch %s (reprendre : rm %s)\n' "$PROG_JOURNAL" "$PROG_STOP" "$PROG_STOP"
    } | sendmail -t -oi 2>>"$PROG_JOURNAL"; then
        prog_journal "compte rendu remis à sendmail pour $PROG_COURRIEL"
    else
        prog_journal "compte rendu NON envoyé (sendmail en échec)"
    fi
    return 0
}


# ── 13d. Point d'entrée du minuteur ──────────────────────────────

# Arrêt du nœud ou « systemctl stop » pendant un enchaînement : le noter, et le
# signaler au compte rendu de la passe suivante.
prog_interrompu() {
    trap - INT TERM HUP
    local ou="une lecture, rien n'était en cours de modification"
    [[ -n "$PROG_EN_COURS" ]] && ou="$PROG_EN_COURS"
    prog_journal "INTERROMPU pendant : $ou"
    [[ -n "$PROG_EN_COURS" ]] && printf '%s\n' "$PROG_EN_COURS" > "$PROG_ETAT/interrompu"
    exit 130
}

# Une passe, puis on sort. Code de sortie : celui de prog_passe.
prog_lancer_passe() {
    local rc
    PROG_MODE=1
    (( EUID == 0 )) || { echo "À lancer en root." >&2; return 1; }
    if [[ ! -e "$PROG_UNITES/$PROG_UNITE.timer" ]]; then
        echo "Progression non armée : rien à faire (voir --help)." >&2
        return 1
    fi
    if prog_autre_moteur; then
        echo "ctf-progression.timer est en place sur ce serveur : cette progression ne tourne pas ici." >&2
        return 0
    fi
    mkdir -p "$PROG_ETAT" "$PROG_SAUVE" 2>/dev/null && chmod 700 "$PROG_ETAT" "$PROG_SAUVE"
    touch "$PROG_JOURNAL" 2>/dev/null && chmod 600 "$PROG_JOURNAL"
    if [[ -e "$PROG_STOP" ]]; then
        prog_noter_une_fois stop "progression suspendue : interrupteur d'arrêt $PROG_STOP présent"
        return 0
    fi
    [[ -e "$PROG_ETAT/note-stop" ]] && { prog_oublier stop; prog_journal "progression reprise : $PROG_STOP retiré"; }
    if ! PROG_JOURNAL=/dev/null prog_lire_conf; then
        prog_noter_une_fois conf "réglages $PROG_CONF introuvables ou invalides : passes abandonnées"
        return 1
    fi
    prog_oublier conf
    # Tout ce qu'affiche la passe (vérifications, création) va au journal.
    [[ -t 1 ]] && echo "Passe en cours : détail dans $PROG_JOURNAL"
    exec >> "$PROG_JOURNAL" 2>&1
    verifier_prerequis
    trap nettoyer EXIT
    trap prog_interrompu INT TERM HUP
    detecter_infra
    prog_passe; rc=$?
    return "$rc"
}


# ── 13e. Réglages, armement et retrait ───────────────────────────

prog_courriel_valide() { [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; }

prog_reglages_valides() {
    local n
    [[ "$BASE_ID" =~ ^[1-9][0-9]{1,8}$ ]] && (( BASE_ID + 1 >= 100 && BASE_ID + ETUDIANT_MAX <= 999999999 )) || return 1
    [[ "$STOCKAGE" =~ ^[A-Za-z][A-Za-z0-9._-]*$ \
       && "$PONT" =~ ^[A-Za-z][A-Za-z0-9._-]*$ && "$MASQUE" =~ ^/([89]|[12][0-9]|30)$ \
       && "$PROG_ETUDIANTS" =~ ^[0-9]+(\ [0-9]+)*$ ]] || return 1
    ipv4_valide "$PREFIXE_IP.1" && ipv4_valide "$PASSERELLE" && ipv4_valide "$DNS" || return 1
    for n in $PROG_ETUDIANTS; do
        (( 10#$n >= 1 && 10#$n <= ETUDIANT_MAX )) || return 1
    done
    return 0
}

# Les réglages sont relus en root à chaque passe : ils sont lus, jamais exécutés.
# Seules les lignes CLÉ="valeur" des clés connues sont prises.
prog_lire_conf() {
    local ligne cle invalide=0 motif='^[A-Z_]+="([^"$`\\]*)"$'
    if [[ ! -r "$PROG_CONF" ]]; then
        prog_journal "réglages $PROG_CONF introuvables : passe abandonnée"
        return 1
    fi
    for cle in $PROG_CLES; do printf -v "$cle" '%s' ""; done
    while IFS= read -r ligne || [[ -n "$ligne" ]]; do
        cle=${ligne%%=*}
        [[ " $PROG_CLES " == *" $cle "* ]] || continue
        if [[ "$ligne" =~ $motif ]]; then
            printf -v "$cle" '%s' "${BASH_REMATCH[1]}"
        else
            invalide=1                    # guillemet, $, ` ou \ dans une valeur
        fi
    done < "$PROG_CONF"
    # Ancien format des réglages : une plage au lieu d'une liste.
    if [[ -z "$PROG_ETUDIANTS" && "$PROG_ETU_DEBUT" =~ ^[0-9]+$ && "$PROG_ETU_FIN" =~ ^[0-9]+$ ]]; then
        PROG_ETUDIANTS=$(seq -s ' ' "$PROG_ETU_DEBUT" "$PROG_ETU_FIN")
    fi
    if (( invalide )) || ! prog_reglages_valides; then
        prog_journal "réglages $PROG_CONF incomplets ou invalides : passe abandonnée"
        return 1
    fi
    # Une adresse que la saisie n'accepterait plus ne bloque pas la progression.
    if [[ -n "$PROG_COURRIEL" ]] && ! prog_courriel_valide "$PROG_COURRIEL"; then
        prog_noter_une_fois courriel "adresse « $PROG_COURRIEL » non reconnue : pas de compte rendu"
        PROG_COURRIEL=""
    fi
    return 0
}

# prog_union : étudiants que la progression surveillera, triés. Avec la même base,
# ceux déjà surveillés (PROG_ANCIENS) sont gardés et les nouveaux s'y ajoutent.
prog_union() {
    local -a anciens
    read -r -a anciens <<< "$PROG_ANCIENS"
    printf '%s\n' "${anciens[@]}" "${ETUDIANTS[@]}" | sed '/^$/d' | sort -nu | paste -sd ' '
}

# Réglages de la création en cours, écrits dans un fichier temporaire puis
# renommé : une coupure ne laisse jamais des réglages à moitié écrits.
prog_ecrire_conf() {
    local tmp cle
    PROG_ETUDIANTS=$(prog_union)
    PROG_ETU_DEBUT="${PROG_ETUDIANTS%% *}" PROG_ETU_FIN="${PROG_ETUDIANTS##* }"
    prog_reglages_valides || return 1
    tmp=$(mktemp "$PROG_CONF.XXXXXX") || return 1
    if {
        echo "# Réglages de la progression automatique des CTF (ctf_creer.sh $VERSION)."
        echo "# Écrit le $(date '+%F à %Hh%M'). Relu à chaque passe du minuteur."
        for cle in $PROG_CLES; do printf '%s="%s"\n' "$cle" "${!cle}"; done
    } > "$tmp" && chmod 600 "$tmp" && mv -f "$tmp" "$PROG_CONF"; then
        return 0
    fi
    rm -f "$tmp"
    return 1
}

# prog_armee : « base|étudiants|réglages|adresse|lance-ce-fichier » de la progression
# en place, rien s'il n'y en a pas. Le dernier champ vaut « non » quand le minuteur
# lance un autre fichier (ancienne version restée ailleurs, script déplacé).
# Dans un sous-shell : la lecture ne touche pas aux réglages du menu.
prog_armee() {
    [[ -e "$PROG_UNITES/$PROG_UNITE.timer" && -r "$PROG_CONF" ]] || return 1
    (
        PROG_JOURNAL=/dev/null prog_lire_conf || exit 1
        meme=non
        grep -qxF -- "ExecStart=/bin/bash \"$(prog_chemin_systemd)\" --progression" \
            "$PROG_UNITES/$PROG_UNITE.service" 2>/dev/null && meme=oui
        echo "$BASE_ID|$PROG_ETUDIANTS|$STOCKAGE $PONT $PREFIXE_IP $MASQUE $PASSERELLE $DNS|$PROG_COURRIEL|$meme"
    )
}

# Un stockage monté en noatime (ou ZFS atime=off) ne date jamais une lecture :
# aucun flag ne serait vu.
prog_verifier_atime() {
    local n nom volume racine
    for n in "${ETUDIANTS[@]}"; do
        nom="" volume=""
        read -r nom volume < <(prog_conf_ct "$((BASE_ID + n))")
        racine=$(prog_racine "$((BASE_ID + n))" "$volume") || continue
        if [[ ",$(findmnt -no OPTIONS -T "$racine" 2>/dev/null)," == *,noatime,* ]]; then
            attention "Le stockage $STOCKAGE ne date pas les lectures (noatime) : aucun flag ne sera vu."
        fi
        return 0
    done
    return 0
}

# Le minuteur lance ce fichier en root chaque minute : ni lui ni son dossier ne
# doivent pouvoir être modifiés par un autre compte que root.
prog_script_protege() {
    local f
    for f in "$PROG_SCRIPT" "$(dirname "$PROG_SCRIPT")"; do
        [[ "$(stat -c '%u' "$f" 2>/dev/null)" == 0 ]] || return 1
        (( ( 8#$(stat -c '%a' "$f") & 8#022 ) == 0 )) || return 1
    done
    return 0
}

# Chemin du script pour une ligne ExecStart : systemd lit « % » et « $ » comme des
# substitutions, et « " » et « \ » dans une chaîne entre guillemets.
prog_chemin_systemd() {
    local c=$PROG_SCRIPT
    c=${c//\\/\\\\}; c=${c//\"/\\\"}; c=${c//%/%%}; c=${c//\$/\$\$}
    printf '%s' "$c"
}

prog_installer() {
    if prog_autre_moteur; then
        ko "Un autre moteur de progression (ctf-progression.timer) est en place sur ce serveur : rien n'est armé."
        return 1
    fi
    if ! prog_script_protege; then
        ko "Armement refusé : $PROG_SCRIPT ou son dossier peut être modifié par un autre compte que root."
        info "Le minuteur le lancerait en root : le ranger dans un dossier à root seul" \
             "(/root par exemple), puis relancer."
        return 1
    fi
    if ! mkdir -p "$PROG_ETAT" "$PROG_SAUVE" || ! chmod 700 "$PROG_ETAT" "$PROG_SAUVE" \
            || ! touch "$PROG_JOURNAL" || ! chmod 600 "$PROG_JOURNAL"; then
        ko "Dossiers ou journal de la progression impossibles à créer."
        return 1
    fi
    if ! prog_ecrire_conf; then
        ko "Réglages $PROG_CONF impossibles à écrire : rien n'est armé."
        return 1
    fi
    if [[ -e "$PROG_STOP" ]]; then
        rm -f "$PROG_STOP"
        info "Interrupteur d'arrêt retiré : la progression reprend."
    fi
    cat > "$PROG_UNITES/$PROG_UNITE.service" <<UNITE
[Unit]
Description=Progression automatique des CTF (une passe)
After=pve-cluster.service

[Service]
Type=oneshot
TimeoutStartSec=3600
ExecStart=/bin/bash "$(prog_chemin_systemd)" --progression
UNITE
    cat > "$PROG_UNITES/$PROG_UNITE.timer" <<MINUTEUR
[Unit]
Description=Progression automatique des CTF : une passe, une minute après la précédente

[Timer]
OnBootSec=2min
OnUnitInactiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
MINUTEUR
    chmod 644 "$PROG_UNITES/$PROG_UNITE.service" "$PROG_UNITES/$PROG_UNITE.timer"
    systemctl daemon-reload
    systemctl enable --now "$PROG_UNITE.timer" >/dev/null 2>&1
    if ! systemctl is-active --quiet "$PROG_UNITE.timer"; then
        systemctl disable --now "$PROG_UNITE.timer" >/dev/null 2>&1
        rm -f "$PROG_UNITES/$PROG_UNITE.timer" "$PROG_UNITES/$PROG_UNITE.service"
        systemctl daemon-reload
        ko "Le minuteur n'a pas démarré : rien n'est armé (voir « journalctl -u $PROG_UNITE.timer »)."
        return 1
    fi
    ok "Progression automatique ARMÉE : étudiants $(plages_txt "$PROG_ETUDIANTS"), base $BASE_ID."
    prog_verifier_atime
    info "Le minuteur lance $CHEMIN_SCRIPT : ne pas le déplacer ni le renommer."
    info "Réglages : $PROG_CONF"
    info "Journal  : $PROG_JOURNAL"
    info "Suspendre sans rien retirer : ${C_GRAS}touch $PROG_STOP${C_0}"
    info "Retirer : ${C_GRAS}$CHEMIN_SCRIPT --progression-retirer${C_0}"
    prog_journal "progression armée par le menu (ctf_creer.sh $VERSION, base $BASE_ID, étudiants $PROG_ETUDIANTS)"
    return 0
}

prog_retirer() {
    local avait=0
    [[ -e "$PROG_UNITES/$PROG_UNITE.timer" || -e "$PROG_UNITES/$PROG_UNITE.service" ]] && avait=1
    systemctl disable --now "$PROG_UNITE.timer" >/dev/null 2>&1
    rm -f "$PROG_UNITES/$PROG_UNITE.timer" "$PROG_UNITES/$PROG_UNITE.service"
    systemctl daemon-reload
    if [[ -e "$PROG_UNITES/$PROG_UNITE.timer" || -e "$PROG_UNITES/$PROG_UNITE.service" ]]; then
        ko "Minuteur NON retiré : voir « systemctl status $PROG_UNITE.timer »."
        return 1
    fi
    if (( ! avait )); then
        info "Aucune progression automatique installée : rien à retirer."
        return 0
    fi
    ok "Progression automatique retirée (minuteur arrêté et supprimé)."
    info "Conservés : $PROG_CONF, $PROG_ETAT/, $PROG_JOURNAL et $PROG_SAUVE/."
    prog_journal "progression automatique retirée"
    return 0
}


# ── 13f. Question de l'étape 2b ──────────────────────────────────

demander_progression() {
    local reponse adresse base_armee="" etu_armes="" regl_armes="" courriel_arme="" meme=oui
    PROG_ANCIENS="" PROG_ARMEE=""
    (( N_CTF >= PROG_DERNIER )) && return 0          # le CTF5 n'a pas de suivant
    section "2b. Progression automatique (facultative)"
    if prog_autre_moteur; then
        info "Un autre moteur de progression (ctf-progression.timer) tourne sur ce serveur : question sautée."
        return 0
    fi
    boite_debut "Progression automatique vers les CTF suivants"
    boite_ligne "Le script peut surveiller tes étudiants et enchaîner les défis"
    boite_ligne "tout seul, du CTF${N_CTF} jusqu'au CTF${PROG_DERNIER}."
    boite_ligne ""
    boite_ligne "Quand un étudiant a affiché tous les flags de son CTF :"
    boite_ligne "  1. c'est reconfirmé au moins une minute plus tard,"
    boite_ligne "  2. la configuration et les clés SSH de son conteneur sont gardées,"
    boite_ligne "  3. son conteneur est DÉTRUIT,"
    boite_ligne "  4. le CTF suivant est créé : même ID, même adresse, mêmes clés SSH."
    boite_ligne ""
    boite_ligne "Une passe par minute : elle lit la date de quelques fichiers, jamais"
    boite_ligne "leur contenu. Elle suit les conteneurs de ce nœud ; un conteneur"
    boite_ligne "éteint attend d'être rallumé."
    boite_ligne ""
    boite_ligne "Tu gardes la main :"
    boite_ligne "  suspendre         touch $PROG_STOP"
    boite_ligne "  reprendre         rm $PROG_STOP"
    boite_ligne "  retirer           ./$(basename "$CHEMIN_SCRIPT") --progression-retirer"
    boite_ligne "  sauvegardes       $PROG_SAUVE/"
    boite_ligne "  menu ouvert       les enchaînements attendent qu'il soit refermé"
    boite_ligne ""
    boite_ligne "Réponse non : rien n'est installé, seul le ${NOM_CTF} est créé."
    boite_fin

    if PROG_ARMEE=$(prog_armee); then
        IFS='|' read -r base_armee etu_armes regl_armes courriel_arme meme <<< "$PROG_ARMEE"
        if [[ "$base_armee" == "$BASE_ID" ]]; then
            info "Déjà armée pour la base $BASE_ID (étudiants $(plages_txt "$etu_armes")) :" \
                 "« o » y ajoute ces étudiants."
            [[ "$regl_armes" == "$STOCKAGE $PONT $PREFIXE_IP $MASQUE $PASSERELLE $DNS" ]] \
                || attention "Stockage, pont ou adresses ont changé : les nouveaux réglages vaudront pour tous."
        else
            attention "Déjà armée pour la base $base_armee (étudiants $(plages_txt "$etu_armes")) : « o » la REMPLACE."
        fi
        [[ "$meme" == oui ]] \
            || attention "Le minuteur en place lance un autre fichier que celui-ci : « o » le fait lancer $PROG_SCRIPT."
        [[ -e "$PROG_STOP" ]] && attention "Elle est suspendue ($PROG_STOP) : « o » la fait reprendre pour tous."
    fi
    demander reponse "Activer la progression automatique ? (o/N) :"
    if [[ "${reponse,,}" != o* ]]; then
        PROGRESSION="non"
        if [[ -n "$PROG_ARMEE" ]]; then
            info "Progression déjà armée : elle continue, inchangée."
        else
            info "Progression automatique non activée."
        fi
        return 0
    fi
    if [[ "$PROG_SCRIPT" == /tmp/* ]]; then
        ko "Le script est dans /tmp, vidé au redémarrage : le minuteur ne le trouverait plus."
        info "Le ranger ailleurs (dans /root par exemple), puis relancer. Progression non activée."
        PROGRESSION="non"
        return 0
    fi
    if ! prog_script_protege; then
        ko "Armement impossible : $PROG_SCRIPT ou son dossier peut être modifié par un autre compte que root."
        info "Le minuteur le lancerait en root : le ranger dans un dossier à root seul" \
             "(/root par exemple), puis relancer."
        PROGRESSION="non"
        return 0
    fi
    PROGRESSION="oui"
    [[ -n "$PROG_ARMEE" && "$base_armee" == "$BASE_ID" ]] && PROG_ANCIENS="$etu_armes"
    attention "Les conteneurs des CTF terminés seront détruits automatiquement."
    info "Configuration et clés SSH gardées avant destruction : $PROG_SAUVE/"
    # Au réarmement de la même classe, l'adresse en place est gardée par défaut.
    [[ -n "$PROG_ARMEE" && "$base_armee" == "$BASE_ID" ]] || courriel_arme=""
    while true; do
        if [[ -n "$courriel_arme" ]]; then
            demander adresse "Adresse du compte rendu [$courriel_arme] (« aucune » = sans courriel) :"
            adresse=${adresse:-$courriel_arme}
            [[ "${adresse,,}" == aucune ]] && adresse=""
        else
            demander adresse "Adresse où envoyer le compte rendu (vide = aucun courriel) :"
        fi
        if [[ -z "$adresse" ]] || prog_courriel_valide "$adresse"; then break; fi
        ko "« $adresse » ne ressemble pas à une adresse (ex. prof@lycee.fr)."
    done
    if [[ -n "$adresse" ]] && ! command -v sendmail >/dev/null 2>&1; then
        attention "sendmail est absent de ce serveur : aucun compte rendu ne partira."
    fi
    PROG_COURRIEL="$adresse"
    ok "Progression automatique retenue : elle sera armée après la confirmation du résumé."
}


# ── 13g. Banc d'essai ────────────────────────────────────────────

# Lecture des flags, garde-fous, vraies passes, réglages et armement, dans un bac à
# sable : les chemins du moteur y sont détournés, et pct, pvesm, pvesh, pveam, qm,
# systemctl et sendmail y sont doublés. Aucune commande Proxmox réelle n'est lancée.
ESSAI_TOTAL=0 ESSAI_OK=0 ESSAI_BAC=""

# essai_verifier LIBELLÉ OBTENU ATTENDU
essai_verifier() {
    ESSAI_TOTAL=$((ESSAI_TOTAL + 1))
    if [[ "$2" == "$3" ]]; then
        ESSAI_OK=$((ESSAI_OK + 1)); printf '  ok     %s\n' "$1"
    else
        printf '  ÉCHEC  %s : attendu « %s », obtenu « %s »\n' "$1" "$3" "$2"
    fi
}

# essai_fichier CHEMIN lu|non : fichier de flag aux dates voulues.
essai_fichier() {
    mkdir -p "$(dirname "$1")"; echo x > "$1"
    touch -m -d '@1000' "$1"
    if [[ "$2" == lu ]]; then touch -a -d '@2000' "$1"; else touch -a -d '@1000' "$1"; fi
}

# essai_ct ID NOM : conteneur du bac (configuration + système de fichiers).
essai_ct() {
    printf 'hostname: %s\nrootfs: local-zfs:subvol-%s-disk-0,size=8G\n' "$2" "$1" > "$PROG_LXC/$1.conf"
    mkdir -p "$ESSAI_BAC/fs/$1"
}

# Doublures : une seule, appelée sous le nom de chaque commande, qui note l'appel.
essai_doublures() {
    mkdir -p "$ESSAI_BAC/bin"
    cat > "$ESSAI_BAC/bin/doublure" <<DOUBLURE
#!/bin/bash
nom=\$(basename "\$0")
echo "\$nom \$*" >> "$ESSAI_BAC/appels"
echo "\$nom \$*" >> "$ESSAI_BAC/appels_tous"
case "\$nom \$1" in
    "pvesm path") v=\${2#*:subvol-}; echo "$ESSAI_BAC/fs/\${v%%-disk-*}" ;;
    "pct status")
        etat=running; grep -qx "\$2" "$ESSAI_BAC/eteints" 2>/dev/null && etat=stopped
        echo "status: \$etat" ;;
    "pct exec"|"systemctl "*) exit 0 ;;
    "sendmail "*) cat > "$ESSAI_BAC/courriel" ;;
    *) exit 1 ;;
esac
DOUBLURE
    chmod 700 "$ESSAI_BAC/bin/doublure"
    local c
    for c in pct pvesm pvesh pveam qm systemctl sendmail; do
        ln -sf doublure "$ESSAI_BAC/bin/$c"
    done
}

essai_lecture() {
    local r="$ESSAI_BAC/fs/300007"
    echo "1. Lecture des flags par leurs dates"
    essai_fichier "$r/root/root.txt" non
    essai_verifier "un flag jamais ouvert n'est pas vu comme lu" \
        "$(prog_flag_lu 300007 "$r" /root/root.txt; echo $?)" "1"
    essai_fichier "$r/root/root.txt" lu
    essai_verifier "un flag dont l'atime dépasse le mtime est vu comme lu" \
        "$(prog_flag_lu 300007 "$r" /root/root.txt; echo $?)" "0"
    essai_verifier "un flag absent est signalé introuvable" \
        "$(prog_flag_lu 300007 "$r" /root/flag_root.txt; echo $?)" "2"
    essai_fichier "$r/home/Gdavid/flag.txt" lu
    essai_verifier "l'étoile du CTF1 ouvre /home/*david/" \
        "$(prog_flag_lu 300007 "$r" "${PROG_FLAG_FINAL[1]}"; echo $?)" "0"
    essai_fichier "$ESSAI_BAC/fs avec espace/root/root.txt" lu
    essai_verifier "un stockage dont le chemin a une espace est lu" \
        "$(prog_flag_lu 300007 "$ESSAI_BAC/fs avec espace" /root/root.txt; echo $?)" "0"
    essai_fichier "$r/var/www/html/flag.txt" non
    essai_verifier "CTF2 : flag de root lu, flag du site jamais ouvert : pas fini" \
        "$(prog_ctf_fini 300007 "$r" 2; echo $?)" "1"
    essai_fichier "$r/var/www/html/flag.txt" lu
    essai_verifier "CTF2 : les deux flags lus : fini" "$(prog_ctf_fini 300007 "$r" 2; echo $?)" "0"
    essai_fichier "$r$PROG_TEMOIN" lu
    essai_verifier "témoin lu en même temps que les flags : lecture groupée" \
        "$(prog_ctf_fini 300007 "$r" 2; echo $?)" "3"
    touch -m -d '@100000' "$r$PROG_TEMOIN"; touch -a -d '@200000' "$r$PROG_TEMOIN"
    essai_verifier "témoin lu un autre jour : pas une lecture groupée" \
        "$(prog_ctf_fini 300007 "$r" 2; echo $?)" "0"
    rm -f "$r$PROG_TEMOIN"
}

essai_garde_fous() {
    echo ""
    echo "2. Garde-fous"
    essai_verifier "nom, numéro et ID cohérents : accepté" \
        "$(prog_conforme 300007 CTF1-Etudiant07 7 && echo oui || echo non)" "oui"
    essai_verifier "suffixe du CTF accepté" \
        "$(prog_conforme 300007 "CTF3-Etudiant07-${CTF_NOM[3]#*-}" 7 && echo oui || echo non)" "oui"
    essai_verifier "ID qui ne correspond pas au numéro : refusé" \
        "$(prog_conforme 300008 CTF1-Etudiant07 7 && echo oui || echo non)" "non"
    essai_verifier "numéro du nom différent de celui de l'ID : refusé" \
        "$(prog_conforme 300027 CTF1-Etudiant07 27 && echo oui || echo non)" "non"
    essai_verifier "conteneur qui n'est pas un CTF : refusé" \
        "$(prog_conforme 300007 VM-Serveur-Prof 7 && echo oui || echo non)" "non"
    essai_verifier "modèle sans numéro d'étudiant : refusé" \
        "$(prog_conforme 300007 CTF1-Modele 7 && echo oui || echo non)" "non"
    essai_verifier "nom d'une ancienne numérotation des CTF : refusé" \
        "$(prog_conforme 300007 CTF3-Etudiant07-ancien 7 && echo oui || echo non)" "non"
    : > "$ESSAI_BAC/appels"
    essai_verifier "destruction hors périmètre refusée" \
        "$(prog_detruire 99 Serveur-Important 7 "$ESSAI_BAC" >/dev/null 2>&1 && echo detruit || echo refuse)" "refuse"
    essai_verifier "et refusée avant tout appel à pct" "$(grep -c '^pct' "$ESSAI_BAC/appels")" "0"
}

essai_passes() {
    local r="$ESSAI_BAC/fs/300007"
    echo ""
    echo "3. Vraies passes (destruction et création doublées)"
    # La passe appelle prog_enchainer : ici il note seulement l'appel.
    prog_enchainer() { echo "enchainer $*" >> "$ESSAI_BAC/appels"; return 0; }
    rm -rf "$ESSAI_BAC/fs/300007"; essai_ct 300007 CTF2-Etudiant07
    essai_fichier "$r/root/root.txt" lu; essai_fichier "$r/var/www/html/flag.txt" non
    PROG_ETUDIANTS="7"; : > "$ESSAI_BAC/appels"
    prog_passe >/dev/null 2>&1
    essai_verifier "flag du site pas encore ouvert : rien n'est mémorisé" \
        "$([[ -e "$PROG_ETAT/vu-300007" ]] && echo oui || echo non)" "non"
    essai_fichier "$r/var/www/html/flag.txt" lu
    prog_passe >/dev/null 2>&1
    essai_verifier "tous les flags lus : première observation mémorisée" \
        "$(cut -d' ' -f1 "$PROG_ETAT/vu-300007" 2>/dev/null)" "2"
    prog_passe >/dev/null 2>&1
    essai_verifier "pas d'enchaînement avant la confirmation" "$(grep -c '^enchainer' "$ESSAI_BAC/appels")" "0"
    printf '2 %s\n' "$(( $(date +%s) - PROG_ECART - 1 ))" > "$PROG_ETAT/vu-300007"
    prog_passe >/dev/null 2>&1
    essai_verifier "confirmé une minute plus tard : enchaînement vers le CTF3" \
        "$(grep '^enchainer' "$ESSAI_BAC/appels")" "enchainer 7 300007 CTF2-Etudiant07 2"
    essai_verifier "et la mémoire est effacée" "$([[ -e "$PROG_ETAT/vu-300007" ]] && echo oui || echo non)" "non"

    echo "300007" > "$ESSAI_BAC/eteints"; : > "$ESSAI_BAC/appels"
    printf '2 %s\n' "$(( $(date +%s) - PROG_ECART - 1 ))" > "$PROG_ETAT/vu-300007"
    prog_passe >/dev/null 2>&1
    essai_verifier "conteneur éteint : rien n'est fait" "$(grep -c '^enchainer' "$ESSAI_BAC/appels")" "0"
    rm -f "$ESSAI_BAC/eteints"

    rm -rf "$ESSAI_BAC/fs/300007"; essai_ct 300007 "CTF5-Etudiant07-${CTF_NOM[5]#*-}"
    essai_fichier "$r/root/flag_calcul.txt" lu; essai_fichier "$r/home/admin/flag.txt" lu
    printf '5 %s\n' "$(( $(date +%s) - PROG_ECART - 1 ))" > "$PROG_ETAT/vu-300007"
    : > "$ESSAI_BAC/appels"; : > "$PROG_JOURNAL"
    prog_passe >/dev/null 2>&1
    essai_verifier "CTF5 terminé : aucun enchaînement, c'est le dernier" \
        "$(grep -c '^enchainer' "$ESSAI_BAC/appels")/$(cut -d' ' -f1 "$PROG_ETAT/vu-300007")" "0/fini"
    prog_passe >/dev/null 2>&1
    essai_verifier "une fois fini, le journal ne se répète pas" "$(grep -c 'terminé' "$PROG_JOURNAL")" "1"

    local n
    for n in 11 12 13; do
        essai_ct "3000$n" "CTF1-Etudiant$n"
        essai_fichier "$ESSAI_BAC/fs/3000$n/home/Kdavid/flag.txt" lu
        printf '1 %s\n' "$(( $(date +%s) - PROG_ECART - 1 ))" > "$PROG_ETAT/vu-3000$n"
    done
    PROG_ETUDIANTS="11 12 13"; : > "$ESSAI_BAC/appels"
    prog_passe >/dev/null 2>&1
    essai_verifier "au plus $PROG_MAX_CREATIONS créations par passe" \
        "$(grep -c '^enchainer' "$ESSAI_BAC/appels")" "$PROG_MAX_CREATIONS"
    prog_enchainer() { echo "enchainer $*" >> "$ESSAI_BAC/appels"; return 4; }
    PROG_ETUDIANTS="13"; : > "$ESSAI_BAC/appels"
    prog_passe >/dev/null 2>&1; prog_passe >/dev/null 2>&1
    essai_verifier "destruction refusée : un seul essai, pas un par minute" \
        "$(grep -c '^enchainer' "$ESSAI_BAC/appels")/$(cut -d' ' -f1 "$PROG_ETAT/vu-300013")" "1/echec"

    # Étudiant prêt à passer : si l'interrupteur était ignoré, l'enchaînement partirait.
    printf '1 %s\n' "$(( $(date +%s) - PROG_ECART - 1 ))" > "$PROG_ETAT/vu-300013"
    : > "$PROG_STOP"; : > "$ESSAI_BAC/appels"; rm -f "$PROG_ETAT/note-stop"
    prog_passe >/dev/null 2>&1
    essai_verifier "interrupteur d'arrêt posé : la passe ne fait rien" "$(wc -l < "$ESSAI_BAC/appels")" "0"
    essai_verifier "et elle le note au journal" "$(grep -c 'interrupteur' "$PROG_JOURNAL")" "1"
    rm -f "$PROG_STOP"
}

essai_reglages() {
    echo ""
    echo "4. Réglages"
    BASE_ID=300000 STOCKAGE=local-zfs PONT=vmbr_CTF PREFIXE_IP=192.36.250
    MASQUE=/24 PASSERELLE=192.36.250.1 DNS=8.8.8.8 PROG_COURRIEL="prof@exemple.fr"
    ETUDIANTS=(5 7) PROG_ANCIENS="3 4"
    prog_ecrire_conf
    essai_verifier "les réglages sont écrits en 600" "$(stat -c %a "$PROG_CONF" 2>/dev/null)" "600"
    BASE_ID="" PROG_ETUDIANTS="" PROG_COURRIEL=""
    prog_lire_conf
    essai_verifier "aller-retour : base, étudiants (anciens + nouveaux), adresse" \
        "$BASE_ID|$PROG_ETUDIANTS|$PROG_COURRIEL" "300000|3 4 5 7|prof@exemple.fr"
    printf '%s\n' 'BASE_ID="300000"' 'STOCKAGE="local-zfs"' 'PONT="vmbr_CTF"' 'PREFIXE_IP="192.36.250"' \
        'MASQUE="/24"' 'PASSERELLE="192.36.250.1"' 'DNS="8.8.8.8"' 'PROG_ETU_DEBUT="3"' 'PROG_ETU_FIN="6"' \
        'PROG_COURRIEL=""' > "$PROG_CONF"
    PROG_ETUDIANTS=""
    prog_lire_conf
    essai_verifier "réglages de la 1.1.0 (une plage) : relus" "$PROG_ETUDIANTS" "3 4 5 6"
    # shellcheck disable=SC2016   # le « $( ) » doit rester tel quel : c'est l'essai
    {
        printf '%s\n' 'BASE_ID="300000"' 'STOCKAGE="local-zfs"' 'PONT="vmbr_CTF"' 'PREFIXE_IP="192.36.250"' \
            'MASQUE="/24"' 'PASSERELLE="192.36.250.1"' 'DNS="8.8.8.8"' 'PROG_ETUDIANTS="3"'
        printf 'PROG_COURRIEL="x@y.fr$(touch %s/execute)"\n' "$ESSAI_BAC"
    } > "$PROG_CONF"
    essai_verifier "une valeur qui contient \$( ) n'est ni exécutée ni acceptée" \
        "$(prog_lire_conf && echo accepte || echo refuse)/$([[ -e "$ESSAI_BAC/execute" ]] \
            && echo execute || echo rien)" \
        "refuse/rien"
    printf '%s\n' 'BASE_ID="300000"' 'STOCKAGE="local-zfs"' 'PONT="vmbr_CTF"' 'PREFIXE_IP="192.36.250"' \
        'MASQUE="/24"' 'PASSERELLE="192.36.250.1"' 'DNS="8.8.8.8"' 'PROG_ETUDIANTS="3"' \
        'PROG_COURRIEL="prénom@lycée.fr"' > "$PROG_CONF"
    essai_verifier "adresse ancienne non reconnue : réglages gardés, sans courriel" \
        "$(prog_lire_conf >/dev/null 2>&1 && echo "garde/${PROG_COURRIEL:-vide}" || echo refuse)" "garde/vide"
    # shellcheck disable=SC2016
    essai_verifier "adresse de courriel douteuse refusée" \
        "$(prog_courriel_valide 'a@b.c$(reboot)' && echo oui || echo non)" "non"
}

essai_armement() {
    local s="$PROG_UNITES/$PROG_UNITE.service" t="$PROG_UNITES/$PROG_UNITE.timer"
    echo ""
    echo "5. Armement et retrait du minuteur"
    ETUDIANTS=(3 4 5) PROG_ANCIENS="" PROG_COURRIEL=""
    essai_verifier "l'armement va au bout" "$(prog_installer >/dev/null 2>&1; echo $?)" "0"
    essai_verifier "unité et minuteur écrits en 644" "$(stat -c %a "$s" "$t" 2>/dev/null | tr '\n' ' ')" "644 644 "
    essai_verifier "l'unité lance le script par bash, chemin entre guillemets" \
        "$(grep -c "^ExecStart=/bin/bash \".*\" --progression$" "$s")" "1"
    essai_verifier "la passe suivante part une minute après la fin de la précédente" \
        "$(grep -c '^OnUnitInactiveSec=1min$' "$t")" "1"
    essai_verifier "une passe est bornée dans le temps" "$(grep -c '^TimeoutStartSec=' "$s")" "1"
    essai_verifier "progression en place vue par le menu" "$(prog_armee | cut -d'|' -f1-2)" "300000|3 4 5"
    essai_verifier "le retrait efface les deux fichiers" \
        "$(prog_retirer >/dev/null 2>&1; find "$PROG_UNITES" -name "$PROG_UNITE.*" | wc -l)" "0"
    essai_verifier "retirer une seconde fois : rien à retirer, sans erreur" \
        "$(prog_retirer >/dev/null 2>&1; echo $?)" "0"
    mkdir -p "$ESSAI_BAC/ouvert"; chmod 777 "$ESSAI_BAC/ouvert"; : > "$ESSAI_BAC/ouvert/s.sh"
    essai_verifier "script dans un dossier ouvert à tous : armement refusé, rien d'écrit" \
        "$(PROG_SCRIPT="$ESSAI_BAC/ouvert/s.sh" prog_installer >/dev/null 2>&1; echo $?)/$(find "$PROG_UNITES" \
            -name "$PROG_UNITE.*" | wc -l)" "1/0"
    : > "$PROG_UNITES/ctf-progression.timer"
    essai_verifier "un autre moteur en place : armement refusé" "$(prog_installer >/dev/null 2>&1; echo $?)" "1"
    rm -f "$PROG_UNITES/ctf-progression.timer"
}

prog_essai() {
    local bac c
    (( EUID == 0 )) || { echo "À lancer en root." >&2; return 1; }
    bac=$(mktemp -d) || { echo "mktemp -d a échoué" >&2; return 1; }
    ESSAI_BAC="$bac"
    trap 'rm -rf "$ESSAI_BAC"' EXIT
    # Tout le banc travaille dans le bac à sable : les fonctions appelées voient ces
    # valeurs (portée dynamique de bash), les vraies restent intactes.
    local PROG_CONF="$bac/conf" PROG_ETAT="$bac/etat" PROG_STOP="$bac/etat/STOP" \
          PROG_JOURNAL="$bac/journal" PROG_SAUVE="$bac/sauve" PROG_UNITES="$bac/unites" \
          PROG_LXC="$bac/lxc" PROG_MEMBRES="$bac/members" NOEUD="essai" \
          PROG_UNITE="ctf-progression-essai" PROG_SCRIPT="$bac/script/ctf_creer.sh"
    local -x PATH="$bac/bin:$PATH"          # exporté : « timeout pct » doit voir la doublure
    mkdir -p "$PROG_ETAT" "$PROG_SAUVE" "$PROG_UNITES" "$PROG_LXC"
    : > "$bac/appels"
    mkdir -p "$bac/script"; : > "$PROG_SCRIPT"; chmod 700 "$bac/script" "$PROG_SCRIPT"
    essai_doublures
    # Une doublure qui ne peut pas s'exécuter (bac monté en noexec) laisserait passer
    # la vraie commande : le banc s'arrête avant le premier essai.
    for c in pct pvesm pvesh pveam qm systemctl sendmail; do
        if [[ "$(type -P "$c")" != "$bac/bin/$c" ]]; then
            echo "Banc arrêté : la doublure de $c ne peut pas s'exécuter ($bac en noexec ?)." \
                 "Relancer avec TMPDIR=/root." >&2
            return 1
        fi
    done
    BASE_ID=300000

    echo "Banc d'essai de la progression automatique (bac à sable : $bac)"
    echo ""
    essai_lecture
    essai_garde_fous
    essai_passes
    essai_reglages
    essai_armement

    echo ""
    essai_verifier "aucune destruction ni création demandée, même à la doublure" \
        "$(grep -c -E '^pct (shutdown|stop|destroy|create|start)' "$bac/appels_tous")" "0"
    echo ""
    printf '%d essais, %d réussis, %d en échec\n' "$ESSAI_TOTAL" "$ESSAI_OK" "$((ESSAI_TOTAL - ESSAI_OK))"
    if (( ESSAI_OK == ESSAI_TOTAL )); then
        echo "BANC D'ESSAI : tout passe"
        return 0
    fi
    echo "BANC D'ESSAI : DES ESSAIS ÉCHOUENT"
    return 1
}


###################################################################
#                    SECTION 14 : CTF EMBARQUÉS                   #
###################################################################

# Les 5 scripts d'installation, en base64, recopiés des modèles d'origine : ils
# sont poussés dans chaque conteneur par « pct push ».
# Les lignes CTF_NOM[n]="…" doivent rester en début de ligne, entre guillemets
# doubles : ctf_corrige_resultats.py les lit dans ce fichier pour trouver les
# dossiers de fiches.
declare -A CTF_NOM CTF_DESC CTF_B64
CTF_NOM[1]="CTF1"
CTF_DESC[1]="Messagerie et SSH"
CTF_B64[1]='
IyEvYmluL2Jhc2gKIyBTY3JpcHQgZmluYWwgcG91ciBWTSBUUDEgRGViaWFuIDEyIC0gVmVyc2lv
biBjb3JyaWfDqWUgZXQgY29tcGzDqHRlIGF2ZWMgbG9jYWxlIGV0IGZsYWcgYmFzw6kgc3VyIGxh
IGxldHRyZQojIENvbXBhdGlibGUgYXZlYyBjbG9uYWdlIExYQywgc3VwcG9ydGUganVzcXXigJnD
oCAzOCDDqXR1ZGlhbnRzIGF2ZWMgbGV0dHJlcyBB4oaSWiBwdWlzIEFB4oaSQUwKCnNldCAtZQoK
IyA9PT0gw4l0YXBlIDAgOiBEZW1hbmRlIGR1IG51bcOpcm8gw6l0dWRpYW50ID09PQpyZWFkIC1y
IC1wICJFbnRyZXogbGUgbnVtw6lybyBkZSBsJ8OpdHVkaWFudCAoZXg6IDA2KSA6ICIgTlVNRVJP
CmlmIFsgLXogIiROVU1FUk8iIF07IHRoZW4KICBlY2hvICJOdW3DqXJvIHJlcXVpcy4iCiAgZXhp
dCAxCmZpCgojID09PSBDb3JyZWN0aW9uIGxvY2FsZSBlbl9VUy5VVEYtOCBhdmFudCB0b3V0IGFw
dCA9PT0KZXhwb3J0IERFQklBTl9GUk9OVEVORD1ub25pbnRlcmFjdGl2ZQoKIyBHw6luw6lyZXIg
bGEgbG9jYWxlIHNpIGVsbGUgbidleGlzdGUgcGFzIGVuY29yZQppZiAhIGxvY2FsZSAtYSB8IGdy
ZXAgLXEgImVuX1VTLnV0ZjgiOyB0aGVuCiAgZWNobyAiZW5fVVMuVVRGLTggVVRGLTgiID4+IC9l
dGMvbG9jYWxlLmdlbgogIGxvY2FsZS1nZW4KZmkKCiMgQ29uZmlndXJlciBsYSBsb2NhbGUgcGFy
IGTDqWZhdXQKdXBkYXRlLWxvY2FsZSBMQU5HPWVuX1VTLlVURi04CmV4cG9ydCBMQU5HPWVuX1VT
LlVURi04CmV4cG9ydCBMQ19BTEw9ZW5fVVMuVVRGLTgKCgoKIyBMZXR0cmVzIEEuLlogcHVpcyBB
QSwgQUIuLi4gYXUtZGVsw6AgZGUgMjYgKMOpdHVkaWFudCAyNyAtPiBBQSwgMzggLT4gQUwpIDog
cGx1cyBkZSBkb3VibG9uIGQnaWRlbnRpZmlhbnQKTDI9JChwcmludGYgIlxcJChwcmludGYgJyUw
M28nICQoKDY1ICsgKE5VTUVSTyAtIDEpICUgMjYpKSkiKQppZiBbICIkTlVNRVJPIiAtZ3QgMjYg
XTsgdGhlbiBMMT0kKHByaW50ZiAiXFwkKHByaW50ZiAnJTAzbycgJCgoNjQgKyAoTlVNRVJPIC0g
MSkgLyAyNikpKSIpOyBlbHNlIEwxPSIiOyBmaQpMRVRUUkU9IiR7TDF9JHtMMn0iCgpVU0VSX1NT
SD0iJHtMRVRUUkV9ZGF2aWQiClVTRVJfUE9QMz0iYWRtaW4iCgojIExpc3RlcyBkZSBtb3RzIGRl
IHBhc3NlIGZhaWJsZXMKTU9UU19QT1AzPShib29ib28ga2lzc21lIGhhcmxleSByb25hbGRvIGls
b3ZleW91MSBwcmVjaW91cyBvY3RvYmVyIGludXlhc2hhIHBlYWNoZXMgdmVyb25pY2EgY2hyaXMg
ODg4ODg4IGFkcmlhbmEgY3V0aWUgamFtZXMgYmFuYW5hIHByaW5jZSBmcmllbmQgamVzdXMxIGNy
eXN0YWwgY2VsdGljIHp4Y3Zibm0gZWR3YXJkIG9saXZlciBkaWFuYSBzYW1zdW5nIGZyZWVkb20g
YW5nZWxvIGhvdGRvZyBmcmlkYXkgc3VtbWVyIHdpbnRlciBtb25rZXkgYnViYmxlIGNob2NvbGF0
ZSB0aWdnZXIgc3Vuc2hpbmUgcHJpbmNlc3MpCk1PVFNfQURNSU49KHNlcHRlbWJlciBkZWNlbWJl
ciBtb3JnYW4gbWFyaXBvc2EgbWFyaWEgZ2FicmllbGEgaWxvdmV5b3UyIGJhaWxleSBqZXJlbXkg
cGFtZWxhIGtpbWJlcmx5IGdlbWluaSBzaGFubm9uIHBpY3R1cmVzIGFzc2hvbGUgc29waGllIGpl
c3NpZSBoZWxsb2tpdHR5IGNsYXVkaWEgYmFieWdpcmwxIGFuZ2VsaWNhIGF1c3RpbiBtYWhhbGtv
IHZpY3RvciBob3JzZXMgdGlmZmFueSBtYXJpYW5hIGVkdWFyZG8gYmFyYmFyYSBkZXN0aW55IHdl
bGNvbWUgYXNobGV5IDEyM3F3ZSBoZWxsbzEgaG9ja2V5IGxvdmVseSBtaWNoZWxsZSBzb2NjZXIp
CgpQQVNTV0RfU1NIPSIke01PVFNfUE9QM1skKChOVU1FUk8gLSAxKSldfSIKUEFTU1dEX1BPUDM9
IiR7TU9UU19BRE1JTlskKChOVU1FUk8gLSAxKSldfSIKRkxBRz0iRkxBR3tUUDFfJHtMRVRUUkV9
XyQoZWNobyAtbiBcIlRQMV8ke0xFVFRSRX1cIiB8IHNoYTI1NnN1bSB8IGN1dCAtYzEtOCl9IiAg
ICMgRklYRSBwYXIgw6lsw6h2ZSAoZm9ybXVsZSBkJ29yaWdpbmUpIDogbGEgZmV1aWxsZSBkdSBw
cm9mIHJlc3RlIHZhbGFibGUgY2hhcXVlIGFubsOpZQpIT1NUTkFNRT0iJChob3N0bmFtZSkiICAg
IyBub20gcG9zw6kgcGFyIFByb3htb3ggKHJlbWlzIMOgIGNoYXF1ZSBkw6ltYXJyYWdlKQpMT0dG
SUxFPSJ2bV90cDFfZnVsbF9zZXR1cF8ke05VTUVST30ubG9nIgpleGVjID4gPih0ZWUgLWEgIiRM
T0dGSUxFIikgMj4mMQoKIyBEw6l0ZWN0aW9uIElQIGV0IGludGVyZmFjZQpJRkFDRT0kKGlwIC1v
IGxpbmsgc2hvdyB8IGF3ayAtRic6ICcgJyQyICF+IC9ebG8vIHtnc3ViKC9ALiovLCAiIiwgJDIp
OyBwcmludCAkMjsgZXhpdH0nKQppZiBbIC16ICIkSUZBQ0UiIF07IHRoZW4KICBlY2hvICJJbnRl
cmZhY2UgcsOpc2VhdSBub24gZMOpdGVjdMOpZS4iCiAgaXAgYQogIGV4aXQgMQpmaQoKSVBfQ0lC
TEU9JChpcCAtbyAtZiBpbmV0IGFkZHIgc2hvdyAiJElGQUNFIiB8IGF3ayAne3ByaW50ICQ0fScg
fCBjdXQgLWQnLycgLWYxKQpNQVNLPSQoaXAgLW8gLWYgaW5ldCBhZGRyIHNob3cgIiRJRkFDRSIg
fCBhd2sgJ3twcmludCAkNH0nIHwgY3V0IC1kJy8nIC1mMikKR0FURVdBWT0kKGlwIHJvdXRlIHwg
Z3JlcCBkZWZhdWx0IHwgYXdrICd7cHJpbnQgJDN9JykKCiMgPT09IENvbmZpZ3VyYXRpb24gc3lz
dMOobWUgPT09CgoKZGViY29uZi1zZXQtc2VsZWN0aW9ucyA8PDwgInBvc3RmaXggcG9zdGZpeC9t
YWluX21haWxlcl90eXBlIHN0cmluZyBMb2NhbCBvbmx5IgpERUJJQU5fRlJPTlRFTkQ9bm9uaW50
ZXJhY3RpdmUgYXB0IHVwZGF0ZQpERUJJQU5fRlJPTlRFTkQ9bm9uaW50ZXJhY3RpdmUgYXB0IGlu
c3RhbGwgLXkgZG92ZWNvdC1wb3AzZCBwb3N0Zml4IG9wZW5zc2gtc2VydmVyIHN1ZG8gbmV0LXRv
b2xzIHBhc3N3ZAoKdXNlcmFkZCAtbSAtcyAvYmluL2Jhc2ggZm9ybWF0aW9uIHx8IHRydWUKZWNo
byAiZm9ybWF0aW9uOk1vcnBoZTEzQCIgfCBjaHBhc3N3ZAp1c2VybW9kIC1hRyBzdWRvIGZvcm1h
dGlvbgoKdXNlcmFkZCAtbSAtcyAvYmluL2Jhc2ggJFVTRVJfUE9QMyB8fCB0cnVlCmVjaG8gIiRV
U0VSX1BPUDM6JFBBU1NXRF9QT1AzIiB8IGNocGFzc3dkCgppZiAhIGlkIFRFTVBMQVRFVVNFUiAm
Pi9kZXYvbnVsbDsgdGhlbgogIHVzZXJhZGQgLW0gLXMgL2Jpbi9iYXNoIFRFTVBMQVRFVVNFUgog
IGVjaG8gIlRFTVBMQVRFVVNFUjokUEFTU1dEX1NTSCIgfCBjaHBhc3N3ZApmaQoKIyBDb25maWd1
cmF0aW9uIERvdmVjb3QKc2VkIC1pICdzL14jZGlzYWJsZV9wbGFpbnRleHRfYXV0aCA9IHllcy9k
aXNhYmxlX3BsYWludGV4dF9hdXRoID0gbm8vJyAvZXRjL2RvdmVjb3QvY29uZi5kLzEwLWF1dGgu
Y29uZgpzZWQgLWkgJ3N8Xm1haWxfbG9jYXRpb24gPSAuKnxtYWlsX2xvY2F0aW9uID0gbWFpbGRp
cjp+L01haWxkaXJ8JyAvZXRjL2RvdmVjb3QvY29uZi5kLzEwLW1haWwuY29uZgpzeXN0ZW1jdGwg
ZW5hYmxlIGRvdmVjb3QgcG9zdGZpeCBzc2gKc3lzdGVtY3RsIHJlc3RhcnQgZG92ZWNvdCBwb3N0
Zml4IHNzaAoKIyBSZW5vbW1hZ2UgdXRpbGlzYXRldXIgVEVNUExBVEVVU0VSCmlmIGlkIFRFTVBM
QVRFVVNFUiAmPi9kZXYvbnVsbCAmJiBnZXRlbnQgZ3JvdXAgVEVNUExBVEVVU0VSICY+L2Rldi9u
dWxsOyB0aGVuCiAgZ3JvdXBtb2QgLW4gIiRVU0VSX1NTSCIgVEVNUExBVEVVU0VSCiAgdXNlcm1v
ZCAtbCAiJFVTRVJfU1NIIiAtZyAiJFVTRVJfU1NIIiBURU1QTEFURVVTRVIKICB1c2VybW9kIC1k
ICIvaG9tZS8kVVNFUl9TU0giIC1tICIkVVNFUl9TU0giCmVsc2UKICBlY2hvICJURU1QTEFURVVT
RVIgbWFucXVhbnQuIgogIGV4aXQgMQpmaQoKIyA9PT0gQ3LDqWF0aW9uIE1haWxkaXIgPT09CnJt
IC1yZiAvaG9tZS8kVVNFUl9QT1AzL01haWxkaXIKc3VkbyAtdSAkVVNFUl9QT1AzIG1haWxkaXJt
YWtlLmRvdmVjb3QgL2hvbWUvJFVTRVJfUE9QMy9NYWlsZGlyCk1BSUxESVI9Ii9ob21lLyRVU0VS
X1BPUDMvTWFpbGRpci9uZXciCm1rZGlyIC1wICIkTUFJTERJUiIKY2hvd24gLVIgJFVTRVJfUE9Q
MzokVVNFUl9QT1AzIC9ob21lLyRVU0VSX1BPUDMvTWFpbGRpcgoKIyA9PT0gSW5qZWN0aW9uIGRl
cyBtYWlscyA9PT0KY2F0IDw8RU9GID4gIiRNQUlMRElSLzAxX2NvbW1hbmRlLiRIT1NUTkFNRSIK
RnJvbTogYW1hem9uQGZha2UuY29tClN1YmplY3Q6IFZvdHJlIGNvbW1hbmRlIG7CsCA0NTYxMjMK
Ck1lcmNpIHBvdXIgdm90cmUgYWNoYXQuIExpdnJhaXNvbiBwcsOpdnVlIHNvdXMgMyBqb3Vycy4K
RU9GCgpjYXQgPDxFT0YgPiAiJE1BSUxESVIvMDJfaXBob25lLiRIT1NUTkFNRSIKRnJvbTogbmV3
c2xldHRlckByYW5kb20ub3JnClN1YmplY3Q6IEdhZ25leiB1biBpUGhvbmUgMTYgIQoKQ2xpcXVl
eiBpY2kgcG91ciBwYXJ0aWNpcGVyIGF1IHRpcmFnZSBhdSBzb3J0Li4uCkVPRgoKY2F0IDw8RU9G
ID4gIiRNQUlMRElSLzAzX3NlY3VyaXRlLiRIT1NUTkFNRSIKRnJvbTogc3VwcG9ydEBzZWN1cml0
eS5uZXQKU3ViamVjdDogQWxlcnRlIGRlIGNvbm5leGlvbiBpbmhhYml0dWVsbGUKClVuZSBjb25u
ZXhpb24gc3VzcGVjdGUgYSDDqXTDqSBkw6l0ZWN0w6llIHN1ciB2b3RyZSBjb21wdGUuCkVPRgoK
Y2F0IDw8RU9GID4gIiRNQUlMRElSLzA0X21hai4kSE9TVE5BTUUiCkZyb206IHVyZ2VudEBjbGVh
bmVyZ3kubG9jYWwKU3ViamVjdDogTWlzZSDDoCBqb3VyIG9ibGlnYXRvaXJlCgpWZXVpbGxleiBt
ZXR0cmUgw6Agam91ciB2b3RyZSBtb3QgZGUgcGFzc2UgYXZhbnQgZGVtYWluLgpFT0YKCmNhdCA8
PEVPRiA+ICIkTUFJTERJUi8wNV9zc2guJEhPU1ROQU1FIgpGcm9tOiBEYW1pZW4gU0NPTlRSSU5P
IDxhZG1pbkBsb2NhbGhvc3Q+ClRvOiAkVVNFUl9QT1AzQGNsZWFuZXJneS5sb2NhbApTdWJqZWN0
OiBBY2PDqHMgU1NICgpCb25qb3VyLAoKVm9pY2kgbCdpZGVudGlmaWFudCBxdWUgamUgdCdhaSBj
csOpw6kgcG91ciBsJ2FjY8OocyBTU0ggOiAkVVNFUl9TU0gKCkNvcmRpYWxlbWVudCwKRGFtaWVu
IFNDT05UUklOTwpFT0YKCmNob3duIC1SICRVU0VSX1BPUDM6JFVTRVJfUE9QMyAvaG9tZS8kVVNF
Ul9QT1AzL01haWxkaXIKZG92ZWFkbSBpbmRleCAtdSAkVVNFUl9QT1AzIElOQk9YCnN5c3RlbWN0
bCByZXN0YXJ0IGRvdmVjb3QgcG9zdGZpeCBzc2gKCiMgPT09IEZsYWcgPT09CmVjaG8gIiRGTEFH
IiA+ICIvaG9tZS8kVVNFUl9TU0gvZmxhZy50eHQiCmNob3duICIkVVNFUl9TU0g6JFVTRVJfU1NI
IiAiL2hvbWUvJFVTRVJfU1NIL2ZsYWcudHh0IgpjaG1vZCA2NDQgIi9ob21lLyRVU0VSX1NTSC9m
bGFnLnR4dCIKCiMgPT09IEluZm9zID09PQpjYXQgPDxJTkZPID4gIi9yb290L2luZm9zX3RwMV8k
e05VTUVST30udHh0IgpFdHVkaWFudCBuwrAgOiAkTlVNRVJPCkxldHRyZSAgICAgICA6ICRMRVRU
UkUKTm9tIFNTSCAgICAgIDogJFVTRVJfU1NICk1vdCBkZSBwYXNzZSBTU0ggOiAkUEFTU1dEX1NT
SApDb21wdGUgUE9QMyAgOiAkVVNFUl9QT1AzCk1vdCBkZSBwYXNzZSBQT1AzIDogJFBBU1NXRF9Q
T1AzCklQICAgICAgICAgICA6ICRJUF9DSUJMRS8kTUFTSwpJbnRlcmZhY2UgICAgOiAkSUZBQ0UK
UGFzc2VyZWxsZSAgIDogJEdBVEVXQVkKRmxhZyAgICAgICAgIDogJEZMQUcKSU5GTwoKIyA9PT0g
VsOpcmlmcyA9PT0KZm9yIHNlcnZpY2UgaW4gZG92ZWNvdCBwb3N0Zml4IHNzaDsgZG8KICBzeXN0
ZW1jdGwgaXMtYWN0aXZlIC0tcXVpZXQgJHNlcnZpY2UgJiYgZWNobyAiJHNlcnZpY2UgOiBhY3Rp
ZiIgfHwgZWNobyAiJHNlcnZpY2UgOiBpbmFjdGlmIgpkb25lCgpmb3IgdXNlciBpbiAiJFVTRVJf
UE9QMyIgIiRVU0VSX1NTSCIgImZvcm1hdGlvbiI7IGRvCiAgaWQgIiR1c2VyIiAmPi9kZXYvbnVs
bCAmJiBlY2hvICJVdGlsaXNhdGV1ciAnJHVzZXInIE9LIiB8fCBlY2hvICJVdGlsaXNhdGV1ciAn
JHVzZXInIG1hbnF1YW50Igpkb25lCgppcCBhIHNob3cgIiRJRkFDRSIgfCBncmVwICdpbmV0ICcg
fCBhd2sgJ3twcmludCAiQWRyZXNzZSBJUCBkw6l0ZWN0w6llIDogIiAkMn0nCgplY2hvICJWTSBU
UDEgY29uZmlndXLDqWUgcG91ciDDqXR1ZGlhbnQgJE5VTUVSTyAoJExFVFRSRSkiCmVjaG8gIlNT
SCA6ICRVU0VSX1NTSCAvICRQQVNTV0RfU1NIIC0gUE9QMyA6ICRVU0VSX1BPUDMgLyAkUEFTU1dE
X1BPUDMgLSBGTEFHIDogJEZMQUciCgo=
'
CTF_NOM[2]="CTF2"
CTF_DESC[2]="Site web intranet"
CTF_B64[2]='
IyEvYmluL2Jhc2gKc2V0IC1lCgojID09PSBTw6ljdXJpdMOpIDogdsOpcmlmaWUgc2kgbGEgVk0g
ZXN0IGTDqWrDoCBpbml0aWFsaXPDqWUgPT09CmlmIFsgLWYgL3Jvb3Qvcm9vdC50eHQgXTsgdGhl
bgogICAgZWNobyAi4pqg77iPICBDZXR0ZSBtYWNoaW5lIHNlbWJsZSBkw6lqw6AgaW5pdGlhbGlz
w6llIChmbGFnIHJvb3QgcHLDqXNlbnQpLiIKICAgIHJlYWQgLXIgLXAgIlZvdWxlei12b3VzIHZy
YWltZW50IGNvbnRpbnVlciA/ICh5L04pIDogIiBDT05GSVJNCiAgICBbWyAiJENPTkZJUk0iICE9
ICJ5IiAmJiAiJENPTkZJUk0iICE9ICJZIiBdXSAmJiBleGl0IDEKZmkKClVTRVI9InN0YWdpYWly
ZSIKUEFTUz0iUGFzc3dvcmRTdGFnaWFpcmUiCgppZiBbIC10IDAgXTsgdGhlbgogICAgcmVhZCAt
ciAtcCAiRW50cmV6IGxlIG51bcOpcm8gZGUgbCfDqXR1ZGlhbnQgKDEgw6AgMzgpIDogIiBOVU0K
ZWxzZQogICAgcmVhZCAtciBOVU0KZmkKCk5VTT0kKHByaW50ZiAiJTAyZCIgJE5VTSkKSE9TVE5B
TUU9IiQoaG9zdG5hbWUpIiAgICMgbm9tIHBvc8OpIHBhciBQcm94bW94IChyZW1pcyDDoCBjaGFx
dWUgZMOpbWFycmFnZSkKCkhBU0hfUk9PVD0kKGVjaG8gLW4gInN1ZG9fZmluZF8ke05VTX1fcm9v
dCIgfCBzaGEyNTZzdW0gfCBjdXQgLWMxLTEyKSAgICMgRklYRSBwYXIgw6lsw6h2ZSAoZm9ybXVs
ZSBkJ29yaWdpbmUpIDogbGEgZmV1aWxsZSBkdSBwcm9mIHJlc3RlIHZhbGFibGUgY2hhcXVlIGFu
bsOpZQpIQVNIX1dFQj0kKGVjaG8gLW4gInN1ZG9fZmluZF8ke05VTX1fd2ViIiB8IHNoYTI1NnN1
bSB8IGN1dCAtYzEtMTIpCkZMQUcxPSJGTEFHe1N1ZG9GaW5kXyR7TlVNfV8ke0hBU0hfUk9PVH19
IgpGTEFHMj0iRkxBR3tXZWJVcGxvYWRfJHtOVU19XyR7SEFTSF9XRUJ9fSIKCiMgPT09IElQIHN0
YXRpcXVlIGV0IHLDqXNlYXUgPT09CklGQUNFPSQoaXAgLWJyIGxpbmsgc2hvdyB8IGF3ayAnJDEg
IT0gImxvIiAmJiAkMiA9PSAiVVAiIHtzdWIoL0AuKi8sICIiLCAkMSk7IHByaW50ICQxOyBleGl0
fScpCmVjaG8gIvCfjYcgQWRyZXNzZSBJUCBnw6lyw6llIHBhciBQcm94bW94ICh2aWEgcGN0IHNl
dCkuIEF1Y3VuIGNoYW5nZW1lbnQgcsOpc2VhdSBkYW5zIGxlIGNvbnRlbmV1ci4iCgoKaWYgISBj
b21tYW5kIC12IHN1ZG8gPi9kZXYvbnVsbCAyPiYxOyB0aGVuCiAgICBhcHQgdXBkYXRlICYmIGFw
dCBpbnN0YWxsIC15IHN1ZG8KZmkKc3luYwpzeXN0ZW1jdGwgZGlzYWJsZSAtLW5vdyBzeXN0ZW1k
LXJlc29sdmVkIDI+L2Rldi9udWxsIHx8IHRydWUKCmlmIGlkICIkVVNFUiIgJj4vZGV2L251bGw7
IHRoZW4KICAgIGVjaG8gIiRVU0VSOiRQQVNTIiB8IGNocGFzc3dkCmVsc2UKICAgIHVzZXJhZGQg
LW0gLXMgL2Jpbi9iYXNoICIkVVNFUiIKICAgIGVjaG8gIiRVU0VSOiRQQVNTIiB8IGNocGFzc3dk
CmZpCgpta2RpciAtcCAvZXRjL3N1ZG9lcnMuZApTVURPX0ZJTEU9Ii9ldGMvc3Vkb2Vycy5kL2Zp
bmRfc3VkbyIKaWYgWyAhIC1mICIkU1VET19GSUxFIiBdOyB0aGVuCiAgICBlY2hvICIkVVNFUiBB
TEw9KHJvb3QpIE5PUEFTU1dEOiAvdXNyL2Jpbi9maW5kIiA+ICIkU1VET19GSUxFIgogICAgY2ht
b2QgNDQwICIkU1VET19GSUxFIgpmaQoKYXB0IHVwZGF0ZSAmJiBhcHQgaW5zdGFsbCAteSBhcGFj
aGUyIHBocCBsaWJhcGFjaGUyLW1vZC1waHAKYXB0IGluc3RhbGwgLXkgbG9jYWxlcyAmJiBzZWQg
LWkgJ3MvXiMgKmVuX1VTLlVURi04IFVURi04L2VuX1VTLlVURi04IFVURi04LycgL2V0Yy9sb2Nh
bGUuZ2VuICYmIGxvY2FsZS1nZW4KIyBBam91dCBhdXRvbWF0aXF1ZSBkZSBBbGxvd092ZXJyaWRl
IEFsbCBkYW5zIC9ldGMvYXBhY2hlMi9hcGFjaGUyLmNvbmYKc2VkIC1pICcvPERpcmVjdG9yeSBc
L3Zhclwvd3d3XC8+LywvPFwvRGlyZWN0b3J5Pi9zL0FsbG93T3ZlcnJpZGUgTm9uZS9BbGxvd092
ZXJyaWRlIEFsbC8nIC9ldGMvYXBhY2hlMi9hcGFjaGUyLmNvbmYKc3lzdGVtY3RsIHJlc3RhcnQg
YXBhY2hlMgoKCldFQl9ESVI9Ii92YXIvd3d3L2h0bWwvdXBsb2FkIgpta2RpciAtcCAiJFdFQl9E
SVIvaW1hZ2VzIgoKaWYgWyAhIC1mICIkV0VCX0RJUi9pbmRleC5waHAiIF07IHRoZW4KY2F0ID4g
IiRXRUJfRElSL2luZGV4LnBocCIgPDwnRU9GJwo8IURPQ1RZUEUgaHRtbD4KPGh0bWwgbGFuZz0i
ZnIiPgo8aGVhZD4KICAgIDxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KICAgIDx0aXRsZT5JbnRyYW5l
dCBDbGVhbmVyZ3kgLSBUw6lsw6l2ZXJzZW1lbnQ8L3RpdGxlPgogICAgPG1ldGEgbmFtZT0idmll
d3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xIj4KICAg
IDxsaW5rIGhyZWY9Imh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vYm9vdHN0cmFwQDUuMy4z
L2Rpc3QvY3NzL2Jvb3RzdHJhcC5taW4uY3NzIiByZWw9InN0eWxlc2hlZXQiPgogICAgPHN0eWxl
PgogICAgICAgIGJvZHkgewogICAgICAgICAgICBiYWNrZ3JvdW5kLWNvbG9yOiAjMWUxZTJmOwog
ICAgICAgICAgICBjb2xvcjogI2Y4ZjlmYTsKICAgICAgICB9CiAgICAgICAgLnVwbG9hZC1ib3gg
ewogICAgICAgICAgICBtYXgtd2lkdGg6IDUwMHB4OwogICAgICAgICAgICBtYXJnaW46IDgwcHgg
YXV0bzsKICAgICAgICAgICAgcGFkZGluZzogMzBweDsKICAgICAgICAgICAgYmFja2dyb3VuZC1j
b2xvcjogIzJhMmE0MDsKICAgICAgICAgICAgYm9yZGVyLXJhZGl1czogMTBweDsKICAgICAgICAg
ICAgYm94LXNoYWRvdzogMCAwIDE1cHggcmdiYSgwLDAsMCwwLjUpOwogICAgICAgICAgICB0ZXh0
LWFsaWduOiBjZW50ZXI7CiAgICAgICAgfQogICAgICAgIC51cGxvYWQtYm94IGltZyB7CiAgICAg
ICAgICAgIG1heC13aWR0aDogMTAwcHg7CiAgICAgICAgICAgIG1hcmdpbi1ib3R0b206IDE1cHg7
CiAgICAgICAgfQogICAgICAgIC5idG4tcHJpbWFyeSB7CiAgICAgICAgICAgIGJhY2tncm91bmQt
Y29sb3I6ICMwZGNhZjA7CiAgICAgICAgICAgIGJvcmRlcjogbm9uZTsKICAgICAgICB9CiAgICAg
ICAgLmJ0bi1wcmltYXJ5OmhvdmVyIHsKICAgICAgICAgICAgYmFja2dyb3VuZC1jb2xvcjogIzBi
YmRkNTsKICAgICAgICB9CiAgICA8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgoKPGRpdiBjbGFzcz0i
dXBsb2FkLWJveCI+CiAgICA8aW1nIHNyYz0iZGF0YTppbWFnZS9wbmc7YmFzZTY0LGlWQk9SdzBL
R2dvQUFBQU5TVWhFVWdBQUFIZ0FBQUI0Q0FJQUFBQzJCcUdGQUFCQVhrbEVRVlI0bkkyOWVZQWRS
YlUvZms1VmQ5ODdjMmVmVENhVHlXU3lrb1N3aENVQkFzZ1c5c1d3aUlxNDRQcVVuOC9uODhsVDM5
UG4vdFAzaGZkVlZKNHJvcUlzcmdnQ3NpTUVra0QyQlpLUVBiTW5zOC9jMjkxVmRiNS9kRmQxZGQ4
NzBSWXo5M1pYVjUwNnkrY3NWZDBYaDRjSGdRZ0FBQkRzQXdITHpzUi9rK1pJUUZoK2IzU0M5TWZv
SXNXM1pGdEdGM1NicURIRkg4b2IyME1nQXBBZXhsQkxBQUNFZ0tTcG1MSVhRMWoweVV5TUtENEJD
RUJFWUtnNWZwK1YrQmlmWjRZZHVoa0JBTVpjSnJBdXh4Y3BKb3dvbmsvbE9WajNrYjZMS2pkTmVv
NGJSLzNIVTR6L28vSzdpU2hxVFJhL2svNk1BSTQ3YUdaaWhsWFJpWGlBZUE2VXBvVEsva1dveURW
QUFKYk1MVGtaVDFMM2FuaVE5RStVOE5xZStOK1pFUUVSNmZHbWFxelpxeWNZL1lkbC9WT0txdmhP
QXRJTWdYZ3dJdXZHY21sVkdELytnT2tHVklHRnR2NVFjZ1pzVTROWW8xR2JkbUo2QkJZckVOTDlX
Q2NRYlNGUTlQVTRSMHc1R2wya05POWl0VWdSYnQyTm1HcUpnR1FwQ1pieFBURnlSRXZwcDZiUjlI
LzhhWUFSUm1UUWFQY2NvMDJNWFVsSExGWkxNdnBDR2pRZ0k2dk1TVVF3bHAxY29FbzJucUUvclY0
V1JLQ0ZsOWxPeUJBS1pFaEdiWC9KM012SG93UzhpT3pwMnNxWVJaL1lWcWZHSFNJQ3dtaTZpWHVJ
cDU4NEQ2TUtMRDF4SXJJSG5CS0JOVzZZYi9IOWlPVVdVUGwyYzgweTBPUGVra2dGRU5FaU1VR1Y0
eWxpUEppMjM2UVRJOXJVVkJQSGl0WXB6SncwSXRZeVF5TlhNOFBJaXhJRGJhc1JqOURXS3JBa2tv
eURGYlUyZGt1SmRpRVpvV2EwQlJLcUVvR2x2T1h4ZUEwSldLTUJIMFQ4Kzd6V3N5Y2RDQ0dnMVg2
SzI4dmhIZFB0RFBkanMwUkFEUnFvUnlTajBaaTVrYktESnR3bEd5ejFSUXZmeUdoSW90NUorSmFa
UXRJWVloeWwxUFVLbEppTFNkQkJFVldZbWtkMnVHUVMraCtXQkZkcE4xV3BoMFFPVk5aRWU0Sm9E
TnVWeE5xR3dKSlRHU1FtM1ljeEFsdG55d1Nka1phT2hHd2xUVzRwVjE4Q01BUlNpdDFKdnhYUlA5
R25PTHd3cXBVSnc3TGNZWURqZ1ZSYUwreDdFakNQTDluVUhZK0NDblJTNU1XUjJWeXdReSswVlpU
U2Q2VWtxM1ZCYTBiaUpNR0thRkl6MW9aYlRyTXRxcFMzaUtaYTRSYWpENEFKVjJMelFLMU9aWGN3
eE1sUWZmSDV3K09CUWpRREdSc3pHRk5tZ2hWaEVHMU9aR2NiZldSUTZVaVBrR0FTeG5GcEpZaE9B
QlRBOE4yRWNSV0h5VkNVVnVRa25xZ0FrMU9BQ1FKR2JFc2xNaGtJUWdEd09MeHdjR1Ruc1ZMZXdm
UnNVeGlxYjlDMFVCTHFUSGxnWnFoWWYyMUdKM29ZWDA0NGhBbDRZQ2EwU09sMXBpOExoVFNPWndQ
bmNvM1QvV0VTSlZrV1ZBNlE5aGVrTkFKYTdzUUdjQklLZnYvbVlHMmVlMXc3cm9UV0ZEY3pHR1p4
dVZ6WnlrNWJrMk1WMEZDVFNFbTdsQmtZQktEeXlTZFlYb0VJQzhmdCtWTUZWbXZaUlAxaFd1UmFC
U2lqZ09XV284UFZGQXE0ak8wNlZselhPekdqeG5VWlp0UEd5QTZ5WFZtcVZzYUppaWx4eGhxWmdh
T1VKaVRwaTIzUUNXTkpoOXhvV3FWb2dqSk9nN2xSajVZUmozVnJURUVDMlZIc3JMVXBxc1Q4M1JE
REpnZ0J5SmdIWi9ERXZwSFJRTTZvZGxsRkdFaEZiRHFDVEdneE1vOVQwMHdTV0RZVkFBREhNTkxL
SVFoTTRwYzFsaVJleTZCNEJwWjBpOFJWVXZvNnhhN1B1Q3RLUUJFQUFCZ2lRODQ1UjBBRlNpbWxR
RVhwSENKandCampESkVJRkVsRlNwRXFuNnFsTFhGa2p3Z2p2bnpxd0xERHNhM0dyY1RtN0FReGhq
eDlLdXJPaUQzK3R3S1hiSXR6SUtwUmtNMG5qRFU2aGNXWTRoM0ZsUTZybWZFQ1NXcGoydXRnTVNX
bitGNEVJa0xOYTRiTVlTNkJHdk5IZThkN0R3OGY2aDQ3MGovZVArYVBGTVdrSWtta0hPN2tuVnhO
cnI2NWF0ck11dmJaOVowemF0dnI4NDBPNDBKSnFZUWgybVphSkdtWHN6VmRvL3RHQW8rem1iVmVa
VGVkdGpBeUJtRnpqb0F3dGhKTmV5ckNvdlIzQjJJSFFwaDFBQVNFQktBelZVckxDYzJ3bGpBZ3BR
a1oyV2lxazZuWldnUG9jaytSNmhucjN0eXphVlAzaHIyRGV3ZUx4M3hSSWxBTWtRRWk2clRaQURV
UVEzQ1oxMVRWT0x0aDNpbHRweTlyTzdPanZwTWpEMlZvb0kyMGdVVkp6VlA3UndWQmpyTVpCVmNs
MUJoZHNQRXJJbzQwTThwbEFFa0xIV3RyWDVyaXRaTXdLQVVxQ1Erc1RNOElLNVVjbW5ndWdsKzBl
UXRwSGFpRXFvaVk0OTVrT0xudXlMcm4zbnBtVzkrV1VYOEVBQjNHRVpBRGx3UktLVUJnREIzbU9v
d2hvQUpTSkNQUUNLVGZNOWJUTTlhenZ1dVYybHp0NHBhVExwNTMrUm50WjFjN2hWQUZOc0l5aEdO
RjhXclBPT2RROEZoTHRhTVNiNUZSbWpMd3ByUVdXU2VKU0dNc3hhYXVZeXpUajJQTHAreXdRTnBp
bjFWV1RRa2hha1lha1JITHljM3kzWE84WWpENXpGdlBQUHJHbjk4NnVnZVFYTzY2TENka0dBcVJj
M0t0dGEyekcrWjBOblRPckp2WldOVllrNnYxdUl1SVNpbEJZaUlZSHl3T0RvejNIaGs1ZEdqNHdN
Qms3MWhwYlAzaGx6ZDFyWnZYdVBEcXhUZWUxM21SNStSQ0dVVGE0Q0JzNnA4OE1oRXlaSTE1cHpI
dktHVW1ZdE5tWVNGWXpFM0hIRm1MdGFzb0tYMG5BSFNNODZSc3dWY1BIOW1NQmNSWitMR0dTd3dM
TTFwaHUwSUFBSTZjTS83cWdWZC90ZW1YZTQ3dDVveTUzQ05RZmhqazNmeUowNWV1NkRqNzFMWmxz
K283YW5JMURKbXVHU21EcWxFY2doaVZhOVJrTU5rMzNyT2pmOXZyWGEvdTZ0LzU1c0RPUGNkMlBi
djM4ZmVjK3FFbDAwOFdTZ0FBUTN6eHlMZ0VBSURXYXFmYVpTcmpQTkphRVlOQXVTSkQrZzdMa2Fk
REJES0lnRU9EUjBsZjE1cFlQbVlTUEVDQ1BacTltTndlajJ1ZHhpeEZBQUFlengyZE9IcnY2L2Mr
KzlhekJNcmxMcEVLWk5CWTFYRCszQXN1WFhqWmd1WUZlU2NubEpSS0VpbEt4R3hOUVgrT3ZqRkF4
aHlIY2FIRWtlRkRMeDk4NGNYOVR4OFpPWmgzYy85eTdoZk9uM09KVkdGSjBJMlA3ajA0RmdnRk55
OXMrTmJiWnBXazBtaWFtamJGNFdBR05hRUNBVk53Q3hNK0lCRTVHU2xNaGRRbVBrc0F6L0taTVpm
TEFqeXQvNGswRUREbjVGNDcvUHAzMTl4OWVQaHd6czF4NUw0SXF0M3FhNVpjKy9ZVFYzYzB6SkpL
Q1NWS29xUVptZUpCVkd6UlpObXVoNlFTVWNqUjBURDcxcVlQWGIxNDliTnZQZm5zdmljREdRS2d3
M0RYME9UQlVaOXpKcFNhVysrbFVUU2VURHhrTW8xS1I0WmpGWUFiRTFjTUJBbEdSdzBzVnNhNmF5
MUxReksvUk1WVFBqTTlhblN2Vlp3Q1FIUzUrN3R0Zi9qSnVwK0dLc3k3VlVySmtnck9uSFhHaDFk
OGVISExZcUZDWC9nNmRNd1liZHlSVUtIRFBFUnQ5RWFCTUVtZGhaSkN5UnF2OXNhVDNuMzE0dXM1
OGxBR1ZRNTdyWHVpRk1wcUJJNDR2eUd2N0ZsVFhHaTEwWHFLc2tZbFVDeHZreWJjTUZxdnowYzZv
aE9LOGpWL1F3ckU3azZyZERyZVNYZ2RTNDRZTW9ic0ordCs5cHRORHpxTzZ6QTNsTUxqN20zTGI3
dng1QnRjNXBSRTBkQVZUeDdqRU5WRW1SN1AvKzNnazBVeGZ2bjg5d1RLdDRZMTBSY1pYNjFJK2RM
bnlLSkpDMFhyZThjQlFSSlZPMnhPblNjVnBTY1lPeHJqWCt5cFdRV1F5cEZEbGtHV0wwVkV4M2FO
UmhJbWhjbDJPVVhNWTFPWmFScDlaNEFPWS9lODh1T0h0dnd1NTNvSTZJdGdXbUhhSFJkODVxek9G
Yjd3ZlJsWW5qNHgzRmpla0hpUDNjYzJyK3QrdktsNit2SzJ5d0paTWpGaVVoQ0liaVdLN0Y4UklR
SkRQRllNM3poVzVBaFMwWXhxWjBiQlZicTJhS1hCWnNuVTFDQmlQMmN2RVJ5dmhtZkNZVXZuU05j
NkVvZEpwakhFcW0wMDJDaDdQS01LYnNMQWh3MXdoQUFPZDMrNi9oY1BiZm1kNStRUVdDQ0NXWFd6
dm5YbDExZk1YbDRLaTBRS003RVNwVDVHQjBNMldPeDdjM0FENS95QkhYZnVHOTd1TWkvUmZ0T0Z6
amxqc3dNQUFJNXdZTVR2bXd5QUtKVHFsR241R28rcGVHWVo1NklyVUJxWEVxNG5pVWs1bHluZGpU
NWlabEN5d21ML2liaVRSQkVSODhscWwxbTdTdmVhY1JZNUovZkhiWS9jditFQmwzc0E2TXVnbzZI
akcxZCtaWDd6UEYvNEZZaXpiOVpHUWdndTkxNCsvSmVoWXIvRHZKSWMrODJPLzM4c0hPTE1TYk5I
dTA4aktnUUM0QXdQamZoRm9RaEFLVm81c3pabGU0YmRDUU1pb3FKY0FHT0xpUUMyTWlpWFRkeWdI
Z0VBTUxLYkpSTkdzb3dnTFFhdDlHWUZvREtYNHB0empyZiswSVo3WHZrcFl3NEFDaVZhcWx1K2ZO
a1haemQwK0NJd1MwZHBLc21tT0ZwNGRkRHRHanZ3OU40L09Od0RpTDd1K2RPdTd5R3lLREhYdTBy
UXJEV0ROc0dJd01sUUtVVkNxcFk4WHpHakVDcExZMUhQS2NzOGlxY0taZ1doWXZ4TGFlSU5BeEpW
WmFBWHlHeUZOVGNncGRwYkpNVHpzSGVtYU80blEzTEcrc2NIN256eGU3NElHVEpGNURMdmpncy92
YUI1bmk4Q1NKeDdodWprWTFTUFJVQUM5ZURXSHcyWGhvQllKR0NYNTliM1BQbDZ6MU11eTRGQmtG
aXo0MTBia1I1RW42TWFmMG5JODl0cjIyczltY1JZWnN5eUxZQm1zbGtzQlkwb1phS1pRdThZNk9o
Q2N6TmxVWldXSkNNOVNVTzBsbWhhSk1pUS9mRFZldzhPSDNHNFN3U2hFaDlZL3A2elppOHZoYjdH
TGtPczlqTnBFNHY2elRtNXAvYys4bHJYMzF6bUtRSWlqTXVsd0I1LzY4ZERwVjZHM0tndzZKcUJQ
U0dHTUtjK3h4R3JIZjdlcFMwS01raGhqVWFKYk1CMlNKakIwcGh6WnJLV1ZsdUtweit6U2dLZ2hI
TkphZC9pc25ZNU5xV0pmSFNIT2NkN2FkOHJUKzE2SWUva0FNQ1h3WXFPTTk1eHlnMitDSkorVXpl
VGRYdkNBbzk3Ty91My9tYkxUeGx6aVpBVVNFVktvU0prNEF4TWRqMTk0SmNPYzFKTW80UlFBSEE1
Yk8yZitNN0dYbUNza0hOQ1pRQWxDVmFuUERCQmpUTHlTT3QxTE5sTXRLR3hDU0MxSlN6bDFneGJE
YW9BcFJZNkRaVTJRWGIzYk13Zi84bmEreFVBSUNwU0JhL3dUMmQveUVGT29FQzdsTW9kV1g4NWM0
WktnejlZZTlka1VBVGlra0FxNW1KVmRMTUM0SmhiMi9YNGdaRWRuTG1KZ1FNQUFVTndPZFo0ZkRK
UUgzbnlyYjhjR0hJNERndjY2TE1IZHcyVkhJYVY5TVRhNEFWcFFWQ0toYlo4S21RUStyeDJ5bVMy
aEZHQzhobVIyRnNhc3Boa0NJbkJPclk3QUkrN2o3L3g5TzZqZXlOZDg4UGcyaVZYTG01WkdLb3dF
MktqWmNSa1N6c3V4dElQMTk1OVlIZy9RMWRLa0JJVVlaN1ZxWGlxU0lDK0xENTM4QUdkcUJORHlE
bVlkNWd2MUtiZThYczM5OXp4M0lFOXc2V0N3eFFCWjlCWEV1dDdKL0l1WTdHOE1UVWplekUrelVz
d3BPcDVVL0lYakU2YU14YUVvNk96RXh0dGJGWlNoRDQyZGxTa2duUkhRTUFRaDRyRHY5dnlxTU5j
QUpCS1RhdHB2dW1VNndJWnBqa2NFWU4ybGcrNnFJSUlPZTQ5c09YWEwrNTdvVHFYSXlCRndBaVZ3
cnhUTTFycVEwU21DQkFZdXRzSFhqa3l1bnRtN1FJa0VTcGFkMlQwTDNzSC8zWm9lUCtvUHlHVUlQ
QTRSMDRPRUJHNW5EMjBleWpIMldXZDlZMTU1a3NxbTQ1RytnekhiYjFQN3o0ME5DZUNzQzRUa0pQ
MFFYYnVrd0NjOVZFenZVS2NnTmJBNUhIdkwzdlhIQmc2a25melJPVEw4UElUTHBsWjExWU1TNWt0
d3NrczB0aEJBQjczTm5SdHVIL2pyMXp1S1FXSWlBeWtBczU0amRmWU14azVjQVJHUUd4U1RyemUr
L1E3R2hadjZCNzV6TE43dHgyZDlCVzVEQkJSS1Rwdlp0MlY4NXQrdUtWdlJDcVBNNC9qaG9ISnpV
ZUxpN1lmKzl5WnJaZDExbXBlVzRxYUxMZGloZ01KelZvU2lIcnAxK2hLaWpjQWxHeWdRVWlMQ0dN
cDJZelJuVlZZalU5MndTSmdTUVNQN1hnYWtVVnV0OGFydm5MeEpVSXY1YVVqaXJoUDFHNDlxZ3h4
eGtaS0l6OTQ1UWVCREFFWUFTb0ZTb0dVNEdDKzROVUlxVWhCbE5vUkFVTjNlLzhyUlRGVzdmSTlR
MFZnV09VeW9jZ0QrdFJwYlErdFhuTEh1UjFYelcwY0xZbkxaOVhlZjhYY1JnY2RCdnZHL0krL2VP
VHVMVWNkTk5wVlFZK3lUc1RRVGhxR0RXQmoyWDBRcHlQV3RsMnpzZHpPczNVeVR1bWU0bDBmQ1p3
bWhEamMyZFcvNTQzK3Qxem1Fa0FvdzFQYWxzNXRtaDB4MnNycFU5YW9vOS80bk12Y0J6WTl0UGZZ
UG9lNWtlY2tRRVVnbENxNDlSdzlJWlZVcUJSSUZkWHhlUDlrMTZHUmZZdW0xWjdUWGpmbWgwcXFx
K1kyL3VuR3BkKzhaRjVObm9laFVrUkE0Q0tjMjFIN2paWHRvQlFEWUVoM2JSNjRjOU9BdzlEU0xh
UlUzRWtaQ1NTK2tHeEV0N1M5REdvY1BVdjdyeTRYYXE3YXE5VHBhRmZYWWhJZEpZNzhwZjNyU3lL
b2N2TlJnd3ZtcmVUTUNhVUVzRmNNeWtTdnUzQzV1K2ZvbmovdmZNempPU0pRQ2hnRHBSQVlTQ1Zu
MXM0T3BaQXEybWlBb0lneFJBSmZsUFlQYnoreFpkbWxjeG9Db1Q2MXZQMzh6bnFHckNnVUFIQ093
NzV3R1E0SDBnL1ZqWXVhUmdMNTVmVzlpQ3pIOFljN2p0VjZ6dTBuTjVlRUFwdHpTVlVMTEk3UWxB
NHRTYWF6ODNPMERGTWdGU1VxV2o0MlUxSWRrUjM5WUdUQ1dBeExyeDNjN0RBSEFCU3BXcS9tdFBh
VGhSU21zMlFEdUIzTlFDd0ZBbVNNL1c3N255YUN5U292cDkwM0FvQlNJQ1F0bm5ieWx0NDFSRXdx
UkFRVmRhcUFBQStQN2ltRjhsMUxXOTkveWd5WE0xOHFnR2hORUlrb2tNUVloSW9VUVNqcGd5ZTNP
SXg5ZVYyWEFIQTUrODdXL2hsVi9NWUY5VVdoWTN6emxFVENVV3VxbGpLbUNzV21EUnJXWVJRZ0FO
Z3FiZ25CZkVoN1dNdFkwbjhSZ1RIV1BkcDdjT2dJUnc0QVVxblpEYk5tMUU2WFNtYTFPTzBTVEQ4
YzJlSGhyalg3WC9VY04xWUNYU0ZRaWdwZS9jS1dFN3JIZWhCNGhOcEtBU2xVaEtEWXdFU1BvTkRq
VEJINFFsbmtrVlJRa29vakZvV0trdStpb1BjdGJiN3p2QTZYU0VoRkJGOTVyVzlkYnpIZTlwZ2hT
NE5FREgySmZaTm1xczI5eERPYVU2elN2akZNOFpOaStJNEhUVGFNcEc2SWloSWMrVnRIRDR6NWt4
R0loMEl1bkRZdjUrVHNUQ2NOYTVrSmtjdmROUWRlSFpvY1FXU3h3OUFWTGwrRXk5ck9jTkE1Tm5t
TWlCR2dWQkNsaUtTQWlJMzVvNEgwVGJocGt5ZVVtZ3dWUXlnS0Vpcm1WRkhRRFNjMDNuUFI3RnFH
UXFoeG9UNjN0cWRyTEhSVG01blRQRXpSSDhYOVJ1UFJSR1daOEl5QVdQbjJmUXZKeVM3c3hoMVky
NWVzNkNIdWxpRytOWEJBNmp5VENCWk1tMnNOa0VnKzd0bXlpVWgvaFJLdkhkcUF5S0tDUmlUbHFD
c0d6alZMcnR0emRMY3ZRZ0tVRXFWQ3FTRDZUeEdHVWlqTGRHeXloYUpBS29Zb2lWVENRU29LdGFx
ejd1ZVhkczRxT0ZLcEEyUEJGOWYxQm9xWWhSNkc4SlFuTWNtSlRwOFRKYlFHTnpqQ3lwUUxyY2pS
R3NXT0UxTUNTYmxZUmVyUVVEY0Frc0lJQjlycVdwTWRBcGFTb0JhYjNSZERIQzZOSEJnNnpMbERB
QUJJaEVSRXdBSVpuamo5NUZObW5MTGh5T3NJWENsVUJBWTlsRUtsNGx5U3JJcGpGSWdpUUtCb1Fp
aUdVQkl5RU1wR2g2SlFwN2NXN3J1MDg5VEduSkxxK2U3eDcyODU2ckdJZjJRSnJjeUswK2NNbEJp
MXMxQUFXRXIrV2NZbFlyR3B6N0xhR2xwSTBUM1NHNGpRRjJFb0ZXTk9YYTRtM242WWFrc0V5VU1y
RVMraUphdWpFNFBEeFRFR21EeFJTa0NLbElJYlQ3NWh6Qi9iZlhRM1E2NGlMVmFvQ0tNSVR5cmdt
R2ZvSkxab0VSbHRha0tBUUpLZ0ZOdUlvQ2pVM0Rydlo2czZMNWxaa0ZMOTlJM0JKdzZPNVoxSzhV
T0dyNkQxVCtPNDlTR1djZFNRSlJtMkJmbXAvcEtnTDZrdXBSaG02YjRpdXU2a3kyNDY5Y3JsSGFm
TXFwOVJuNnV0emxVbno1WWsyb3lwcnZXc0dXTWp4WkZBQkJUcmNuUUpBeVVXVGx1MGNzN1oyM3Uz
RFJZSE1TcEpFOFFsVXdWS29WVFVtSitlNDNtS2h3Q2I4cUpRSmFrUVFSRkpYZkkzaW9jSXZxU0dI
UC9laGJQZXU3Qmh3cGRmWGQrN2J5UndrOElUWlRSRkUyMDNTRS9HRWtlVWdsdFdYT0daZDlKWE5J
c2dhYUQ1VGd6QjVRd0JHTVAzbkhFTjRyVWxFWXlVaXVPbDhjYnFla25LZEt2RHU4cktnb0JDQ1VY
SnduQ2srRUxLU3hkZVV1MVdiK3phSkpXS2R2WVRJUUVwQmNBQUNZUlNuUTBuTUV4czFCNGtsQlFL
aVFTQklsOVN0R3FUT0UwRVJPQUlPYzYrY2s3YnpJTDc3VTM5Ly9GS3o4OVdkVGdNVlZZZlRPOEdZ
Q21SRzJTYlJCeDBqSlVoV092cHFLY1k4eWVtV2o4N2lEYkNJa0FvNlQrZjJqbFNFaDBOVlcxMXVk
YWFmR2REOVluVGF4ek1JWkxIa0RNR0FBb29rSllhV0lGL0ZMUW9VdFZldGNNY2lvSmZJQ0JRUUhX
NWhyTTdWNHo2b3p2N2RqSjBpRUFCZ0FLSU5JNFFGSEhJblRUOVRMMUxPcFVUSWNKa0tJVWdRQkJD
aFVyRjhVSHlsQXFFaXU3WmRleXE5dG9GdGQ3dHk2YTNGZHc3MW5UL3o2YitMNXpaR2xSd1kxVEdk
Q01KUzd4V0U4ZWNNQUxXWE16MFRxbmxGanZnUVBBY3RtOW84b1VEZzU3REVKRXhWdkNjaDI0Njlk
ZmJlcmIwVDNRMlZNMXFxT3FvemM5cHlKOHpxejZReEJsVU81eHpZSWlob2pEaVBpSVJOVmMxNVoy
cW9waEVqZ3dRZ0lTU0M2Y3RhSzl2UHp4MHFHdTBpeUdUQkJ4UUFhRUN4UkNKQWltV1REOTVmdE1T
b1VROG1SU3g2QXNWS2dVY2xWSkM2bmhFTTRJRDlQbnloM3RINmp4bmNWMnVKTlVOQ3h1bUY5ei9Y
Tk4xV1VmdEdhM1YwUUpqckhIeE15ZmwrUzNGYk5MSmZMTElFNlhnYUFWOW1iVXJvb3dEMUhoRUNG
YWwzM1BZVFV2YlhqMDhsSGM0SUNEaVdDQit1Nk4zK2N6NlgyN3JmV053Z2dDQk1TSzgrOUlGSTc3
OHhZNytPUTFWTTJ0ejdiVzVTMmJYTDI2dUNpUVJnUVRWWEdpYVVUdjlyYUY5bkZpVW4wb2xsMHcv
SWNlOS9ZTUh4L3pKbk9NU2tRSmtBQktJRVlBQ1NYajFvaHRkN2dZaXNBZzJHVE1VUXlXSkhNQkEw
Vmdvcll3am1SaG5PQzVpTnBVRXJXd3IvUHJLdVE1RG9TckFiaGswNndoTm80RWRjcUIrRnR3S1BF
eEVFMHN2dytVNExMZmpTZ1FJcGJwZ2JsTnJkYnppU1VRNWhvL3RHVmcwcmJDNHVkcEJySEpZRlVl
UHcwODJkUzl2cXgzMnhRdUhoeDk0YytEYnIzVjk2Szl2SFJyeFhSNC9aRmJ0NWs5dFd4b0tHWVhQ
UUlEQTVqYk5RWUQ5UXdka1ZCb2lWUEcvcUJRV3cyQjUrM25MWjUwYnlpQmxqam9JUUlTeFVBaEZS
S1FVU1prZ2x0WW1LRW9TaW55bFRHblNsOVJTN1Ria3VMS2Z6eThERGl0YXMyc0xPZ2ZRSWJqMStK
c2RtcGRGRjVsbUpucUtScFdLMnVxcXp1OXNDa0pCU2dFUlErcWY4Si9mZit5R1JTMStLSUFVRURr
TXRoK2IyTm8vZnR2SnJhUW96NkRnWVBkRThLMzFSNGlBQVJDQkpIWEJnbk5kNXFuWTNRRm43clJD
c3lMVk5kSWJMYWtvUXFYaWtDT1FzakhmOHY3VFA0Sm1pMFNsR1lXQ1NCRVFDS1VtQTJIaktBRXdn
cU8rS0NvaUt6MURoRGk3QVZ2MUxhczJTNCtra1VocnJDV1pXT1lzMGViNG9yNmpjbHlRNUVQMms1
M1IzK3RPYkVVQ3BmY2NlQndmM3RGenpxeUc1cHdqcFFJaUpQQVkvbmh6OTZWekd0dHJYRUVFUkht
T2Z6MDQvUENiUjNNY0FVaEljZktNSmN0bUx2VkZHQVZ3SEhtVld5V1VHSndjUXVRbUk1Y0twQ0lp
L09oWm41aFYzeUZVYUZKaUU2U1M1djF3S1l3SUUxS05oOUlHY0VSZ0RBNU9oQUZCamlkNWlJWEtO
b01oY3RGNjM0QzF2OExvTnNWaERGZ0FrVmtGVHlKaVNqM2RsK3JJYXB3SUxwQnFlVWZqT2JNYUNw
eTVBQ1NWa3VyTmdmR05QU09Yem1zYTk0V1FTaWpGZ1BZT0YxODhPUFNCazJiNFlmUmdBekhFLzd1
aDY2Mmhvc3VRZ0J6dTNITGFEUXk0cENpR1lBNXpRaVhHL0lrSVh4U2hBbFFFSlJIZXN1eldDK1pl
NkF2Zkp0NmVRa1NvTDVWZXNLQkFLTXVUeFg5MmpBWUFVQmVYT1V3WXJ1MDdheW5tdXdiU2FKR2xV
cVVzNmlDOVNsL3BpNEdjU2w0UnpOd1VRSlhMdjcvNmxOMERZNHBRS0pnSXhXQkpuTkJjZmQ2Y3Bn
TWpwWEdoeGdNMUlSUUkrdkdtcnA5ZmMrTDh1dHp1RWQ5ekdHT3Nheno0K3RxdS83MTBIZ0lFSWpp
Nzg4eFZDODUvWXZjTGVkY1RJRXVoajRCU3FRaVhvekpsU2ZqWG5YajFMY3R1Q2FMOUN4WVhHTVph
cjBFVHhnTkJLc294WWNnWEpnWUdBQVNjRUxSbHFPUXluSjUzTEp6RnNza2FITkhQajJ0bHM1RTYr
cHRodUdQWlEwVldJbEpHOW1ZNk9yL1RWMTNPTmg0Wi92UmZ0amNWdkJyUEtYaE9mWlc3cmNmNytO
bHo3cng4eWVHUlVzNWhCQ0FJUm4zUjJaQy82NUo1eng0WUhnbmtZRWtNQi9MSVNPblZydEVMWnpm
NFVpbFNIMS81Z2EwOWIvWk9ERENHNDhFNEloSkdQaEFBMFJmKytYUFArK1RLVDVCU09yaVBDV0dJ
SmFFY2hqeE9qUkFBeGdJWkd6MlJMeVFZN1FGd0dPd2VDL2FPQndXT00vTmNrcTFnMmRscUkwNTUw
NVFBeWc4Q0FIQk1GV2FLdzloZnJCMUpqbEVXYUF1bFRtcXJ5em44OEdqSjFMbExFb1pMNHBJRkxY
Yzh2YXV4MnF0MmVVM09xZkhjUjNiMWYrT2lCUTVDd2VXZGRmbGFqN3VjTWNCaXFEaERJV1ZiWGV2
bkxycjlzNDkvY3lLYzdCN3BjNWxUY0F1U29pcGR1S0I1d1IwWC9FdjBJRVh5MENrQk11QUlYMXJi
ZlhsbjNaV2Q5WHJWRllKUXhUcE9OT1pMc0diaElEelhPekVtMU95Q096UHZ5SVFYTWZ1eTY5WnBI
bGZTL1V3ekJBQW5jWjJWdlo5cG1uUmhBcG5NNkVKUlIwUFZ5bzZHUjNiMWVTNlBudVZ4SFZ4emFQ
RDlwODJhMzFCMVlLdzBHY3FCeVlDUXJlMVdTNmNWZ1BET2RZY0tIbWVJbkRFRitORlRXdjlqNWV5
U0pGLzQ1OHhaL3RrTFB2cGZULzNmUFVjUE9NeVpWdDBzaVJTUngzT2ZQdS9qRGZsNlgvaFI0ZHRr
cW5tT1A5amM5OENld1RFaEw1dGRCNUg3SmhvdWhRQ2dTQkhBUkdoS3FZU0FJMEkrM2pQQmtNMnQ5
cG84cGlqek5CU2xvK2FVWjZKVWRuazhHYkRrVEFWZlp3MldiRzJMTnpoU0lxMmtPd1M4Y2xGclZM
S00zRDhTalFiaWJ3ZU92WE5wYXhnS0JzUVJISVFhbC8xOGE4L2JaamVjMUZUbElIaWNPUXhkanZk
dDczdjU4RWlPTXlBb2lkTGJsMTd4MmJkOWJHZnZucUlveldtYXJSVDRRcXhhY09HeXRwT2pMYitr
RjVVUUlNZnhwMXY3LzN0alQ3V0xhM3ZHOTQ3NERvdm5IVWdGT3NZdmh0SzRyQnpERjNvbmQ0OEhE
R0Y1Yzk1aityRUh6VEhLZkpqeUlFc1hNWVBDQ2FOTllFMHBhWlVmVnRabFJTaUc1YUZVNTNRMnRk
ZmxSV3lwUUVRZXgwZDM5WjNkMGRoYTdVbEZwQlFBY1lUK3llRFIzUU1mV2RZV0NCa0poaEVGaXI2
MTl2Q1lMNkxTZTBuNDd6NTk5VTJuWE5VM09yQ2dlUTVIenBsejJjSUxGYWtFTkFrWWdvTjQxMnM5
WDMydG16RjBFRVo4OFdyM21NTVFBSlNDeVZER29aK2lFVjhxVWdURUFJdFMzYmR2QkFEekNPYzI1
MlVFTGpvb3MvVldoeHBwdGxSWUxhS1VmTFFwTU5BclUyUS9ZbW8xTGkrTkpoMm1QaEFBU0tMcHRi
bTN6V2tPaERSUkVRYzRQRkxjMlQvMjlzV3RmaWdCRUVnUlVaN2hnenQ3RnpSVkw1dGVDSVFFVWtU
S1k3QjVZT0pIbTNvOEhudVBRSVpYTHJtNHVkRFlWdHVhZC9MMXVmclpEZTFDQ1RNd0lqQ0VyNzF5
K002TjNSemp4QWNRTnc1TUtrVUlJRW1OaFRJV1BFSWdZeUhsT1A3NThOakdvUklEV0ZEcm5WaWZF
eFlMakZOTWRCVjFmZHhrSytXQlNheU9CdC9qYTh6cUNwT2RweGhYUUNpYnVKZ013QUtyc2haWEw1
N2hSSS9wa29yeWFJZmhnMXU3cmw0MHZlQXlVb3BVdEZXQXhnSngvOWFlVDV3K2k1UTBXVWFPNDcz
YmVqZjJqbnM4cm5sS0tRR291ZERZV05WUTdWWlZ1WGxyUXl5NERQOW4zWkgvM2RxZGQ5QkFGa000
TWhhRWloQkFFWVNoaktZYzFXR0VJZ2V4cnhUK1lOY2dBeEJTWFRXalVCTS8zNWxXTngwaVpyWit4
M3dIamFKYUJ1WnFwS3NtNUdaMnZ3blVVeEt0cC9IQjVuY0NPUGJGUUtybHM1dVd0dFNNbDRKaUlD
YjlzQmdJS2RXNkk4UGRvLzZxdWMxamZoZ0lHVW9wcFBJUUh0MHo0Q0ZjMU5GUUNnV1JBa1VNWUNK
VTMzcjFrQzlWdkZNSFFCRVZ2S3EyMmxhcExNa1M1RGw3WnYvUTl6WjI1emtEUlVqRTQ0ZkZxS2hJ
RWdCQ0tOVjRJT0xYeUJHVkpCR1JnL2pkSGNmMmo0Y01zZG5qVjg4c1JPZ3lSZVNnMlpHazlmWUtr
TVV1R3dDc0JEVXBrNExWUUQrMVhHbmwxa1lLMUErS1diNlVBUEl1Ly83MXAyM3FHaDR1QmlXaGhv
cWlKRlh2ZUhCMHZQU3hGYlA3eGtvbG9jYWxDaFFXcFNvSjliTk4zZi9maW81WGpveE0rSUl4Qmd3
QjRMbER3ei9kMUhQNzhuWmZSRFZLZEpqVFVkKytmL0JJS0lYSHZRZzN4M3h4NTlwRGdpQUhJQlF0
cXZNR2ZERXFpUWlxR1hJRUlGQUVnVW9Zb0tUS2MzejA4T2lEQjBieWpKV0VYRDJucnJQR0xja2tG
N1Q0bW9iSVJOa3crMEV2YXFUNUZIZVJlcUF6a1pYQlo0dlhaY21oUlEra05FQW9OYWVwc0xDbEJn
QmM3bkxHb2kwc1FoRUIvUEY5elpOQlVCSktLRlVTS2hDcUpOVUp6WVg3VnkvZGVXeHlQRkRqb1J6
MjViZ3Z1c1pLazRGeVdJSlByWFV0UmVIN01xakJBaW5LdWV6UlhRT2Irc2VxUEZjcGxlTjhSVnZ0
Zzd1UElrTXBhV0c5NTNIMEpZVlNCYUdJVlZCUmpzT2J3LzVYTnZVUmdDUnF5ZkgzenF1UHBGbk92
SExtWktQYWxCajB2anFyUVhUQnlmUVNSVW9JQkhxeHgvQTN0WHM2SVNTdVROdFJFU0xLZUVOUStM
MFg3aDBwalRkVzE5WGtxbXFxQ2pWZTFZemFhV2ZQUGMzaENvRE04OGRTMFpudDlXZDNOQmppaUVB
U0NSVkRWQVNTdFY3QkYrRmtVSnBXallBVUN2WGJuYjBNZ0pRcVN2clk4cGtEcGJBa1paNXhEbkR4
N1Bwb0I0Y3ZWREZVU0FvVUl0RjRxRDc3V2s5dlVlUmRQaW5wdHZtTmMycThZbHgxemhweEZHbGdh
dkwydnpaUGpURmtCSUFBNktSUFdRaWpDMWRaOE1DMElpZnVPVWtjVExwZjdWVXRiSjN6K1VmdmRo
eUg2ZUNTTS9hcHQ5MzZ3Yk51REdRb1NSbmtDeVNGaWpKRFpRN09lS2hVSUFKRWRKQzlkWFJpUTg4
b1J5eUc4cjBuemJoNmZ0TzdIbjNEUXlpRjhxd1p0ZWZPckluMmNoQlJKQzlTeXVWOEw3aDhKTWc3
ekpmcTlLYXE5ODJ2OTJYMFlBSW04N2NZbTMwZVAydlo1V21oa1lUcEJWbmF5VUg2UzNiTHFENWRN
WWtrdlg4MUtaNEdNcnpoMUV2ZmZmb1ZRSkRqdVp5VHp6dDVoN3ZmZS9rMzMzL3BWd3pSWVZ3dnlX
djNhaWtLbFkxUkRFc0VwRUFCZ0lPd3JtdWtieUp3Z0Q2N291Ty9MNTczM2RjUGp3UkNFZFU0N0hQ
TDIzT2NtY2czMnZXRWlJV1dCcTg2eDRHa29nTEhMNTdTVXVNd2xSQ2VqbkVoRGlxUytrY0d0aU9W
bkxMSW1YeG1VMVZDZExza3ZrUE1pQVQwczZvSkdDVXBoRDRsbGZ6WGk5OS8yc3hGcFRBQUZjV0x5
Smp6NDdWLytPTGozeDN6SjNLT0c1WHo0OVhZS2FMRzZEZzQyTU9BTzh3QklnTGMzRDJ5cXJQeG9S
dE8rZElGYzcvL1d0ZVQrd1k1QUFQNDVybWRLOXBxQTdNbENSRkljWTZGMWlhM0tnZFNBRkVnMVdl
V1RscytyU3FRcEVzTFpQaHFtMlpHelpNOTUvYSsvektsc0h3aEFCRFRNYzlVdkU3ZXJVc2FMSzIr
a25nSUswdU1oRksxK2NJM3J2M24yUTB6ZkJFQ0FDbEFRby9uSHQzNThzY2Yvc3IybnQzVmJvN3BL
bUdsdllBQUFBeHh6Qjkvcld0SFkxVkRVMVc5SWxVUzhwTm5kejUwODZrWHpHbjgvcnBELzJmZGdW
Q3E2VlhPRHk2WmYrT2lhU1VoSTRJWm9zZlF5YmxWclUyTzU1Q1VRRkFNNUh2bTFiOS9RV05KR2M5
dnE3RW1RelBkeEw4bWo4RDA5Z0xEYmRJN1dQUmJ4T1AveHkrY3pYTEk2c1A4WkVGRnFMZnZRSDBu
V2dxQ0FLRUk1elMzLzUvVi96cTkwQmdJcVNFUDgyNytqWUZELy9UdzErOWIvMGVwWk43TnNjcWdC
QUNRZDNKUHZMbG0xOERoMDJZdWJheHVpTUI5Zm5PQkNMNzAzTzQ3bnQzakl0eXl1T1gzMTU5MDFm
em1rbENSY3VZNW13alZ6OTRZS05VV1hJZURrZ0EwS2VRVjdiVmZQRzJHakhNUU5GdHF5MEJBKytH
c1NnR0FVZWRFTnNhMG80Y3RVRnNuQXVCQWYyOEd4S25zeGNYbTdjenhNRGI2VitBTTZzN2lYY09S
eWxTNXVhMWR1Ly8xRDNmMlRnem1YQmNoeG5xcEtGVGg2ZTJMUG5UMjllZk1PY1Z6Y2tKS1JjcHNO
K0dNNTdpN1p2L21mMy84N2tsUit2Rk4vM0ZxMnlLcHBGQnEvZUhodTEvZHYzZTRkT1dpMW5lZU5H
TlphNDBrRUlvUTBXT29DSjQvUFBTZHpiMWJoMHA1aDBWclZwT1NMcDVaOTczek9nb08wOXRLajNQ
WWNKa2sxdW1aeHdGZkxDNkRKMVlvaUFoNGRLQXZCbk9LWXp1d3VhZUJHZlhUeW1DL2E2eFNSRkx4
ZS9RaDczaDcrZzkrN3RIdnZqbHdxTXJOV2Z0ME1KU0NNM2JxekJPdVhMSnkrZXlsTTJxYjg2N0hF
SVdTL2VQRGorMTg2UmNiSGg4cGpYMzYvSGQ5ZU1YcVVJbitzZEs2ZzROZDQvNEpMYlZudHRlM0ZE
eEJGRXJpaUM1bm9WU3Y5WXpldTczbmhlNFJoY3gxT0RCT2dFVkpWODV1dUhQbHJJTExoWTV3cG5B
SHgyRzlmVlBtQThVYVQrbm1zVVpiN2JPeFMwS0ZSaEI3ektrdFBjTnJMU2ZJT2Q2eDhhR3ZQdm1q
Wi9hOG5uTTh4a3dOQUFtWmtFb1IxT1ZyMnVxbnRkWTFlY3daOFNmMkR2YjJqQTQwVmxYZmZzN3E5
NTU1cFZTS2dLSmlSZDVoQkNRVUlJTERHQkgxalpkZU9qejR4N2NHWHU4YkN3aHpyZ09NQVRJSlRB
Qys3NFNXejUvWjVqS01iaUhibTJseUsyWWovOEFVYmJ2UHlFQXpPbzdKZGFsSlAvWUhvRW5SRWlv
TE8wenNtVVFibGROMm15YUhPMHJKbjcvNnlFL1dQbElTb2VlNGNlaUMwV1p0VG9BU2dBZ0pFUkFi
ODRYejVpeit3UExMVHAyNXdCZWhmcUFtTGpjSXBjWUQwVDAydWExLytKVWpnK3Q3UnJxTGdqSHVP
UTRpQThZQmVVbEJYYzc5OTlQYjM3MjRSU3FTaVdHRHNYcU5WT2FSb1lTSFp1TmcycG1WYzhNQ2kr
Uk16TXFFMFRIZktzc2owMS9NZTl0ZjR6K3FDUWhBRE5GenZJMkhkdDcxM1AwYnUvWjRqc2N4VWow
RVlORWJ2NUE1QkZ3cU5xdHUyb3JaUzFwckcvT09XNSt2WnVnUXNQRkFEdnRoMzNpcGE2eDRlTXp2
bXdqSGhRTGtydU14emdFWk1nN0lCTENRMkZsdERWODhhL1lwMHdwUk9jbFFrbmdsaXp6TGNDdHQr
ekl1YU9yWlZiNHcwTjlMbEpHRGx0emY0MXE4akRSVnN3cDhUNDNpY2E4WWxuNi8rWmxmckh1aWEy
ekljenlIT1lRTWdBTXdRQTdJQWJna0hrcFV3QWxjQUFmUUkvUUlIRUlYMEdYTVpkeGx6R1hNb2Zn
V0JveExRRjloVzAzVlIwN3R1R1h4akx6REFwbDlTMnlhTUtqRUkyTTcwWHhUT0lPVlZySEtweG1m
MG93MlRheEhSaTBNeVI2UkhabjF1dU1id2RTYXpoakxjYTludFAvaGpjODlzbTFOMStnd1o0N2pl
QXk0WnJSRHdDTzJFcmdBbk1BQmRCRmRRaGZRSWVDRURqQUhrQU56Q0Zpb1VCQnJxNjIrZnRITVcw
K2MyVkdYTHdrVnJRT1MyUmsrbFhMRTBKR0cyaFNEMHk3TFltbDVrY1M0QVVETU1qbzdyaDRucVlo
VzFsTklhbFpKdWU4ZnNBbEFBbkFZY3gyM2IvVFlNN3MyUExuejlSMjlSeWJDQUpucjhCeGpEb0FE
NkFJNENod0FoMUQvaXk2aVErQVFjZ2xNQXBlRU9TKzN1TG5oMmhQYXIxclFPcXMySDBnbEZCZ1Ba
SFlQVmNvZGJENm1BbDVkRTU5Q2ZTdk9OcVd3T282bThuQXlLME5LT1QyTGlMSnVvNmRJS0JGNTlz
YnlpY1g5Y0dTZTQvb2kySHUwWisyQk4xOC90Ry8zUU4vUnljbVNJQVVPZ1F2TUJYQUJPWUVEd0pY
V2JzL05OVlJWTDJocU9LdGorbm1kclV1bTFWVjdQSlFrbE1yTWwvU0FhQVkvM2pFbDRGbzNsL3U5
ZEFNVFIwY2FYYkhJbithbHpwNHljWHBDZWZxYUpTb2R5VlBpU0thZUlRSTZqSFBPcEZJanhZbnUw
YUd1NGNFakk2UDk0NU1qUlg4OGtJQ01nRHZNYWFpcWJpNVV0OVhXZFRiV3pXNnNtMWFkOHppVFJL
RlVWTllucFpVMENUYitIcmVQNTRTU0RwTXd5RG9QRnJRRER2VDFScVZlWTAxVE1GMi9ldzVzN0xF
SFN5V1E5bVJBcDZjRWxza2UzeEJqRjRDY0lZL0RQaUFnMi9pWUxnNUVqNlZJcFk3UGtneHJ0TVhw
bmQ1VGVCY05PUEVjcDRpVEUrQzJrM0w3Y0hRTEN4UXErRUFkaGlUYWFOT2xVNncwMWtla3BVNmkz
b21KZjg4dTlTK1JLSWtoU0VPRU1Rb3pud1I4S3k2N1ZkQkhzaThscjFlTGtnbE0xTUQ4S0taOVY2
eTFpRkRoSjNEc2h5SXdmU09hSDFPb0dDN3FqL0dTTnVnUWM4b1NRUVgyeDFFMkFpQVNtSzBsbEdr
OVpXZUpEdW02R09qdHgxaWhZYWFMS1QyZXJRTlIxUWRBUHpscVdsU2NxTkhEOUZ3VGNWbEtGQkdK
WVA4OGlLNEJtaTlXTndUUkcvYkliSDBsYTRqMGdPbHZXa0hTbStiQlpqS2w3OGlTZnB4R2tkcGxx
UzBqQThwRW12UVFGKy9JQUVQOGE0dVZCeVp6aHREbW13M09LYVliRlNCbWoycVVyVXlRV1kyUEUx
VXFNNUhza2VHWHRnaWI4VGFHL0IwOHFkaS9UV1dpai9iWHY5TnBrdUpHM3hLbkFwcFczVld5QmtS
Si94RWFWcVFwbVNUTFhJa3VKeGhLOFZnMk13eVROZGVpMDVwOXFRNHJRYm5ORnRMek5QZVcyMnFX
dkFycWFTMUJ4VXd4TEU1L3JYaFlSTnViR3kwMkdWNmtwbXlybWJWOXlXQ2NhVVhSS3JnNVl6YUZK
VUZJUERvNm5IUE9vMWNVQ1NuSWlxQmNod09Ba0ZJL0dXZ2lIblE0czBtUExpaWxWUEprQ0JHZ3d6
a2lBeUNwekF0d1l3L3VjSTRNZ1VCS1NSWkhOREZLS1FVQURuZXNGRVFyTkpHUTBWdFJPRU83akU2
S0tMcXhITzA0WjFIblFDU1ZFa0pFd1JaakxLbzE2a0ZOTkllT3c2UHhwRlNZdlBtSHJJcHllbCtI
SVZUSE13U0FydU1Bd0tFalhRY09IeWtXUzgxTmpRdm16bWxxYWd5Q0FBaDhQempZMzQrSXJTMHR1
WnluOTA4aklwWksvc0grZmxNMlFZMm50YlUxVFkyTnBIK2ZoakhvR3pnNk1URUpBQzB0MHdyVlZU
RUxDQm5Edm9HQnljbEp4M1ZudGJYWitOWFYzZXY3ZmwxdFRWTlRrNVRpWVBmaDZGRnZTdUNIUE0r
Yk1iMEZBTHU2ZTRJd3NBU0JkYlUxTGRPYVZjUkhIVHh5emgySDkvUU43RDk0YUhCNHVDcWY2K3lZ
MVRsckZuT1lsUExZNE5ESXlDZ3luTjdTVXFpcU1yc3NpZWpBb2NOU3lGek9hNXZSYXRJRkszd2pq
TFliMkQ1U3N6dFNUUFE4YjkrQmd6LzUxYS9YYjlveVBqRWhGWGtPYjUwKy9kYWJybDk5OVJXYzh4
MXY3dnJrRjc3RUVMLzd6YStjZXRKU0lVUUVCSzdqN3RuM3hxZSs4R1ZrYUtkbmZoQzg0OXFyNy9q
a3gwdStEMENJNkFmaHYzLzFtL3NQSGhaUzNITEQ2azk5N0VNbDM0K0ljYm56dlovOC9QazFyK1p6
M2plK2NNZDVaNjhvK1Q1RHBraDkrYi92MnJMampYZXR2dmJ6bi81a2QrL3dKNy93cFpIUmNjWjAv
RWNRQ3JGNDRmd2Yzdmt0QlBpdmI5KzVlOTkreDNHTXBHcXFxODQ4N1pTUHZ1L1c5cllaWVJnU2dP
ZTZSd2VIN3YzMUE4Ky8vT3JReUdnb0JHT3NVSlZmZHRMUzJ6LzAvaE1YTHpxeWZlZS8vT2RYL0ND
NGV0WEYvM1hIdndaaENFRDVYTzd4WjU3NzJwM2ZEVVB4cVk5OThOWjMzT2dIdnVhbC9XTmpjZFFm
WWJKVnBFQUVJTTl6TjIzYmZ2dm4vdk9abDlhTWpvOVg1Zk9OOWZYSTJKR2UzbS9kZmMrOTl6L0FP
U2NnSWFXUWtpS0ZNbWlPQUFSQ3lxaE9ieXpHWk9qUjRUck9HN3YyN05sL0lGb2ZmMm5kK3RHeGNj
YVlzU3FocEZTcVdQSi84UE5mam95TmNjYWozcVJTUXNwSTl3bElTaVdWSkdWV3A4RTRjSUlJQVNR
Uk1NWVlad0F3TURqMDJOUFAvZHVYdm5iczJDRG4zSFdjSTkyOW4vemNGeDk2NUxHQm9TSE9lWE5q
UTFVK056NVplbW45NjUvOC9KZTI3dGk1NG96VEwzbmJ1YUVRVDczd3QwM2J0cm11ZzRpalkrUDNQ
ZmpieVZKcDNweloxMTF4V1JpR2FYU0lOK1VSZ1VQSnZzekVXU0VCNC96bzRORFg3L3J1c2FHaFFs
WFZPMWRmZThuYnpxdktWeDNwNmY3eEwzNjllZnZPcnQ1ZUlRU2lscFNWS0VadjV6R28rS1hQZkdw
ZTUyd2haVFQ3dXRyYUlBZzBickFYWDFrYmhxS211cHFoT3R6VnMyM25tK2VzT0NNSVFnTTVDT0I1
N3U2OSszN3p1ejkrNG9QdkwvbCtVcVBYMDJHSVlSRGUvckgzclZ4eFpqUmJJc3A1T1l6ZmlJNkJF
RmRmZXZFSGIzbFhFSVpFNnNublh2ak5IeDdadlcvL0gvN3l4TWR2ZTMreFZQejIzVC9Zcy8rQTY3
aVhuTC95cHV1dW1UNnRlV3g4NHRFbm4vcnRvNC83dmo4ME9BUkF0OTN5empYclh6ODJOUHp6Qng3
K254TlB6SG01aC8vMDZKNTkrMTNIK2ZDdDc2cXJxL1Y5MytLa0haQ1pWODlibDZMVTFIV2NSeDUv
OHNDUkk1N3JmdklqdDczcityY0hRYUNJT2p2YU8yZk5Xcjl4MDFXckxvazJBWmxnVVBlVXhDZVI2
WFRNYWw4NGYxNG9SSVNnU2lrbFZaUmlqNHlPcnR1d2lZQXVQbi9sN3IzN2R1emU4OEthVjFhdU9C
UHN5QlJSRWJtdTkrQ2ZIajMvN0xPV0xsbFVLdmtKd3VrY2tZamFXcWVmTUgrKzcvc21DMU15emlx
SnFLNVFtRGRuZHNuM0VmSGpIM2pmaHMxYk4rMTRZL3NidXhqRFYxL2JzRzdqSnNid3FsVVhmZkhm
L29VaENpbmIyOWlTRTI2ZjA5R3hlTkdDazVjc21Td1c1ODd1ZU9mcWErKzU3MWRyTjJ4YXMyNzlz
cE9XUHZDSFI1U2k4MWFjZnRGNTUvcCtBUFlSSXpMcU9CcXpBb2hDK0dLcDlMZTE2eEJ3NmFJVHJy
dmlzc2xpTVF5RkZMSlU4cWUzVEx2KzZpc2pwNS91MlE2OGtPeElKK2tiZE1nQnJ1TnNmK1BOUTkz
ZG51dXV2dXJ5czg0OEhSSFhiOW95T0R6TWtvMEhKS1ZzbjlGYVc2Z2VuNWo4d2IzM2hVSEk3UGUz
V21USGYvVVpwUXhpeDJtV0lsS0tpSWd4Wkl4RjRRY0EvTzNWZFZKUlhVM05iZSsrR1FEOElBQUNS
YVJJM2ZLTzY1ZWR0RlNSUXNRZ0NONXgzVFh6TzJlSFF2enE0ZC8vNUplLzd1N3ZMMVJYZmZqV2Qz
TmU5bllxTXNRaHhMV09zalNCSVRzMlBOVFhmNVNBbHAyME5PZmxpcVVpNnVlVGxGSVJLV25ySU52
blUzd1pBZUN1ZTM1VVV5am9EUVIwKzRjL01IOU9wNUFLa1QyL1pxMGZCQ2ZNbmJ0NDRZSXdGQS84
L3BIdTNyN04yM1pjZlA1S1B3aWlXRFFVWXVrSko4eWEyWGJQZmI5YXYybnJueDUvOHViVjF5Wnpp
ZTJJWE5lNTc4SGZQdmJYWnhRUUVvUkMzSExqOVN0WG5PRUhZUVQzeFZKcFlPQm9aSmQvZmY3Rk45
L2FpNGlMRnN4VFNoMDhjb1NJT2p0bXRiVk9GNkZBWkgwREF5TmpZeVp1NEp4MXRMY0RadzMxOVI5
ODl6dS85TzI3ZHV6YXMzUDNIZ1M0ZXRYRnB5dzkwUS84c3NVOE93WkhKNTFMYWZSQUtQbCtFSVlJ
V0NnVVFCZFFkSDFQOTJCcms5N1BCRmIzMGZIYTVxMVM2NzZTNmowMzM4Z1lZNG9HaDRmV2I5eU1n
T2VlZFdaTm9YRGlvb1Z6T3RyZmZHdmZDMnRldWVqOGxYSFBDQWdRaXZEV20yOTg5cVdYZCsvYmYr
OERENjA0NHpUSFNiL1NCWUVoMjdGclR4Q0VVVjNPOS8yTHpsL0pPSXV5Z3B6blBmWGlTeSs4c2c0
UnBGSmo0eE5TcXZhMjF1dXZ1aUlJQWhFS0lxcXVxbUtNQ3luem5udnZieDcrNCtOUDVqd1BHUUpS
VGFId2krOS9wNlc1eVEvOFZSZWMvOWpUejY3ZnRKbHozdExjOU42YmJ6UnY5WXRoTjhsQmtuOGRL
KzVNSktHSUN0WFYrWHh1Wkd6czJPQXhpQU1Sazd0RkpkTjRCMC9rRGpQMUcwdTBkTk0xVjAxcmJv
cUNmQUpxbTk0aXBIUWNaOHUySFQxOS9WWDUzRW1MRm5YMzlqSEVwWXNYN2RxMy8vVXRXL3NIampZ
MU5oaXFwRkoxdFRXM2YrajluLzN5MXdlT0RmM3d2bCtSVW1aN1VYUklLUys5NEx5NXMyZEhnQ2Fr
V0x4Z2dZaWYzU1FFbEZLVmxLK1Vra29oNG9wbHAzem05by9ObWpsVFNKSEw1eEJ4WkdSVUNJRU1p
YUFxbjJ1b3E4bDVPVDhJSmlhTDBRTk9nRUNLUE0rOTdkMDNiOTYrbytRSE4xOTN6ZXhaN2NXU2I1
WEtiSFZPL0l4RE5vTk5EVWlweHZyNmpwa3ord2FPcnQrMGVXUjB0S3FxU21ySHdqbG5qRWtsSTY2
YnRMSXN6eVVDUW1BM3I3NTI2ZUpGUW9nbzN3dUNRRXJsY0hoK3phdUtpSEgyN2UvZkUza0dJVVZW
TGo5d2JIRERscTFYcmJvazRtWmtMcjd2bjd0aStkV3JMdm5qRTM5OWFlMTZoenNPTnovR0NCRm5y
N2o0d2lzdnVjalhJVTBZaGlJVUVYMGwzNzlxMVlVZnZ2V1d2b0dCejMvdFd3TkRRelBiWml4YXNH
Q3lPSm5QNVU2WU4vZTFUVnNQSEQ2eVo5LytrNVlzOWdQL3c3ZSsrMzAzMzVqenZELzg1Y203Zi9w
ejFML3RBd0JDeXJiVzZmbGNydVQ3OCtkMEtyMkxQRlkyc2hrWlJienhEOEZndWxYTWNzOXpMbm5i
dVFodzhIRFhqMzV4UHhCVTVmUDVYSzVRWGIzOWpUZS9mZmYzZGNBTFFJUUFPYy9MNS9QNVhDNzZq
OFhsRW0wSXBJdGNSSTdqY01ZR2poN2RzR1diNDNBa0tKWDhrdThYaTBVaG9tZXQ4UG1YWDVGS1Fy
elVFUGNrcGZ6SWUyOXBuekZEQ0JuSytBR3E1SmRBVEFTaUk5WTRrNDVuUkxXRlFtZkhyT1duTGJ2
bThsVkE5T1N6TDd5K2ViUG5lbEtxaTg0N04rZDVSZC8vM2svdkhSd2Vxc3JuR3hycVc2ZTN6SmpS
R3ZGS21Ub09BUUNvcUZSQUlLV0NWTm02TEtQWHB1NGtLV09TT2dJUUJFRjQxYXFMLy9yY2kxdDJ2
dkg3Ung4L2RMaHIxWVhuRjZvTCt3OGQrdjJqajNmMTlYWDM5bjNubTEvRkdFbnd5ZWRmM1ByR0xs
TkF1SExWUlpFWWlPaUpaNS9mc0hVYnFlZzNVRlJMYzlPVnF5N2V1SFY3LzlHanJ1dCs3cDgvc2VT
RWhVSktJSEJkNS83Zi92RlBUejYxZWZ2Tzd0Nyt6bGt6azRJaWtaQ3lkWHJMeDk1M3k1ZnYvQTRI
bm9va0FSeUh2N1IyZmQvQXNjalVTS25xNnFvckxyN1E0VHlTaUNJU1FvUkMzSFROVlk4Ly9WenYw
YVAzUGZEd1hWOWJvcVJjZHZMUzZ5NWY5ZHMvUDdaeDY0NS8rcmZQdi8yS3l4Yk1uYU9VZW0zVGxr
ZWZlb1p4VnBYUDVYTWVrYldKR1JJdnBWWGhPT3RlOFk3L3FJZlVLeHVWZ3FxcXFxLzgrMmYrNjF0
M2J0bjU1cHJYTjd6eStrWmtHQzBtMWRmVVhIVGV1YTdqS0NJaEJTUDI2OS8vTVNxcFJOMHRXM29p
WXlpbFZFVDNQZmhiRlVNcWhtRjQya2tuWG5IeFJjLys3YVdTSDNSMnpMcmd2SlhWK1h5a0w1N3JY
WDd4Qlg5KzZwbitvOGRlV2JkKy9weWJwRlJDQ2tYeGl4OUt2bi9aeFJlK3NHYnQweSs5VElwaW5r
SlVjc0pIbm54YXlpZWlTVXNwcDdkTXUramNsVzZoV2tnWmhxR1NLam8vczIzRzZxc3UvOS83ZnZY
U3V0ZGVYTFAya3JlZEc0cndVeC83VUJpR2p6Mzk3TzU5Qis2ODUwZXU0eEJRRUFvRW5OM2U5c1hQ
ZktxaHZsNkk1Rlcyb1pCaEtKU0t6VFRPbnpJdTBEcjBVcFpXWkVxeVpCS2htRG1qOVR2Zi9Nb2pU
L3oxMmIrOTNOTS9JSVh3dk53SjgrZmVjc1BxNWFjdkMwT1J6K1htenU1QUhkbWF1bGt1NXdrcDdV
dVJFWVdobURlbmMzQm9hSGhrZE1HYzJaZGZkRUdocWlvSTRzeFZ5dUxpaFF2T09uMVpWM2ZQM29N
SGd6QnNuVFp0ZnVmczZkT21hUkFCUlB5bjI5N2Iwejh3TVRFeHJhbEpLY1VaNjVqVlhqODJ6bG4w
TUdmTTZPYkdCc1lZQWJTM3pSZ2ZHMjl1YW95cWtrRVlycjdxaXZXYnRod2JISHp4bFZmUFAyY0ZF
WG1lOXgvLytzL25uclg4MGFlZTJidi80R1J4RXBGTmEybzg3NndWNzNqNzFhM1RwNXRzbG9nY2g4
L3BhQjhiYjZpdXppZGhsa0ZxU0hPWkFKQ3dyN2M3Vm1SckZSV01Ed0pFaGpuUEs1WktROE1qdnU4
WHFxdWJHaHNZWTVvN0pLSW4vL1JTV2pRR1p4d1FvclE3NGcrUjB1RUpZd3lqOU4xeG5PaFVzaTBZ
VVVxcGxDSUMxM0dVVW9vVU1oWWhRQ1F4eGxnb1FxVVVZNXh6UmhRLzhabjRtbGpxY1FGVFNBbUtH
R2VtVk1JWUUwSXFKUldSNTdwbXk1WG51a3Fwb1pIUjhmRnh6bmxqUTBOTm9TQkVLTk9wV1ZUR2lU
aXVOZG5rWmFaUXFRVVFrZExYMjIycVBLa2tFWk40SXBvL1l3d1I0MHF1aWJnaE5ocmJKZGdPd2JT
S1QwZmlWSVRNYUg5cUNucGpmTHc0aTdyenVFU2U3dGVNRi9kV1pyQTI2KzNSTk5sR25lTEdVVXVH
REJuR1N5dXFiQzlGMUlORldKcXBtdFZteHdBQVVQUUQ3SHF3Vktac1ZDek9ZaUVsVmEzQ3VtUm5v
WHYyUURzdE5ndGc1UnNUOU5ENmZ3bG55UGdka3cyUVRaN2RXeVVpMHJMVTdDVmo2SGFJaTRDZ1NJ
SFVmRSt5NkV5ZjlwUjFOS2VMUC9xMVB3aDY3d2F6NERraEo5dXRWcjdVVENyNVYxdnAwTzZIS3JF
Z21aNE8xZElqMjN0QUVIUXdsN2FDMUhLZlBRUnB1clBqYW4rQnV2SVkxUjZqYjdiTlZJd2Z5UDZZ
bVJVUmFaK1lYSW0zTStoWFVxZnFuR1Y5azJWWGRpdXNNSTF5QUVtVzBQUXlZZmF1bUNGRTZRc1U3
NWxMZEZERGp6RjlhN0JNYUdYeXhoVHZFc21aekNKVk81akNLbldQbG5vanBrOUdTR3g4ZHR4ZHpG
YzB6eG1tSjVqUkRFMEtKY2tBYUJBd2QxSkNQRmlEZzlXSXJEUC93TVNpNnpaeENCRHZCekQzb3A1
anVYVlg2QzBOSWhxaTBQQTZtVmtLUnMwbk8ybEp6OGtLTzZ3bGF0UThVeXd1SjJkZ2poSXRCR3NL
K25WNmNSZ1lEMkE1R091d2RDYzVoZVpmc2pyN1I0Nmsza3IyR2F5OGw4ZVdEcFg5QzJDcFNVeTg1
aTNaU1llOUZwVTJtZ3pJMmRvYWl4M05SQUVoZWwxdGNtdEd0VFZtV2QwWW50cjEvUXBUTGVOZmxx
bDZsNmsxZ0c1bXQ2clFzUjN2YUc2a1I4c1V4c3YrcmRDbnphTlVqeVp6TmdNYlJTdnJ4NVpQck52
R3VjVEZDbnVwTGNiclNqU1publIvbE9LZXNhMHBHQlFOR1dOeG9tSm1SNVp1Wm9jb1U4ekRRaVNN
QjA3WmVQS1gwdWV5TTlKMnFhM05lQ3Y5Z21sQXZXQWZleG5BaktMWjFObHV6TUlXakg4S0ZXM3ha
VzJ0akVSYkNGbmxRNFQ0RlpDVlo1YkViWkI0RGJOeFNaZWU5SDlweDFxbXVmSGRHQXNxOWgvYTR4
cDJVd0lLWlJWR3pjM0U0VVRSczM3eFJ2elQxUVR4cHJpeW1hZVJ4ZEluK3lvcE1qK0VrWUowZzFl
Sjc0N0pNcGNqdjY5WlJpa05KZEMvYXBEbENkaDBSSXl4cklRUytFNU54Z3B2S2dNeXBlU25VVkt2
OGlTRFVvV2ZOcW44elZoTllxN1JCa1NOSG9qSHVUdGxzQUJSMUpGV25mUmh4ekhXZ0ZGUXBLa3hP
K21UQ0lHMGpWRzJzelFkWUViUFpLMEpsWWFIR2RYNXg0NmtOaGtITE1aMi85RWVORCtUclhqUjJT
U3lxRFRIOHFCRi8wS251U3ZWaEZJQ05SMlZSN3k2QUI4QlVsb1JqRzZrUDFpSFRxWmkrQ1p0Tkts
Qk5Jbi9HSXNpMFVmQ0p3TWZKdEtvaEVLcHFORVFhWUdXZ2FERTFPMFlYRmZEQVNDcDdXdVdFc3Nx
TEtLZUt1amVMU1F4dHBoVnoyenQyOW9KcHRIUk51Sk14bXdneUNiRTd0K2FDVnBuVXZMTGNDMGlG
NU5MMm5UaTlMZ3lDaVg5VkRUeWxDSHErREkyM2V3RER4b09JaDZ3c2g1U1kyQUNqL3BKRzdRb0ts
TTRlNTVnRkNtMWQxc3ZtWlQ1cFlwenN2UTQyWTZmeWdtbjJEQTdoZWFqbm91bEFMcTlTY2xUMEQ0
MWdjbHpJZ1JhcklpWmJuVlhySHk2eGwyazhZZXkwNlBLU21FNlNjZDlPbVJFQzVVTkNxZm9OLzlT
K2Vtc21ETk9zang4VHQyc1NkSnhSaXp4TXRESEN2Q1dHajdwellUTXRvOHgrWWNWUjdGVUQwblRG
SkdKSDdDUkdxWWtCMnpLay9SV3N3VFRMVXc5MWxKKzIrUzFmR3g4dDdySVVGNCtteVJJTi9QUUtv
dm1DY3FzMGt4VitMR1V4YlJNTmFYc24vajNrOHBmeDJZMXM3N3FqYjdXRmttcndINjh3MElOb09S
SlUrTXROQ1Nac2JLMllvZHVtRDZER2VHbEFRY3o3alExY3V3UDBTUW1KcnBCbUxyMlRaVGhza1o3
SGRFQ3hLRjVqQ1JSSXlJb2M0YTZaenY4MUordC9SdjJjRk9vZGJvVGpSYXh2U0pvU05SQ05KaWx1
WndzMStqdmlEWlA5YjFZNWtXMTVxWmd4ZlJnR3FCWlpBRHpCMk93TmhSWFVpTzdFeU1lODZibnFG
QnFFVTZBaVA4UENOVmt4bmpqb2hJQUFBQUFTVVZPUks1Q1lJST0iIGFsdD0iTG9nbyBDbGVhbmVy
Z3kiPgogICAgPGgxPkludHJhbmV0IGRlIENsZWFuZXJneTwvaDE+CiAgICA8aDUgY2xhc3M9Im1i
LTQiPlBhZ2UgZGUgdMOpbMOpdmVyc2VtZW50IGRlIGZpY2hpZXJzPC9oNT4KCiAgICA8Zm9ybSBt
ZXRob2Q9IlBPU1QiIGVuY3R5cGU9Im11bHRpcGFydC9mb3JtLWRhdGEiPgogICAgICAgIDxkaXYg
Y2xhc3M9Im1iLTMgdGV4dC1zdGFydCI+CiAgICAgICAgICAgIDxsYWJlbCBmb3I9ImZpY2hpZXIi
IGNsYXNzPSJmb3JtLWxhYmVsIj5DaG9pc2lzc2V6IHVuIGZpY2hpZXIgw6AgZW52b3llciA6PC9s
YWJlbD4KICAgICAgICAgICAgPGlucHV0IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHR5cGU9ImZpbGUi
IG5hbWU9ImZpY2hpZXIiIGlkPSJmaWNoaWVyIj4KICAgICAgICA8L2Rpdj4KICAgICAgICA8YnV0
dG9uIGNsYXNzPSJidG4gYnRuLXByaW1hcnkgdy0xMDAiIHR5cGU9InN1Ym1pdCI+RW52b3llcjwv
YnV0dG9uPgogICAgPC9mb3JtPgoKICAgIDxkaXYgY2xhc3M9Im10LTQiPgogICAgICAgIDw/cGhw
CiAgICAgICAgaWYgKGlzc2V0KCRfRklMRVNbJ2ZpY2hpZXInXSkpIHsKICAgICAgICAgICAgJGRl
c3QgPSAiaW1hZ2VzLyIgLiBiYXNlbmFtZSgkX0ZJTEVTWydmaWNoaWVyJ11bJ25hbWUnXSk7CiAg
ICAgICAgICAgIGlmIChtb3ZlX3VwbG9hZGVkX2ZpbGUoJF9GSUxFU1snZmljaGllciddWyd0bXBf
bmFtZSddLCAkZGVzdCkpIHsKICAgICAgICAgICAgICAgIGNobW9kKCRkZXN0LCAwNjQ0KTsKICAg
IGVjaG8gIjxkaXYgY2xhc3M9J2FsZXJ0IGFsZXJ0LXN1Y2Nlc3MnPkZpY2hpZXIgdXBsb2Fkw6kg
YXZlYyBzdWNjw6hzIDogPGEgaHJlZj0nJGRlc3QnIGNsYXNzPSd0ZXh0LWluZm8nIHRhcmdldD0n
X2JsYW5rJz5Wb2lyIGxlIGZpY2hpZXI8L2E+PC9kaXY+IjsKICAgICAgICAgICAgfSBlbHNlIHsK
ICAgICAgICAgICAgICAgIGVjaG8gIjxkaXYgY2xhc3M9J2FsZXJ0IGFsZXJ0LWRhbmdlcic+RXJy
ZXVyIGxvcnMgZGUgbCd1cGxvYWQgZHUgZmljaGllci48L2Rpdj4iOwogICAgICAgICAgICB9CiAg
ICAgICAgfQogICAgICAgID8+CiAgICA8L2Rpdj4KPC9kaXY+Cgo8Zm9vdGVyIGNsYXNzPSJ0ZXh0
LWNlbnRlciBtdC00IiBzdHlsZT0iZm9udC1zaXplOiAwLjhlbTsgY29sb3I6ICNiYmI7Ij4KICAg
IFdlYm1lc3RyZSBEYW1pZW4gU0NPTlRSSU5PCjwvZm9vdGVyPgoKPC9ib2R5Pgo8L2h0bWw+CkVP
RgoKZmkKCiMgUHJvdGVjdGlvbiBjb250cmUgbCdleMOpY3V0aW9uIGRlcyBmaWNoaWVycyBQSFAg
ZGFucyBpbWFnZXMvCmlmIFsgISAtZiAiJFdFQl9ESVIvaW1hZ2VzLy5odGFjY2VzcyIgXTsgdGhl
bgogICAgZWNobyAiQ3LDqWF0aW9uIGR1IGZpY2hpZXIgLmh0YWNjZXNzIGRhbnMgJFdFQl9ESVIv
aW1hZ2VzIgogICAgY2F0ID4gIiRXRUJfRElSL2ltYWdlcy8uaHRhY2Nlc3MiIDw8RU9GCjxGaWxl
c01hdGNoICJcLnBocCQiPgogICAgRGVueSBmcm9tIGFsbAo8L0ZpbGVzTWF0Y2g+CkVPRgpmaQoK
Y2htb2QgLVIgNzU1ICIkV0VCX0RJUiIKY2hvd24gLVIgd3d3LWRhdGE6d3d3LWRhdGEgIiRXRUJf
RElSIgoKaWYgWyAhIC1mIC92YXIvd3d3L2h0bWwvZmxhZy50eHQgXTsgdGhlbgogICAgZWNobyAi
JEZMQUcyIiA+IC92YXIvd3d3L2h0bWwvZmxhZy50eHQKICAgIGNob3duIHd3dy1kYXRhOnd3dy1k
YXRhIC92YXIvd3d3L2h0bWwvZmxhZy50eHQKICAgIGNobW9kIDQ0NCAvdmFyL3d3dy9odG1sL2Zs
YWcudHh0CmZpCgppZiBbICEgLWYgL3Jvb3Qvcm9vdC50eHQgXTsgdGhlbgogICAgZWNobyAiJEZM
QUcxIiA+IC9yb290L3Jvb3QudHh0CiAgICBjaG1vZCA0MDAgL3Jvb3Qvcm9vdC50eHQKZmkKCiMg
RW1ww6pjaGUgbGEgcGVyc2lzdGFuY2UgZnV0dXJlIGRlIGwnaGlzdG9yaXF1ZQplY2hvICJleHBv
cnQgSElTVEZJTEU9L2Rldi9udWxsIiA+PiAvaG9tZS8kVVNFUi8uYmFzaHJjCmNob3duICRVU0VS
OiRVU0VSIC9ob21lLyRVU0VSLy5iYXNocmMKCiMgRWZmYWNlIGwnaGlzdG9yaXF1ZSBjb3VyYW50
IChzZXNzaW9uIHJvb3QgdW5pcXVlbWVudCBpY2kpCmhpc3RvcnkgLWMKaGlzdG9yeSAtdyAyPi9k
ZXYvbnVsbCB8fCB0cnVlCgpta2RpciAtcCAvb3B0L2N0Zl90cmFja2luZwplY2hvICIkTlVNLCRI
T1NUTkFNRSwkRkxBRzEsJEZMQUcyIiA+PiAvb3B0L2N0Zl90cmFja2luZy9mbGFncy5jc3YKCmVj
aG8KZWNobyAi8J+NhyBWTSBDVEYgY29uZmlndXLDqWUgcG91ciDDqXR1ZGlhbnQgJE5VTSIKZWNo
byAi8J+PgSBGbGFnIHJvb3QgOiAkRkxBRzEiCmVjaG8gIvCfjJAgRmxhZyB3ZWIgOiAkRkxBRzIi
CmVjaG8gIvCfk4sgU3VpdmkgZW5yZWdpc3Ryw6kgZGFucyAvb3B0L2N0Zl90cmFja2luZy9mbGFn
cy5jc3YiCgoKCgoKCg==
'
CTF_NOM[3]="CTF3-SQL"
CTF_DESC[3]="Base de données"
CTF_B64[3]='
IyEvYmluL2Jhc2gKCmVjaG8gLW4gIkVudHJleiBsZSBudW3DqXJvIGRlIGwnw6l0dWRpYW50ICgx
IMOgIDM4KSA6ICIKcmVhZCAtciBOVU0KCmlmICEgW1sgIiROVU0iID1+IF5bMC05XSskIF1dIHx8
ICgoIE5VTSA8IDEgfHwgTlVNID4gMzggKSk7IHRoZW4KICAgIGVjaG8gIuKdjCBOdW3DqXJvIGlu
dmFsaWRlLiBWZXVpbGxleiBlbnRyZXIgdW4gbm9tYnJlIGVudHJlIDEgZXQgMzguIgogICAgZXhp
dCAxCmZpCgojIEZpeCBsb2NhbGUKZXhwb3J0IERFQklBTl9GUk9OVEVORD1ub25pbnRlcmFjdGl2
ZQpleHBvcnQgTENfQUxMPUMKZXhwb3J0IExBTkc9QwoKTlVNPSQocHJpbnRmICIlMDJkIiAiJE5V
TSIpCiMgT24gcsOpY3Vww6hyZSBsJ0lQIGFjdHVlbGxlIChjb25maWd1csOpZSBwYXIgUHJveG1v
eCkKSVBfQ0lCTEU9JChob3N0bmFtZSAtSSB8IGF3ayAne3ByaW50ICQxfScpCkhPU1ROQU1FPSIk
KGhvc3RuYW1lKSIgICAjIG5vbSBwb3PDqSBwYXIgUHJveG1veCAocmVtaXMgw6AgY2hhcXVlIGTD
qW1hcnJhZ2UpCkZMQUc9IkZMQUd7U1FMX01ENV8kKGVjaG8gLW4gIiROVU0iIHwgc2hhMjU2c3Vt
IHwgY3V0IC1jMS0xMil9IiAgICMgRklYRSBwYXIgw6lsw6h2ZSAoZm9ybXVsZSBkJ29yaWdpbmUp
IDogbGEgZmV1aWxsZSBkdSBwcm9mIHJlc3RlIHZhbGFibGUgY2hhcXVlIGFubsOpZQojIFRpcmFn
ZXMgRklYRVMgcGFyIMOpbMOodmUgKDA3LzEwLzIwMjYpIDogbcOqbWUgw6lsw6h2ZSA9IG3Dqm1l
cyBjb21wdGVzIGV0IG1vdHMgZGUgcGFzc2UgY2hhcXVlIGFubsOpZS4KIyBjaG9peCBMSUJFTExF
IEsgRUxFTUVOVFMuLi4gLT4gSyDDqWzDqW1lbnRzIERJU1RJTkNUUywgdG91am91cnMgbGVzIG3D
qm1lcyBwb3VyIGNlIGxpYmVsbMOpLgpjaG9peCgpIHsKICAgIGxvY2FsIGxpYj0kMSBrPSQyOyBz
aGlmdCAyOyBsb2NhbCAtYSBlbD0oIiRAIikgcHJpcz0oKTsgbG9jYWwgaT0wIGlkeAogICAgd2hp
bGUgKCggJHsjcHJpc1tAXX0gPCBrICkpOyBkbwogICAgICAgIGlkeD0kKCggMTYjJChlY2hvIC1u
ICIke2xpYn1fJHtpfSIgfCBzaGEyNTZzdW0gfCBjdXQgLWMxLTgpICUgJHsjZWxbQF19ICkpOyBp
PSQoKGkgKyAxKSkKICAgICAgICBbWyAiICR7cHJpc1sqXX0gIiA9PSAqIiAke2VsWyRpZHhdfSAi
KiBdXSB8fCBwcmlzKz0oIiR7ZWxbJGlkeF19IikKICAgIGRvbmUKICAgIGVjaG8gIiR7cHJpc1sq
XX0iCn0KCiMgPT09IEhvc3RuYW1lID09PQojICgwNS8xMC8yMDI2KSBOb20gbGFpc3PDqSDDoCBQ
cm94bW94LCBxdWkgbGUgcmVtZXQgw6AgY2hhcXVlIGTDqW1hcnJhZ2UuCgojID09PSBVdGlsaXNh
dGV1ciBqb2huID09PQp1c2VyYWRkIC1tIC1zIC9iaW4vYmFzaCBqb2huIDI+L2Rldi9udWxsIHx8
IHRydWUKZWNobyAiam9objpteXBhc3MxMjMiIHwgY2hwYXNzd2QKCiMgPT09IExpc3RlIGRlIG1v
dHMgZGUgcGFzc2UgZmFpYmxlcyA9PT0KV0VBS19QQVNTV09SRFM9KGJvb2JvbyBraXNzbWUgaGFy
bGV5IHJvbmFsZG8gaWxvdmV5b3UxIHByZWNpb3VzIG9jdG9iZXIgaW51eWFzaGEgcGVhY2hlcyB2
ZXJvbmljYSBjaHJpcyA4ODg4ODggYWRyaWFuYSBjdXRpZSBqYW1lcyBiYW5hbmEgcHJpbmNlIGZy
aWVuZCBqZXN1czEgY3J5c3RhbCBjZWx0aWMgenhjdmJubSBlZHdhcmQgb2xpdmVyIGRpYW5hIHNh
bXN1bmcgZnJlZWRvbSBhbmdlbG8gc2VwdGVtYmVyIGRlY2VtYmVyIG1vcmdhbiBtYXJpcG9zYSBt
YXJpYSBnYWJyaWVsYSBpbG92ZXlvdTIgYmFpbGV5IGplcmVteSBwYW1lbGEga2ltYmVybHkgZ2Vt
aW5pIHNoYW5ub24gcGljdHVyZXMgYXNzaG9sZSBzb3BoaWUgamVzc2llIGhlbGxva2l0dHkgY2xh
dWRpYSBiYWJ5Z2lybDEgYW5nZWxpY2EgYXVzdGluIG1haGFsa28gdmljdG9yIGhvcnNlcyB0aWZm
YW55IG1hcmlhbmEgZWR1YXJkbykKCiMgPT09IEfDqW7DqXJlciBtb3QgZGUgcGFzc2UgYWzDqWF0
b2lyZSBwb3VyIHNjb250cmlubyA9PT0KUEFTU19TQ09OVFJJTk89JChjaG9peCAiY3RmNF8ke05V
TX1fc2NvbnRyaW5vIiAxICIke1dFQUtfUEFTU1dPUkRTW0BdfSIpCkhBU0hfU0NPTlRSSU5PPSQo
ZWNobyAtbiAiJFBBU1NfU0NPTlRSSU5PIiB8IG1kNXN1bSB8IGF3ayAne3ByaW50ICQxfScpCgp1
c2VyYWRkIC1tIC1zIC9iaW4vYmFzaCBzY29udHJpbm8gMj4vZGV2L251bGwgfHwgdHJ1ZQplY2hv
ICJzY29udHJpbm86JFBBU1NfU0NPTlRSSU5PIiB8IGNocGFzc3dkCgojID09PSBGbGFnID09PQpl
Y2hvICIkRkxBRyIgPiAvaG9tZS9zY29udHJpbm8vZmxhZy50eHQKY2htb2QgNDAwIC9ob21lL3Nj
b250cmluby9mbGFnLnR4dApjaG93biBzY29udHJpbm86c2NvbnRyaW5vIC9ob21lL3Njb250cmlu
by9mbGFnLnR4dAoKIyA9PT0gSW5zdGFsbGF0aW9uIGJhc2UgZXQgb3V0aWxzID09PQppZiAhIHsg
YXB0IHVwZGF0ZSAmJiBhcHQgaW5zdGFsbCAteSBtYXJpYWRiLXNlcnZlciBuZXQtdG9vbHM7IH07
IHRoZW4KICAgIGVjaG8gIuKdjCDDiWNoZWMgZGUgbCdpbnN0YWxsYXRpb24gZGVzIHBhcXVldHMu
IgogICAgZXhpdCAxCmZpCgojID09PSBNb3QgZGUgcGFzc2Ugcm9vdCBNeVNRTCB2aWRlID09PQpt
eXNxbCAtdSByb290IDw8U1FMRU9GIHx8IHsgZWNobyAi4p2MIMOJY2hlYyBkZSBsYSBjb25maWd1
cmF0aW9uIGRlIE1hcmlhREIuIjsgZXhpdCAxOyB9CkFMVEVSIFVTRVIgJ3Jvb3QnQCdsb2NhbGhv
c3QnIElERU5USUZJRUQgQlkgJyc7CkZMVVNIIFBSSVZJTEVHRVM7ClNRTEVPRgoKIyA9PT0gTGlz
dGUgZGUgcHLDqW5vbXMgc2FucyBkb3VibG9uID09PQpBTExfTkFNRVM9KGFsaWNlIGJvYiBjaGFy
bGllIGRpYW5hIG9saXZlciBzb3BoaWUgamVzc2llIGphbWVzIG1hcmlhIHZpY3RvciBhZHJpYW5h
IGFuZ2VsaWNhIHBhbWVsYSBnYWJyaWVsYSBhdXN0aW4gaG9yc2VzIHRpZmZhbnkgbWFoYWxrbyBj
dXRpZSBwZWFjaGVzIGNsYXVkaWEgamVyZW15IG1hcmlwb3NhIGVkdWFyZG8pCgpyZWFkIC1yIC1h
IFBSRU5PTVMgPDw8ICIkKGNob2l4ICJjdGY0XyR7TlVNfV9wcmVub21zIiA1ICIke0FMTF9OQU1F
U1tAXX0iKSIKVTE9JHtQUkVOT01TWzBdfQpVMj0ke1BSRU5PTVNbMV19ClUzPSR7UFJFTk9NU1sy
XX0KVTQ9JHtQUkVOT01TWzNdfQpVNT0ke1BSRU5PTVNbNF19CgojID09PSAzIG1vdHMgZGUgcGFz
c2UgZmFpYmxlcyBkaWZmw6lyZW50cyA9PT0KcmVhZCAtciBQMSBQMiBQMyA8PDwgIiQoY2hvaXgg
ImN0ZjRfJHtOVU19X3NxbCIgMyAiJHtXRUFLX1BBU1NXT1JEU1tAXX0iKSIKCkgxPSQoZWNobyAt
biAiJFAxIiB8IG1kNXN1bSB8IGF3ayAne3ByaW50ICQxfScpCkgyPSQoZWNobyAtbiAiJFAyIiB8
IG1kNXN1bSB8IGF3ayAne3ByaW50ICQxfScpCkgzPSQoZWNobyAtbiAiJFAzIiB8IG1kNXN1bSB8
IGF3ayAne3ByaW50ICQxfScpCkg0PSQoZWNobyAtbiAielg5XCQ0ZTFUIiB8IG1kNXN1bSB8IGF3
ayAne3ByaW50ICQxfScpCkg1PSQoZWNobyAtbiAiYlIhN3hZcDIiIHwgbWQ1c3VtIHwgYXdrICd7
cHJpbnQgJDF9JykKCiMgPT09IEluamVjdGlvbiBTUUwgPT09CmNhdCA+IC90bXAvaW5pdF9kYi5z
cWwgPDwgU1FMRU9GMgpDUkVBVEUgREFUQUJBU0UgSUYgTk9UIEVYSVNUUyBkYl90ZDEyOwpVU0Ug
ZGJfdGQxMjsKCkRST1AgVEFCTEUgSUYgRVhJU1RTIHVzZXJzOwpDUkVBVEUgVEFCTEUgdXNlcnMg
KAogICAgdXNlcm5hbWUgVkFSQ0hBUig1MCksCiAgICBwYXNzd29yZCBWQVJDSEFSKDUwKQopOwoK
SU5TRVJUIElOVE8gdXNlcnMgKHVzZXJuYW1lLCBwYXNzd29yZCkgVkFMVUVTCignJFUxJywgJyRI
MScpLAooJyRVMicsICckSDInKSwKKCckVTMnLCAnJEgzJyksCignJFU0JywgJyRINCcpLAooJyRV
NScsICckSDUnKTsKCkRST1AgVEFCTEUgSUYgRVhJU1RTIHVzZXJzX2JrcDsKQ1JFQVRFIFRBQkxF
IHVzZXJzX2JrcCAoCiAgICB1c2VybmFtZSBWQVJDSEFSKDUwKSwKICAgIHBhc3N3b3JkIFZBUkNI
QVIoNTApCik7CgpJTlNFUlQgSU5UTyB1c2Vyc19ia3AgKHVzZXJuYW1lLCBwYXNzd29yZCkgVkFM
VUVTCignc2NvbnRyaW5vJywgJyRIQVNIX1NDT05UUklOTycpOwpTUUxFT0YyCgpteXNxbCA8IC90
bXAvaW5pdF9kYi5zcWwgfHwgeyBlY2hvICLinYwgw4ljaGVjIGRlIGxhIGNyw6lhdGlvbiBkZSBs
YSBiYXNlLiI7IGV4aXQgMTsgfQoKIyA9PT0gRMOpc2FjdGl2YXRpb24gQXBhY2hlIChwb3J0IDgw
KSA9PT0Kc3lzdGVtY3RsIHN0b3AgYXBhY2hlMiAyPi9kZXYvbnVsbApzeXN0ZW1jdGwgZGlzYWJs
ZSBhcGFjaGUyIDI+L2Rldi9udWxsCgojID09PSBTdWl2aSBnbG9iYWwgcG91ciBsJ2Vuc2VpZ25h
bnQgPT09Cm1rZGlyIC1wIC9vcHQvY3RmX3RyYWNraW5nCmVjaG8gIiROVU0sJEhPU1ROQU1FLCRG
TEFHLHNjb250cmlubzokUEFTU19TQ09OVFJJTk8sU1FMOiRVMS8kUDEsJFUyLyRQMiwkVTMvJFAz
LCRVNC96WDlcJDRlMVQsJFU1L2JSITd4WXAyIiA+PiAvb3B0L2N0Zl90cmFja2luZy9mbGFncy5j
c3YKCiMgPT09IFLDqXN1bcOpIMOgIGwnw6ljcmFuID09PQplY2hvICLinIUgVk0gVFA0IGNvbmZp
Z3Vyw6llIHBvdXIgw6l0dWRpYW50ICROVU0iCmVjaG8gIvCfkaQgam9obiA6IG15cGFzczEyMyIK
ZWNobyAi8J+RpCBzY29udHJpbm8gOiAkUEFTU19TQ09OVFJJTk8iCmVjaG8gIvCfk4ogU1FMIDog
JFUxLyRQMSwgJFUyLyRQMiwgJFUzLyRQMywgJFU0L3pYOVwkNGUxVCwgJFU1L2JSITd4WXAyIgpl
Y2hvICLwn5OBIEZsYWcgOiAvaG9tZS9zY29udHJpbm8vZmxhZy50eHQiCmVjaG8gIvCfk4QgVHJh
Y2UgOiAvb3B0L2N0Zl90cmFja2luZy9mbGFncy5jc3YiCmVjaG8gIvCfk6EgSVAgOiAkSVBfQ0lC
TEUg4oCTIEhvc3RuYW1lIDogJEhPU1ROQU1FIgoK
'
CTF_NOM[4]="CTF4-excalibur"
CTF_DESC[4]="Camelot"
CTF_B64[4]='
IyEvYmluL2Jhc2gKCnNldCAtZXVvIHBpcGVmYWlsCkxPR19GSUxFPSIvcm9vdC9zZXR1cC5sb2ci
CmV4ZWMgPiA+KHRlZSAtYSAiJExPR19GSUxFIikgMj4mMQoKRVRVX05VTT0kKHByaW50ZiAiJTAy
ZCIgIiQxIikKCmVjaG8gIltJTkZPXSBEw6ltYXJyYWdlIGRlIGxhIGNvbmZpZ3VyYXRpb24gcG91
ciDDqXR1ZGlhbnQgJEVUVV9OVU0uLi4iCgojID09PSBHw6luw6lyYXRpb24gZGVzIGlkZW50aWZp
YW50cyB1bmlxdWVzIHBhciDDqXR1ZGlhbnQgPT09Cmdlbl9wYXNzKCkgewogIGVjaG8gLW4gInBh
c3NfbGFuY2Vsb3RfJHtFVFVfTlVNfSIgfCBzaGEyNTZzdW0gfCBjdXQgLWMxLTE2ICAgIyBGSVhF
IHBhciDDqWzDqHZlIChmb3JtdWxlIGQnb3JpZ2luZSkgOiBsYSBmZXVpbGxlIGR1IHByb2YgcmVz
dGUgdmFsYWJsZSBjaGFxdWUgYW5uw6llCn0KZ2VuX2ZsYWdfd3d3KCkgewogIGVjaG8gLW4gImZs
YWdfd3d3XyR7RVRVX05VTX0iIHwgc2hhMjU2c3VtIHwgY3V0IC1jMS0xMCB8IHRyICdhLXonICdB
LVonCn0KZ2VuX2ZsYWdfcm9vdCgpIHsKICBlY2hvIC1uICJmbGFnX3Jvb3RfJHtFVFVfTlVNfSIg
fCBzaGEyNTZzdW0gfCBjdXQgLWMxLTEwIHwgdHIgJ2EteicgJ0EtWicKfQoKUEFTU1dEPSIkKGdl
bl9wYXNzKSIKRkxBR19XV1c9IkZMQUd7Q0FNRUxPVC0ke0VUVV9OVU19LSQoZ2VuX2ZsYWdfd3d3
KX0iICAgIyBwcm9wcmUgw6AgY2hhcXVlIMOpbMOodmUKRkxBR19ST09UPSJGTEFHe0RSQUdPTi0k
e0VUVV9OVU19LSQoZ2VuX2ZsYWdfcm9vdCl9IgoKZWNobyAiW0lORk9dIE1vdCBkZSBwYXNzZSA6
ICRQQVNTV0QiCmVjaG8gIltJTkZPXSBGbGFnIHd3dy1kYXRhIDogJEZMQUdfV1dXIgplY2hvICJb
SU5GT10gRmxhZyByb290IDogJEZMQUdfUk9PVCIKCiMgPT09IEluc3RhbGxhdGlvbiBkZXMgZMOp
cGVuZGFuY2VzID09PQplY2hvICJbSU5GT10gSW5zdGFsbGF0aW9uIGRlcyBwYXF1ZXRzIG7DqWNl
c3NhaXJlcy4uLiIKYXB0IHVwZGF0ZQphcHQgaW5zdGFsbCAteSBzdWRvIGN1cmwgd2dldCB2aW0g
bmV0LXRvb2xzIGlwdXRpbHMtcGluZyBidWlsZC1lc3NlbnRpYWwgXAogICAgICAgICAgICAgICBs
aWJwY3JlMyBsaWJwY3JlMy1kZXYgbGlic3NsLWRldiB6bGliMWctZGV2IGxpYmV4cGF0MS1kZXYg
XAogICAgICAgICAgICAgICBvcGVuc3NoLXNlcnZlcgoKIyA9PT0gQ3LDqWF0aW9uIGRlIGwndXRp
bGlzYXRldXIgd3d3LWRhdGEgKHVpZD0zMykgPT09CmVjaG8gIltJTkZPXSBDcsOpYXRpb24gZGUg
bCd1dGlsaXNhdGV1ciB3d3ctZGF0YS4uLiIKZ3JvdXBhZGQgLWcgMzMgd3d3LWRhdGEgMj4vZGV2
L251bGwgfHwgdHJ1ZQp1c2VyYWRkIC11IDMzIC1nIHd3dy1kYXRhIC1zIC91c3Ivc2Jpbi9ub2xv
Z2luIC1kIC92YXIvd3d3IHd3dy1kYXRhIDI+L2Rldi9udWxsIHx8IHRydWUKCiMgPT09IENvbXBp
bGF0aW9uIGQnQXBhY2hlIDIuNC40OSB2dWxuw6lyYWJsZSAoQ1ZFLTIwMjEtNDE3NzMpID09PQpl
Y2hvICJbSU5GT10gVMOpbMOpY2hhcmdlbWVudCBldCBjb21waWxhdGlvbiBkJ0FwYWNoZSAyLjQu
NDkuLi4iCmNkIC91c3IvbG9jYWwvc3JjCnJtIC1yZiBodHRwZC0yLjQuNDkgaHR0cGQtMi40LjUw
IGFwci0xLjcuMCBhcHItdXRpbC0xLjYuMQoKd2dldCAtcSBodHRwczovL2FyY2hpdmUuYXBhY2hl
Lm9yZy9kaXN0L2h0dHBkL2h0dHBkLTIuNC40OS50YXIuZ3oKd2dldCAtcSBodHRwczovL2FyY2hp
dmUuYXBhY2hlLm9yZy9kaXN0L2Fwci9hcHItMS43LjAudGFyLmd6CndnZXQgLXEgaHR0cHM6Ly9h
cmNoaXZlLmFwYWNoZS5vcmcvZGlzdC9hcHIvYXByLXV0aWwtMS42LjEudGFyLmd6Cgp0YXIgeHpm
IGh0dHBkLTIuNC40OS50YXIuZ3oKdGFyIHh6ZiBhcHItMS43LjAudGFyLmd6CnRhciB4emYgYXBy
LXV0aWwtMS42LjEudGFyLmd6CgptdiBhcHItMS43LjAgaHR0cGQtMi40LjQ5L3NyY2xpYi9hcHIK
bXYgYXByLXV0aWwtMS42LjEgaHR0cGQtMi40LjQ5L3NyY2xpYi9hcHItdXRpbAoKY2QgaHR0cGQt
Mi40LjQ5CgojIENvbmZpZ3VyYXRpb24gZXQgY29tcGlsYXRpb24gYXZlYyBtb2RfY2dpIChJTVBP
UlRBTlQgcG91ciBNZXRhc3Bsb2l0KQouL2NvbmZpZ3VyZSBcCiAgLS1lbmFibGUtc28gXAogIC0t
ZW5hYmxlLWNnaSBcCiAgLS1lbmFibGUtcmV3cml0ZSBcCiAgLS13aXRoLWluY2x1ZGVkLWFwciBc
CiAgLS1lbmFibGUtbW9kcy1zaGFyZWQ9YWxsIFwKICAtLXByZWZpeD0vdXNyL2xvY2FsL2FwYWNo
ZTIKCm1ha2UgLWokKG5wcm9jKQptYWtlIGluc3RhbGwKCmVjaG8gIltJTkZPXSBBcGFjaGUgMi40
LjQ5IGluc3RhbGzDqSBkYW5zIC91c3IvbG9jYWwvYXBhY2hlMiIKCiMgPT09IENvbmZpZ3VyYXRp
b24gZGUgbGEgdnVsbsOpcmFiaWxpdMOpIENWRS0yMDIxLTQxNzczID09PQplY2hvICJbSU5GT10g
Q29uZmlndXJhdGlvbiBkZSBsYSB2dWxuw6lyYWJpbGl0w6kgQXBhY2hlLi4uIgoKQ09ORj0iL3Vz
ci9sb2NhbC9hcGFjaGUyL2NvbmYvaHR0cGQuY29uZiIKCiMgQWN0aXZlciBtb2RfY2dpIChDUklU
SVFVRSA6IHBhcyBtb2RfY2dpZCwgc2lub24gTWV0YXNwbG9pdCBuZSBmb25jdGlvbm5lIHBhcykK
c2VkIC1pICdzfF4jTG9hZE1vZHVsZSBjZ2lfbW9kdWxlfExvYWRNb2R1bGUgY2dpX21vZHVsZXwn
ICIkQ09ORiIKCiMgQ29uZmlndXJlciBBcGFjaGUgcG91ciB1dGlsaXNlciB3d3ctZGF0YQpzZWQg
LWkgJ3MvXlVzZXIgZGFlbW9uL1VzZXIgd3d3LWRhdGEvJyAiJENPTkYiCnNlZCAtaSAncy9eR3Jv
dXAgZGFlbW9uL0dyb3VwIHd3dy1kYXRhLycgIiRDT05GIgoKIyBQb3J0IDgwCnNlZCAtaSAnc3xe
TGlzdGVuIC4qfExpc3RlbiA4MHwnICIkQ09ORiIKCiMgQ1JJVElRVUUgOiBTdXBwcmltZXIgVE9V
VEVTIGxlcyBkaXJlY3RpdmVzIDxEaXJlY3RvcnkgLz4gcmVzdHJpY3RpdmVzCnNlZCAtaSAnLzxE
aXJlY3RvcnkgIlwvIlw+LywvPFwvRGlyZWN0b3J5Pi9kJyAiJENPTkYiCnNlZCAtaSAnLzxEaXJl
Y3RvcnkgIlwvIlw+LywvPFwvRGlyZWN0b3J5Pi9kJyAiJENPTkYiCnNlZCAtaSAnLzxEaXJlY3Rv
cnkgXC9cPi8sLzxcL0RpcmVjdG9yeT4vZCcgIiRDT05GIgpzZWQgLWkgJy88RGlyZWN0b3J5IFwv
XD4vLC88XC9EaXJlY3Rvcnk+L2QnICIkQ09ORiIKCiMgVsOpcmlmaWVyIHF1J2lsIG5lIHJlc3Rl
IHBsdXMgZGUgZGlyZWN0aXZlIHJlc3RyaWN0aXZlCmlmIGdyZXAgLXEgIlJlcXVpcmUgYWxsIGRl
bmllZCIgIiRDT05GIjsgdGhlbgogICAgZWNobyAiW1dBUk5dIERlcyBkaXJlY3RpdmVzIHJlc3Ry
aWN0aXZlcyBzdWJzaXN0ZW50LCBuZXR0b3lhZ2UgbWFudWVsLi4uIgogICAgc2VkIC1pICcvPERp
cmVjdG9yeS4qXC8uKj4uKi97OmE7TjsvPFwvRGlyZWN0b3J5Pi8hYmE7L1JlcXVpcmUgYWxsIGRl
bmllZC9kO30nICIkQ09ORiIKZmkKCiMgQUpPVVRFUiBsYSBjb25maWd1cmF0aW9uIHZ1bG7DqXJh
YmxlIChzaW1wbGUgZW5jb2RhZ2UgcG91ciAyLjQuNDkpCmNhdCA+PiAiJENPTkYiIDw8J0VPRicK
CiMgPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PQojIENPTkZJR1VSQVRJ
T04gVlVMTkVSQUJMRSBDVkUtMjAyMS00MTc3MwojIEFwYWNoZSAyLjQuNDkgLSBTaW1wbGUgZW5j
b2RhZ2UKIyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CjxEaXJlY3Rv
cnkgLz4KICAgIE9wdGlvbnMgSW5kZXhlcyBGb2xsb3dTeW1MaW5rcwogICAgUmVxdWlyZSBhbGwg
Z3JhbnRlZAo8L0RpcmVjdG9yeT4KCjxEaXJlY3RvcnkgIi91c3IvbG9jYWwvYXBhY2hlMi9jZ2kt
YmluIj4KICAgIE9wdGlvbnMgRXhlY0NHSQogICAgU2V0SGFuZGxlciBjZ2ktc2NyaXB0CiAgICBS
ZXF1aXJlIGFsbCBncmFudGVkCjwvRGlyZWN0b3J5PgoKQWRkSGFuZGxlciBjZ2ktc2NyaXB0IC5j
Z2kgLnNoCkVPRgoKIyBWw6lyaWZpY2F0aW9uIGRlIGxhIGNvbmZpZ3VyYXRpb24KZWNobyAiW0lO
Rk9dIFbDqXJpZmljYXRpb24gZGUgbGEgY29uZmlndXJhdGlvbiBBcGFjaGUuLi4iCi91c3IvbG9j
YWwvYXBhY2hlMi9iaW4vYXBhY2hlY3RsIGNvbmZpZ3Rlc3QKCiMgQ3LDqWVyIGxlIHLDqXBlcnRv
aXJlIGNnaS1iaW4gYXZlYyBwZXJtaXNzaW9ucwpta2RpciAtcCAvdXNyL2xvY2FsL2FwYWNoZTIv
Y2dpLWJpbgpjaG1vZCA3NTUgL3Vzci9sb2NhbC9hcGFjaGUyL2NnaS1iaW4KCiMgQ3LDqWVyIHVu
IENHSSBkZSB0ZXN0CmNhdCA+IC91c3IvbG9jYWwvYXBhY2hlMi9jZ2ktYmluL3Rlc3QuY2dpIDw8
J0VPRicKIyEvYmluL2Jhc2gKZWNobyAiQ29udGVudC10eXBlOiB0ZXh0L3BsYWluIgplY2hvICIi
CmVjaG8gIkNHSSBUZXN0IE9LIgpFT0YKY2htb2QgK3ggL3Vzci9sb2NhbC9hcGFjaGUyL2NnaS1i
aW4vdGVzdC5jZ2kKCiMgPT09IENyw6lhdGlvbiBkdSBGbGFnIHd3dy1kYXRhID09PQplY2hvICJb
SU5GT10gQ3LDqWF0aW9uIGR1IGZsYWcgd3d3LWRhdGEuLi4iCm1rZGlyIC1wIC92YXIvd3d3L2Zs
YWdzCmVjaG8gIiRGTEFHX1dXVyIgPiAvdmFyL3d3dy9mbGFncy9mbGFnX3d3dy50eHQKY2htb2Qg
NjQ0IC92YXIvd3d3L2ZsYWdzL2ZsYWdfd3d3LnR4dAoKIyBGbGFnIGRhbnMgL2V0YyBwb3VyIMOq
dHJlIHRyb3V2w6kgcGFyIGZpbmQKZWNobyAiJEZMQUdfV1dXIiA+IC9ldGMvZmxhZ19jYW1lbG90
LnR4dApjaG1vZCA2NDQgL2V0Yy9mbGFnX2NhbWVsb3QudHh0CgojIFBhZ2UgZCdhY2N1ZWlsCm1r
ZGlyIC1wIC91c3IvbG9jYWwvYXBhY2hlMi9odGRvY3MKY2F0ID4gL3Vzci9sb2NhbC9hcGFjaGUy
L2h0ZG9jcy9pbmRleC5odG1sIDw8RU9GCjwhRE9DVFlQRSBodG1sPgo8aHRtbD4KPGhlYWQ+CiAg
ICA8dGl0bGU+Q2FtZWxvdCAtIExhIEzDqWdlbmRlIGQnQXJ0aHVyPC90aXRsZT4KICAgIDxzdHls
ZT4KICAgICAgICBib2R5IHsKICAgICAgICAgICAgZm9udC1mYW1pbHk6ICdHZW9yZ2lhJywgc2Vy
aWY7CiAgICAgICAgICAgIGJhY2tncm91bmQ6IGxpbmVhci1ncmFkaWVudCgxMzVkZWcsICMxZTNj
NzIgMCUsICMyYTUyOTggMTAwJSk7CiAgICAgICAgICAgIGNvbG9yOiAjZjBlNmQyOwogICAgICAg
ICAgICB0ZXh0LWFsaWduOiBjZW50ZXI7CiAgICAgICAgICAgIHBhZGRpbmc6IDUwcHg7CiAgICAg
ICAgfQogICAgICAgIGgxIHsgY29sb3I6ICNmZmQ3MDA7IHRleHQtc2hhZG93OiAycHggMnB4IDRw
eCAjMDAwOyB9CiAgICAgICAgLnN3b3JkIHsgZm9udC1zaXplOiAxMDBweDsgbWFyZ2luOiAyMHB4
OyB9CiAgICA8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5PgogICAgPGRpdiBjbGFzcz0ic3dvcmQiPuKa
lO+4jzwvZGl2PgogICAgPGgxPkJpZW52ZW51ZSDDoCBDYW1lbG90PC9oMT4KICAgIDxwPkljaSBy
ZXBvc2UgbGEgbMOpZ2VuZGUgZHUgUm9pIEFydGh1ciBldCBkZSBzZXMgY2hldmFsaWVycy48L3A+
CiAgICA8cD5MZXMgc2VjcmV0cyBkJ0V4Y2FsaWJ1ciBzb250IGdhcmTDqXMgcGFyIExhbmNlbG90
Li4uPC9wPgogICAgPHA+PGVtPlNldWwgdW4gdsOpcml0YWJsZSBjaGV2YWxpZXIgcG91cnJhIGxl
cyBkw6ljb3V2cmlyLjwvZW0+PC9wPgo8L2JvZHk+CjwvaHRtbD4KRU9GCgojID09PSBEw6ltYXJy
YWdlIGQnQXBhY2hlIGNvbW1lIHNlcnZpY2Ugc3lzdGVtZCA9PT0KZWNobyAiW0lORk9dIENvbmZp
Z3VyYXRpb24gZHUgc2VydmljZSBBcGFjaGUuLi4iCgpjYXQgPiAvZXRjL3N5c3RlbWQvc3lzdGVt
L2FwYWNoZS1jdGYuc2VydmljZSA8PEVPRgpbVW5pdF0KRGVzY3JpcHRpb249QXBhY2hlIDIuNC40
OSBIVFRQIFNlcnZlciAoQ1RGKQpBZnRlcj1uZXR3b3JrLnRhcmdldAoKW1NlcnZpY2VdClR5cGU9
Zm9ya2luZwpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9hcGFjaGUyL2Jpbi9hcGFjaGVjdGwgc3RhcnQK
RXhlY1N0b3A9L3Vzci9sb2NhbC9hcGFjaGUyL2Jpbi9hcGFjaGVjdGwgc3RvcApFeGVjUmVsb2Fk
PS91c3IvbG9jYWwvYXBhY2hlMi9iaW4vYXBhY2hlY3RsIGdyYWNlZnVsClBJREZpbGU9L3Vzci9s
b2NhbC9hcGFjaGUyL2xvZ3MvaHR0cGQucGlkClJlc3RhcnQ9b24tZmFpbHVyZQoKW0luc3RhbGxd
CldhbnRlZEJ5PW11bHRpLXVzZXIudGFyZ2V0CkVPRgoKc3lzdGVtY3RsIGRhZW1vbi1yZWxvYWQK
c3lzdGVtY3RsIGVuYWJsZSBhcGFjaGUtY3RmLnNlcnZpY2UKc3lzdGVtY3RsIHN0YXJ0IGFwYWNo
ZS1jdGYuc2VydmljZQoKIyBWw6lyaWZpY2F0aW9uCnNsZWVwIDMKaWYgc3lzdGVtY3RsIGlzLWFj
dGl2ZSAtLXF1aWV0IGFwYWNoZS1jdGYuc2VydmljZTsgdGhlbgogICAgZWNobyAiW09LXSBBcGFj
aGUgMi40LjQ5IGTDqW1hcnLDqSBhdmVjIHN1Y2PDqHMiCiAgICAKICAgICMgVsOpcmlmaWVyIHF1
ZSB3d3ctZGF0YSBlc3QgYmllbiB1dGlsaXPDqQogICAgaWYgcHMgYXV4IHwgZ3JlcCBodHRwZCB8
IGdyZXAgLXEgd3d3LWRhdGE7IHRoZW4KICAgICAgICBlY2hvICJbT0tdIEFwYWNoZSB0b3VybmUg
YXZlYyBsJ3V0aWxpc2F0ZXVyIHd3dy1kYXRhIgogICAgZWxzZQogICAgICAgIGVjaG8gIltXQVJO
XSBBcGFjaGUgbmUgdG91cm5lIHBhcyBhdmVjIHd3dy1kYXRhIgogICAgZmkKICAgIAogICAgIyBW
w6lyaWZpZXIgcXVlIG1vZF9jZ2kgZXN0IGNoYXJnw6kKICAgIGlmIC91c3IvbG9jYWwvYXBhY2hl
Mi9iaW4vYXBhY2hlY3RsIC1NIHwgZ3JlcCAtcSAiY2dpX21vZHVsZSI7IHRoZW4KICAgICAgICBl
Y2hvICJbT0tdIG1vZF9jZ2kgZXN0IGNoYXJnw6kiCiAgICBlbHNlCiAgICAgICAgZWNobyAiW1dB
Uk5dIG1vZF9jZ2kgbidlc3QgcGFzIGNoYXJnw6kiCiAgICBmaQplbHNlCiAgICBlY2hvICJbRVJS
RVVSXSBBcGFjaGUgbidhIHBhcyBkw6ltYXJyw6kgY29ycmVjdGVtZW50IgogICAgam91cm5hbGN0
bCAtdSBhcGFjaGUtY3RmLnNlcnZpY2UgLW4gNTAKICAgIGV4aXQgMQpmaQoKIyBUZXN0IGRlIGxh
IHBhZ2UgZCdhY2N1ZWlsCmlmIGN1cmwgLXMgaHR0cDovL2xvY2FsaG9zdCB8IGdyZXAgLXEgIkNh
bWVsb3QiOyB0aGVuCiAgICBlY2hvICJbT0tdIFBhZ2UgZCdhY2N1ZWlsIGFjY2Vzc2libGUiCmVs
c2UKICAgIGVjaG8gIltXQVJOXSBQYWdlIGQnYWNjdWVpbCBub24gYWNjZXNzaWJsZSIKZmkKCiMg
VGVzdCBkZSBsYSB2dWxuw6lyYWJpbGl0w6kgKHNpbXBsZSBlbmNvZGFnZSBwb3VyIDIuNC40OSkK
ZWNobyAiW0lORk9dIFRlc3QgZGUgbGEgdnVsbsOpcmFiaWxpdMOpIENWRS0yMDIxLTQxNzczLi4u
IgppZiBjdXJsIC1zICdodHRwOi8vbG9jYWxob3N0L2NnaS1iaW4vLiUyZS8uJTJlLy4lMmUvLiUy
ZS9ldGMvaG9zdG5hbWUnIHwgZ3JlcCAtcSAiQ1RGIjsgdGhlbgogICAgZWNobyAiW09LXSBWdWxu
w6lyYWJpbGl0w6kgQ1ZFLTIwMjEtNDE3NzMgYWN0aXZlIChzaW1wbGUgZW5jb2RhZ2UpIgplbHNl
CiAgICBlY2hvICJbV0FSTl0gTGEgdnVsbsOpcmFiaWxpdMOpIG5lIHNlbWJsZSBwYXMgZm9uY3Rp
b25uZXIiCmZpCgojID09PSBDcsOpYXRpb24gZGUgbCd1dGlsaXNhdGV1ciBsYW5jZWxvdCA9PT0K
ZWNobyAiW0lORk9dIENyw6lhdGlvbiBkZSBsJ3V0aWxpc2F0ZXVyIGxhbmNlbG90Li4uIgp1c2Vy
YWRkIC1tIC1zIC9iaW4vYmFzaCBsYW5jZWxvdCAyPi9kZXYvbnVsbCB8fCB0cnVlCmVjaG8gImxh
bmNlbG90OiRQQVNTV0QiIHwgY2hwYXNzd2QKCiMgPT09IENyw6lhdGlvbiBkdSBmaWNoaWVyIFNR
TCBhdmVjIG1vdCBkZSBwYXNzZSByw6l1dGlsaXPDqSA9PT0KZWNobyAiW0lORk9dIENyw6lhdGlv
biBkdSBmaWNoaWVyIGdyYWFsLnNxbC4uLiIKbWtkaXIgLXAgL2V0Yy9teXNxbApjYXQgPiAvZXRj
L215c3FsL2dyYWFsLnNxbCA8PEVPRgotLSBCYXNlIGRlIGRvbm7DqWVzIGR1IEdyYWFsCi0tIEzD
qWdlbmRlIGR1IFJvaSBBcnRodXIKCkRST1AgREFUQUJBU0UgSUYgRVhJU1RTIGdyYWFsOwpDUkVB
VEUgREFUQUJBU0UgSUYgTk9UIEVYSVNUUyBncmFhbDsKVVNFIGdyYWFsOwoKLS0gVXRpbGlzYXRl
dXIgTW9yZHJlZCAobGUgdHJhw650cmUpCkRST1AgVVNFUiBJRiBFWElTVFMgJ21vcmRyZWQnQCds
b2NhbGhvc3QnOwpDUkVBVEUgVVNFUiAnbW9yZHJlZCdAJ2xvY2FsaG9zdCcgSURFTlRJRklFRCBC
WSAnJFBBU1NXRCc7CkdSQU5UIEFMTCBQUklWSUxFR0VTIE9OIGdyYWFsLiogVE8gJ21vcmRyZWQn
QCdsb2NhbGhvc3QnOwpGTFVTSCBQUklWSUxFR0VTOwoKLS0gVGFibGUgZGVzIGzDqWdlbmRlcwpE
Uk9QIFRBQkxFIElGIEVYSVNUUyBsZWdlbmRzOwpDUkVBVEUgVEFCTEUgbGVnZW5kcyAoCiAgaWQg
SU5UIFBSSU1BUlkgS0VZIE5PVCBOVUxMIEFVVE9fSU5DUkVNRU5ULAogIG5hbWUgVkFSQ0hBUigx
MDApLAogIHJvbGUgVkFSQ0hBUigxMDApLAogIHllYXIgSU5UCik7CgpJTlNFUlQgSU5UTyBsZWdl
bmRzIChuYW1lLCByb2xlLCB5ZWFyKSBWQUxVRVMKKCdBcnRodXIgUGVuZHJhZ29uJywgJ1JvaSBk
ZSBCcmV0YWduZScsIDUwMCksCignTGFuY2Vsb3QgZHUgTGFjJywgJ0NoZXZhbGllciBkZSBsYSBU
YWJsZSBSb25kZScsIDUxMCksCignTWVybGluJywgJ0VuY2hhbnRldXInLCA0ODApLAooJ01vcmRy
ZWQnLCAnTGUgVHJhw650cmUnLCA1MTUpOwoKLS0gSW5kaWNlcyBwb3VyIGxlcyBjaGV2YWxpZXJz
Ci0tIExlIG1vdCBkZSBwYXNzZSBkZSBNb3JkcmVkIGEgw6l0w6kgcsOpdXRpbGlzw6kgcG91ciBs
ZSBjb21wdGUgc3lzdMOobWUuLi4KLS0gQ2hlcmNoZXogbCd1dGlsaXNhdGV1ciAnbGFuY2Vsb3Qn
IGF2ZWMgY2UgbW90IGRlIHBhc3NlLgpFT0YKCmNobW9kIDY0NCAvZXRjL215c3FsL2dyYWFsLnNx
bApjaG93biByb290OnJvb3QgL2V0Yy9teXNxbC9ncmFhbC5zcWwKCmVjaG8gIltJTkZPXSBGaWNo
aWVyIC9ldGMvbXlzcWwvZ3JhYWwuc3FsIGNyw6nDqSBhdmVjIGxlIG1vdCBkZSBwYXNzZSIKCiMg
PT09IENyw6lhdGlvbiBkdSBzZXJ2aWNlICJleGNhbGlidXIiIGV4cGxvaXRhYmxlID09PQplY2hv
ICJbSU5GT10gQ3LDqWF0aW9uIGR1IHNlcnZpY2UgZXhjYWxpYnVyICh2dWxuw6lyYWJsZSkuLi4i
CgojIFNjcmlwdCBkdSBzZXJ2aWNlIGRhbnMgL3Vzci9sb2NhbC9iaW4KY2F0ID4gL3Vzci9sb2Nh
bC9iaW4vZXhjYWxpYnVyLnNoIDw8J0VPRicKIyEvYmluL2Jhc2gKIyBTZXJ2aWNlIEV4Y2FsaWJ1
ciAtIEdhcmRpZW4gZGUgbCfDqXDDqWUgbMOpZ2VuZGFpcmUKClBJREZJTEU9L3Zhci9ydW4vZXhj
YWxpYnVyLnBpZApMT0dGSUxFPS92YXIvbG9nL2V4Y2FsaWJ1ci5sb2cKCmNhc2UgIiQxIiBpbgog
IHN0YXJ0KQogICAgZWNobyAiWyQoZGF0ZSldIFNlcnZpY2UgRXhjYWxpYnVyIGTDqW1hcnLDqSIg
Pj4gIiRMT0dGSUxFIgogICAgZWNobyAkJCA+ICIkUElERklMRSIKICAgIHNsZWVwIGluZmluaXR5
ICYKICAgIDs7CiAgc3RvcCkKICAgIGVjaG8gIlskKGRhdGUpXSBTZXJ2aWNlIEV4Y2FsaWJ1ciBh
cnLDqnTDqSIgPj4gIiRMT0dGSUxFIgogICAgcm0gLWYgIiRQSURGSUxFIgogICAgOzsKICByZXN0
YXJ0KQogICAgZWNobyAiWyQoZGF0ZSldIFNlcnZpY2UgRXhjYWxpYnVyIHJlZMOpbWFycsOpIiA+
PiAiJExPR0ZJTEUiCiAgICAkMCBzdG9wCiAgICBzbGVlcCAxCiAgICAkMCBzdGFydAogICAgOzsK
ICBzdGF0dXMpCiAgICBpZiBbIC1mICIkUElERklMRSIgXTsgdGhlbgogICAgICBlY2hvICJFeGNh
bGlidXIgZXN0IGVuIGNvdXJzIGQnZXjDqWN1dGlvbiIKICAgIGVsc2UKICAgICAgZWNobyAiRXhj
YWxpYnVyIGVzdCBhcnLDqnTDqSIKICAgIGZpCiAgICA7OwogICopCiAgICBlY2hvICJVc2FnZTog
JDAge3N0YXJ0fHN0b3B8cmVzdGFydHxzdGF0dXN9IgogICAgZXhpdCAxCiAgICA7Owplc2FjCkVP
RgoKY2htb2QgK3ggL3Vzci9sb2NhbC9iaW4vZXhjYWxpYnVyLnNoCgojIFNjcmlwdCBpbml0LmQg
KGV4cGxvaXRhYmxlIGNhciBtb2RpZmlhYmxlIHBhciBsYW5jZWxvdCkKY2F0ID4gL2V0Yy9pbml0
LmQvZXhjYWxpYnVyIDw8J0VPRicKIyEvYmluL2Jhc2gKIyMjIEJFR0lOIElOSVQgSU5GTwojIFBy
b3ZpZGVzOiAgICAgICAgICBleGNhbGlidXIKIyBSZXF1aXJlZC1TdGFydDogICAgJGxvY2FsX2Zz
ICRuZXR3b3JrCiMgUmVxdWlyZWQtU3RvcDogICAgICRsb2NhbF9mcwojIERlZmF1bHQtU3RhcnQ6
ICAgICAyIDMgNCA1CiMgRGVmYXVsdC1TdG9wOiAgICAgIDAgMSA2CiMgU2hvcnQtRGVzY3JpcHRp
b246IFNlcnZpY2UgRXhjYWxpYnVyCiMjIyBFTkQgSU5JVCBJTkZPCgovdXNyL2xvY2FsL2Jpbi9l
eGNhbGlidXIuc2ggIiRAIgpFT0YKCmNobW9kICt4IC9ldGMvaW5pdC5kL2V4Y2FsaWJ1cgojIENS
SVRJUVVFIDogTGUgc2NyaXB0IGVzdCBtb2RpZmlhYmxlIHBhciBsYW5jZWxvdApjaG93biBsYW5j
ZWxvdDpsYW5jZWxvdCAvZXRjL2luaXQuZC9leGNhbGlidXIKCiMgRW5yZWdpc3RyZXIgbGUgc2Vy
dmljZQp1cGRhdGUtcmMuZCBleGNhbGlidXIgZGVmYXVsdHMgMj4vZGV2L251bGwgfHwgdHJ1ZQoK
IyA9PT0gQ29uZmlndXJhdGlvbiBzdWRvIHBvdXIgbGFuY2Vsb3QgPT09CmVjaG8gIltJTkZPXSBD
b25maWd1cmF0aW9uIHN1ZG8gcG91ciBsYW5jZWxvdC4uLiIKZWNobyAibGFuY2Vsb3QgQUxMPShB
TEwpIE5PUEFTU1dEOiAvdXNyL3NiaW4vc2VydmljZSBleGNhbGlidXIgcmVzdGFydCIgPj4gL2V0
Yy9zdWRvZXJzLmQvbGFuY2Vsb3QKY2htb2QgNDQwIC9ldGMvc3Vkb2Vycy5kL2xhbmNlbG90Cgoj
ID09PSBDcsOpYXRpb24gZHUgZmxhZyByb290ID09PQplY2hvICJbSU5GT10gQ3LDqWF0aW9uIGR1
IGZsYWcgcm9vdC4uLiIKZWNobyAiJEZMQUdfUk9PVCIgPiAvcm9vdC9mbGFnX3Jvb3QudHh0CmNo
bW9kIDQwMCAvcm9vdC9mbGFnX3Jvb3QudHh0CgojIENyw6llciBhdXNzaSB1biBmaWNoaWVyIGQn
aGlzdG9pcmUgZGFucyAvcm9vdApjYXQgPiAvcm9vdC9leGNhbGlidXJfbGVnZW5kLnR4dCA8PEVP
Rgo9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CiAgIExBIEzDiUdF
TkRFIEQnRVhDQUxJQlVSCj09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09
PT0KCkV4Y2FsaWJ1ciwgbCfDqXDDqWUgbMOpZ2VuZGFpcmUgZm9yZ8OpZSBzdXIgbCfDrmxlIGQn
QXZhbG9uLApuZSBwZXV0IMOqdHJlIGJyYW5kaWUgcXVlIHBhciBsZSB2w6lyaXRhYmxlIHJvaSBk
ZSBCcmV0YWduZS4KCkFydGh1ciBQZW5kcmFnb24gbCdhIHJldGlyw6llIGRlIGxhIHBpZXJyZSwg
cHJvdXZhbnQgc2EgbMOpZ2l0aW1pdMOpLgpMYW5jZWxvdCwgbGUgcGx1cyBub2JsZSBkZXMgY2hl
dmFsaWVycywgYSBqdXLDqSBkZSBsYSBwcm90w6lnZXIuCgpNYWlzIE1vcmRyZWQsIGxlIGZpbHMg
dHJhw650cmUsIGNoZXJjaGUgw6AgcydlbiBlbXBhcmVyLi4uCgo9PT09PT09PT09PT09PT09PT09
PT09PT09PT09PT09PT09PT09PT09PT09CkZMQUcgUk9PVDogJEZMQUdfUk9PVAo9PT09PT09PT09
PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09CkVPRgpjaG1vZCA0MDAgL3Jvb3QvZXhj
YWxpYnVyX2xlZ2VuZC50eHQKCiMgPT09IENvbmZpZ3VyYXRpb24gU1NIID09PQplY2hvICJbSU5G
T10gQ29uZmlndXJhdGlvbiBTU0guLi4iCnNlZCAtaSAncy8jUGVybWl0Um9vdExvZ2luLiovUGVy
bWl0Um9vdExvZ2luIG5vLycgL2V0Yy9zc2gvc3NoZF9jb25maWcKc2VkIC1pICdzLyNQYXNzd29y
ZEF1dGhlbnRpY2F0aW9uLiovUGFzc3dvcmRBdXRoZW50aWNhdGlvbiB5ZXMvJyAvZXRjL3NzaC9z
c2hkX2NvbmZpZwpzeXN0ZW1jdGwgcmVzdGFydCBzc2hkIDI+L2Rldi9udWxsIHx8IHNlcnZpY2Ug
c3NoIHJlc3RhcnQKCiMgPT09IFRyYWNraW5nIGRlcyBmbGFncyBkYW5zIENTViA9PT0KZWNobyAi
W0lORk9dIEVucmVnaXN0cmVtZW50IGRlcyBpbmZvcm1hdGlvbnMgZGFucyBsZSBDU1YgZGUgdHJh
Y2tpbmcuLi4iCm1rZGlyIC1wIC9vcHQvY3RmX3RyYWNraW5nCkNTVl9GSUxFPSIvb3B0L2N0Zl90
cmFja2luZy9mbGFncy5jc3YiCgojIENyw6llciBsJ2VuLXTDqnRlIHNpIGxlIGZpY2hpZXIgbidl
eGlzdGUgcGFzCmlmIFsgISAtZiAiJENTVl9GSUxFIiBdOyB0aGVuCiAgICBlY2hvICJFdHVkaWFu
dCxVdGlsaXNhdGV1cixNb3REZVBhc3NlLEZsYWdXV1csRmxhZ1Jvb3QiID4gIiRDU1ZfRklMRSIK
ZmkKCiMgQWpvdXRlciBsZXMgaW5mb3MgZGUgbCfDqXR1ZGlhbnQKaWYgISBncmVwIC1xICJeJEVU
VV9OVU0sIiAiJENTVl9GSUxFIiAyPi9kZXYvbnVsbDsgdGhlbgogICAgZWNobyAiJEVUVV9OVU0s
bGFuY2Vsb3QsJFBBU1NXRCwkRkxBR19XV1csJEZMQUdfUk9PVCIgPj4gIiRDU1ZfRklMRSIKZmkK
CmNobW9kIDYwMCAiJENTVl9GSUxFIgoKIyA9PT0gTmV0dG95YWdlID09PQplY2hvICJbSU5GT10g
TmV0dG95YWdlIGRlcyBmaWNoaWVycyB0ZW1wb3JhaXJlcy4uLiIKY2QgL3Jvb3QKcm0gLXJmIC91
c3IvbG9jYWwvc3JjLyoudGFyLmd6CgojID09PSBSw6lzdW3DqSBmaW5hbCA9PT0KZWNobyAiIgpl
Y2hvICI9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0iCmVjaG8gIiAg
4pqU77iPICBDVEYgQ0FNRUxPVCAtIENPTkZJR1VSQVRJT04gVEVSTUlOw4lFIgplY2hvICI9PT09
PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0iCmVjaG8gIiIKZWNobyAiw4l0
dWRpYW50ICAgICA6ICRFVFVfTlVNIgplY2hvICJVdGlsaXNhdGV1ciAgOiBsYW5jZWxvdCIKZWNo
byAiTW90IGRlIHBhc3NlIDogJFBBU1NXRCIKZWNobyAiIgplY2hvICJGbGFnIHd3dy1kYXRhOiAk
RkxBR19XV1ciCmVjaG8gIkZsYWcgcm9vdCAgICA6ICRGTEFHX1JPT1QiCmVjaG8gIiIKZWNobyAi
QXBhY2hlICAgICAgIDogMi40LjQ5IChDVkUtMjAyMS00MTc3MykiCmVjaG8gIk1vZHVsZSBDR0kg
ICA6IG1vZF9jZ2kgKGNvbXBhdGlibGUgTWV0YXNwbG9pdCkiCmVjaG8gIlNlcnZpY2UgICAgICA6
IGFwYWNoZS1jdGYuc2VydmljZSIKZWNobyAiU2VydmljZSB2dWxuIDogZXhjYWxpYnVyIgplY2hv
ICIiCmVjaG8gIuKchSBMYSBtYWNoaW5lIGVzdCBwcsOqdGUgcG91ciBsZSBDVEYgISIKZWNobyAi
PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09Igo=
'
CTF_NOM[5]="CTF5-knockingPorts"
CTF_DESC[5]="Ports et serveur de calcul"
CTF_B64[5]='
IyEvYmluL2Jhc2gKZXhwb3J0IERFQklBTl9GUk9OVEVORD1ub25pbnRlcmFjdGl2ZQoKIyBMZWN0
dXJlIGR1IG51bcOpcm8gKHN1cHBvcnRlIHN0ZGluIHBvdXIgY2xvbmFnZSBhdXRvbWF0aXPDqSkK
aWYgWyAtdCAwIF07IHRoZW4KICAgIHJlYWQgLXIgLXAgIkVudHJleiBsZSBudW3DqXJvIGRlIGwn
w6l0dWRpYW50ICgxIMOgIDM4KSA6ICIgTlVNCmVsc2UKICAgIHJlYWQgLXIgTlVNCmZpCgppZiAh
IFtbICIkTlVNIiA9fiBeWzAtOV0rJCBdXSB8fCAoKCBOVU0gPCAxIHx8IE5VTSA+IDM4ICkpOyB0
aGVuCiAgICBlY2hvICJOdW3DqXJvIGludmFsaWRlLiBWZXVpbGxleiBlbnRyZXIgdW4gbm9tYnJl
IGVudHJlIDEgZXQgMzguIgogICAgZXhpdCAxCmZpCgpOVU09JChwcmludGYgIiUwMmQiICIkTlVN
IikKSE9TVE5BTUU9IiQoaG9zdG5hbWUpIiAgICMgbm9tIHBvc8OpIHBhciBQcm94bW94IChyZW1p
cyDDoCBjaGFxdWUgZMOpbWFycmFnZSkKRkxBR19DVEYzPSJGTEFHe1BvcnRLbm9ja18kKGVjaG8g
LW4gIiROVU0iIHwgc2hhMjU2c3VtIHwgY3V0IC1jMS0xMil9IiAgICMgRklYRSBwYXIgw6lsw6h2
ZSAoZm9ybXVsZSBkJ29yaWdpbmUpIDogbGEgZmV1aWxsZSBkdSBwcm9mIHJlc3RlIHZhbGFibGUg
Y2hhcXVlIGFubsOpZQpGTEFHX0NBTEM9IkZMQUd7VERfQ2FsY3VsXyQoZWNobyAtbiAiJE5VTSIg
fCBzaGEyNTZzdW0gfCBjdXQgLWMxLTEyKX0iCgojIExlIGRyYXBlYXUgZHUgc2VydmV1ciBkZSBj
YWxjdWwgdml0IGRlc29ybWFpcyBkYW5zIHVuIEZJQ0hJRVIsIGV0IHBsdXMgZW4gZHVyCiMgZGFu
cyBsZSBjb2RlIGR1IHNlcnZldXIgOiB1biBlbGV2ZSBxdWkgbGlyYWl0IC91c3IvbG9jYWwvYmlu
L3NlcnZlcl9tYXRoX2ZsYWcuc2gKIyBsZSB0cm91dmFpdCBzYW5zIHJlc291ZHJlIGxlIGRlZmku
IEMnZXN0IGF1c3NpIGNlIHF1aSBsZSByZW5kIG9ic2VydmFibGUgOiBsYQojIHBhZ2UgQ2hhbGxl
bmdlIGNvbXB0ZSBsYSBQUkVNSUVSRSBsZWN0dXJlIGRlIGNlIGZpY2hpZXIgY29tbWUgdW5lIHJl
dXNzaXRlLgojIFBJRUdFIDogbmUgSkFNQUlTIHJlbGlyZSBjZSBmaWNoaWVyIGRlcHVpcyBjZSBz
Y3JpcHQsIHBhcyBtZW1lIHVuIGNhdCBkZQojIHZlcmlmaWNhdGlvbiDigJQgbGEgbGVjdHVyZSBm
ZXJhaXQgcGFzc2VyIGwnZWxldmUgcG91ciBnYWduYW50LiBMZXMgY29udHJvbGVzCiMgY2ktZGVz
c291cyBuZSByZWdhcmRlbnQgcXVlIGwnZXhpc3RlbmNlIGV0IGxhIHRhaWxsZSwgamFtYWlzIGxl
IGNvbnRlbnUuCmVjaG8gIiRGTEFHX0NBTEMiID4gL3Jvb3QvZmxhZ19jYWxjdWwudHh0CmNobW9k
IDYwMCAvcm9vdC9mbGFnX2NhbGN1bC50eHQKUE9SVFM9KDEyMzQ1IDY3ODkgMTU2OSA2OTE5IDE2
MTYgNTk5OSkKCiMgPT09IENyw6lhdGlvbiBkZSBsJ3V0aWxpc2F0ZXVyIGFkbWluID09PQp1c2Vy
YWRkIC1tIC1zIC9iaW4vYmFzaCBhZG1pbiB8fCB0cnVlCmVjaG8gImFkbWluOmFkbWluIiB8IGNo
cGFzc3dkCgojID09PSBGaXggRE5TIHRlbXBvcmFpcmUgKEFWQU5UIEFQVCkgPT09CiMgKDA0LzEw
LzIwMjYpIEROUyBsYWlzc8OpIMOgIGNlbHVpIHBvc8OpIHBhciBQcm94bW94IChxdWVzdGlvbiDC
qyBTZXJ2ZXVyIEROUyDCuyBkZSBjdGZfY3JlZXIuc2gpIDoKIyBmb3JjZXIgOC44LjguOC8xLjEu
MS4xIGNhc3NhaXQgYXB0IHN1ciBsZXMgcsOpc2VhdXggcXVpIGJsb3F1ZW50IGxlcyBETlMgcHVi
bGljcy4KCiMgPT09IEFQVCA6IE1BSiArIG91dGlscyA9PT0KaWYgISB7IGFwdCB1cGRhdGUgJiYg
YXB0IGluc3RhbGwgLXkgdGNwZHVtcCBpcHRhYmxlcyBuZXQtdG9vbHMgbmV0Y2F0LW9wZW5ic2Qg
c29jYXQ7IH07IHRoZW4KICAgIGVjaG8gIsOJY2hlYyBkZSBsJ2luc3RhbGxhdGlvbiBkZXMgcGFx
dWV0cy4iCiAgICBleGl0IDEKZmkKCiMgPT09IETDqXRlY3Rpb24gaW50ZXJmYWNlIHLDqXNlYXUg
PT09CklGQUNFX1JBVz0kKGlwIC1iciBsaW5rIHNob3cgfCBhd2sgJyQxICE9ICJsbyIgJiYgJDIg
PT0gIlVQIiB7cHJpbnQgJDE7IGV4aXR9JykKSUZBQ0U9JChlY2hvICIkSUZBQ0VfUkFXIiB8IGN1
dCAtZCdAJyAtZjEpCmlmIFsgLXogIiRJRkFDRSIgXTsgdGhlbgogICAgZWNobyAiQXVjdW5lIGlu
dGVyZmFjZSByw6lzZWF1IGTDqXRlY3TDqWUuIgogICAgZXhpdCAxCmZpCgplY2hvICJBZHJlc3Nl
IElQIGfDqXLDqWUgcGFyIFByb3htb3ggKHZpYSBwY3Qgc2V0KS4gQXVjdW4gY2hhbmdlbWVudCBy
w6lzZWF1IGRhbnMgbGUgY29udGVuZXVyLiIKZWNobyAiSW50ZXJmYWNlIGTDqXRlY3TDqWUgOiAk
SUZBQ0UiCgojID09PSBIb3N0bmFtZSA9PT0KIyAoMDUvMTAvMjAyNikgTm9tIGxhaXNzw6kgw6Ag
UHJveG1veCwgcXVpIGxlIHJlbWV0IMOgIGNoYXF1ZSBkw6ltYXJyYWdlLgoKIyA9PT0gaXB0YWJs
ZXMgOiB2ZXJyb3VpbGxhZ2UgaW5pdGlhbCBkdSBTU0ggPT09CmlmIGNvbW1hbmQgLXYgaXB0YWJs
ZXMgPi9kZXYvbnVsbCAyPiYxOyB0aGVuCiAgICBpcHRhYmxlcyAtRgogICAgaXB0YWJsZXMgLUEg
SU5QVVQgLXAgdGNwIC0tZHBvcnQgMjIgLWogRFJPUApmaQoKIyA9PT0gU2NyaXB0IGlwdGFibGVz
IGF1IGJvb3QgPT09Cm1rZGlyIC1wIC9ldGMvbmV0d29yay9pZi1wcmUtdXAuZApjYXQgPDwnRU9G
JyA+IC9ldGMvbmV0d29yay9pZi1wcmUtdXAuZC9pcHRhYmxlcwojIS9iaW4vc2gKaXB0YWJsZXMg
LUYKaXB0YWJsZXMgLUEgSU5QVVQgLXAgdGNwIC0tZHBvcnQgMjIgLWogRFJPUApFT0YKY2htb2Qg
K3ggL2V0Yy9uZXR3b3JrL2lmLXByZS11cC5kL2lwdGFibGVzCgojID09PSBTYXV2ZWdhcmRlIGFu
Y2llbiBrbm9jayBzaSBwcsOpc2VudCA9PT0KaWYgWyAtZiAvdXNyL2xvY2FsL2Jpbi9wb3J0a25v
Y2tkX2x4Yy5zaCBdOyB0aGVuCiAgICBjcCAtdiAvdXNyL2xvY2FsL2Jpbi9wb3J0a25vY2tkX2x4
Yy5zaCAvdXNyL2xvY2FsL2Jpbi9wb3J0a25vY2tkX2x4Yy5zaC5iYWsuJChkYXRlICslcykgfHwg
dHJ1ZQpmaQoKIyA9PT0gU2NyaXB0IGRlIGtub2NrIExYQyAodmVyc2lvbiB0b2zDqXJhbnRlIOKA
lCBpZGVudGlxdWUgw6AgVk0xMDAgZmluYWwpID09PQpjYXQgPiAvdXNyL2xvY2FsL2Jpbi9wb3J0
a25vY2tkX2x4Yy5zaCA8PCdFT0YnCiMhL2Jpbi9iYXNoCklGQUNFPSIkezE6LWV0aDB9IgpTRVFV
RU5DRT0oMTIzNDUgNjc4OSAxNTY5IDY5MTkgMTYxNiA1OTk5KQpMT0c9Ii90bXAva25vY2subG9n
IgoKIyBpbml0aWFsaXNhdGlvbgo+ICIkTE9HIgppcHRhYmxlcyAtRgppcHRhYmxlcyAtQSBJTlBV
VCAtcCB0Y3AgLS1kcG9ydCAyMiAtaiBEUk9QCgojIGNhcHR1cmUgU1lOcyBldCBlbnJlZ2lzdHJl
bWVudCAodG9sw6lyYW50IGF1IGJydWl0KQp0Y3BkdW1wIC1ubiAtbCAtaSAiJElGQUNFIiAndGNw
W3RjcGZsYWdzXSAmIHRjcC1zeW4gIT0gMCcgMj4vZGV2L251bGwgfCB3aGlsZSByZWFkIC1yIGxp
bmU7IGRvCiAgICBTUkM9JChlY2hvICIkbGluZSIgfCBhd2sgJ3twcmludCAkM30nIHwgY3V0IC1k
LiAtZjEtNCkKICAgIERTVFBPUlQ9JChlY2hvICIkbGluZSIgfCBncmVwIC1vUCAnPlxzK1xkK1wu
XGQrXC5cZCtcLlxkK1wuXEtcZCsnIHx8IHRydWUpCgogICAgaWYgW1sgLW4gIiRTUkMiICYmIC1u
ICIkRFNUUE9SVCIgXV07IHRoZW4KICAgICAgICBlY2hvICIkU1JDICREU1RQT1JUIiA+PiAiJExP
RyIKCiAgICAgICAgIyBmZW7DqnRyZSBkZXMgcG9ydHMgcsOpY2VudHMgcG91ciBjZXR0ZSBzb3Vy
Y2UgKDIwMCBsaWduZXMpCiAgICAgICAgUE9SVFNfU1JDPSQodGFpbCAtbiAyMDAgIiRMT0ciIHwg
YXdrIC12IHM9IiRTUkMiICckMT09cyB7cHJpbnRmICIlcyAiLCAkMn0nKQogICAgICAgIFJFTT0i
JFBPUlRTX1NSQyIKICAgICAgICBNQVRDSEVEPTEKCiAgICAgICAgZm9yIFdBTlQgaW4gIiR7U0VR
VUVOQ0VbQF19IjsgZG8KICAgICAgICAgICAgaWYgZWNobyAiJFJFTSIgfCBncmVwIC1xIC1FICIo
XnwgKSR7V0FOVH0oIHwkKSI7IHRoZW4KICAgICAgICAgICAgICAgICMgcmV0aXJlciBqdXNxdSfD
oCBsYSBwcmVtacOocmUgb2NjdXJyZW5jZSBpbmNsdXNlCiAgICAgICAgICAgICAgICBSRU09JChl
Y2hvICIkUkVNIiB8IHNlZCAtRSAicy9eKC4qXFxiJHtXQU5UfVxcYikvLyIpCiAgICAgICAgICAg
IGVsc2UKICAgICAgICAgICAgICAgIE1BVENIRUQ9MAogICAgICAgICAgICAgICAgYnJlYWsKICAg
ICAgICAgICAgZmkKICAgICAgICBkb25lCgogICAgICAgIGlmIFtbICIkTUFUQ0hFRCIgLWVxIDEg
XV07IHRoZW4KICAgICAgICAgICAgZWNobyAiIEtub2NrIGNvcnJlY3QgZGVwdWlzICRTUkMiCiAg
ICAgICAgICAgIGlwdGFibGVzIC1JIElOUFVUIC1zICIkU1JDIiAtcCB0Y3AgLS1kcG9ydCAyMiAt
aiBBQ0NFUFQKICAgICAgICAgICAgOiA+ICIkTE9HIgogICAgICAgIGZpCiAgICBmaQpkb25lCkVP
RgoKY2htb2QgK3ggL3Vzci9sb2NhbC9iaW4vcG9ydGtub2NrZF9seGMuc2gKCiMgPT09IFNlcnZp
Y2Ugc3lzdGVtZCBwb3VyIGtub2NrZCBMWEMgPT09CmNhdCA8PEVPRiA+IC9ldGMvc3lzdGVtZC9z
eXN0ZW0vcG9ydGtub2NrZF9seGMuc2VydmljZQpbVW5pdF0KRGVzY3JpcHRpb249UG9ydCBLbm9j
a2luZyBUQ1BEdW1wIExYQwpBZnRlcj1uZXR3b3JrLnRhcmdldAoKW1NlcnZpY2VdCkV4ZWNTdGFy
dD0vdXNyL2xvY2FsL2Jpbi9wb3J0a25vY2tkX2x4Yy5zaCAkSUZBQ0UKUmVzdGFydD1hbHdheXMK
UmVzdGFydFNlYz0yCgpbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKRU9GCgoj
ID09PSBTZXJ2ZXVyIG1hdGjDqW1hdGlxdWUgKGRldXhpw6htZSDDqXByZXV2ZSkgPT09CiMgKDA1
LzEwLzIwMjYpIHNvY2F0IGxhbmNlIHVuIHRyYWl0ZW1lbnQgcGFyIGNvbm5leGlvbi4gTCdhbmNp
ZW4gwqsgbmMgLWwgfCB3aGlsZSByZWFkIMK7IHBlcmRhaXQKIyBsZXMgcsOpcG9uc2VzIDogYXZl
YyDCqyBlY2hvIDE3IHwgbmMgSVAgNTQzMjEgwrssIG5jIHMnYXJyw6p0YWl0IGF2YW50IHF1ZSBs
YSByw6lwb25zZSBzb2l0IMOpY3JpdGUuCmNhdCA+IC91c3IvbG9jYWwvYmluL3NlcnZlcl9tYXRo
X2ZsYWcuc2ggPDwnRU9GJwojIS9iaW4vYmFzaAojIFBldGl0IHNlcnZldXIgVENQICJURCBjYWxj
dWwiIDogcsOpcG9uZCDDoCBxdWVscXVlcyBjb21tYW5kZXMgZXQgZMOpbGl2cmUgRkxBRyBzaSBs
YSByw6lwb25zZSBlc3QgY29ycmVjdGUuClBPUlQ9NTQzMjEKIyBQYXMgZGUgZHJhcGVhdSBpY2kg
OiBpbCBlc3QgbHUgZGFucyAvcm9vdC9mbGFnX2NhbGN1bC50eHQsIGV0IFVOSVFVRU1FTlQgcXVh
bmQKIyBsYSByZXBvbnNlIGVzdCBqdXN0ZSAodm9pciBzZXJ2ZXJfbWF0aF9zZXNzaW9uLnNoKS4K
CiMgT3DDqXJhdGlvbiB0aXLDqWUgYXUgZMOpbWFycmFnZSBkdSBzZXJ2aWNlLCBsYSBtw6ptZSBw
b3VyIHRvdXRlcyBsZXMgY29ubmV4aW9ucwpPUF9MSVNUPSgiKyIgIi0iICIqIikKbjE9JCgoUkFO
RE9NICUgMTAgKyAxKSkKbjI9JCgoUkFORE9NICUgMTAgKyAxKSkKb3A9IiR7T1BfTElTVFtSQU5E
T00gJSAkeyNPUF9MSVNUW0BdfV19IgpjYXNlICIkb3AiIGluCiAgICAiKyIpIHJlc3VsdD0kKChu
MSArIG4yKSkgOzsKICAgICItIikgcmVzdWx0PSQoKG4xIC0gbjIpKSA7OwogICAgIioiKSByZXN1
bHQ9JCgobjEgKiBuMikpIDs7CmVzYWMKCiMgam91cm5hbGlzZXIgbCdvcMOpcmF0aW9uIHBvdXIg
bCdlbnNlaWduYW50L2RlYnVnCmVjaG8gIltDVEZdIFNlcnZldXIgcHLDqnQgc3VyIHBvcnQgJFBP
UlQgOiAkbjEgJG9wICRuMiA9ICRyZXN1bHQiID4gL3RtcC9vcGVyYXRpb24ubG9nCgpleHBvcnQg
bjEgbjIgb3AgcmVzdWx0CmV4ZWMgc29jYXQgLXQgMiBUQ1AtTElTVEVOOiRQT1JULHJldXNlYWRk
cixmb3JrIEVYRUM6L3Vzci9sb2NhbC9iaW4vc2VydmVyX21hdGhfc2Vzc2lvbi5zaApFT0YKCiMg
VW5lIGNvbm5leGlvbiA9IHVuZSBzZXNzaW9uIDogcsOpcG9uZCDDoCBjaGFxdWUgbGlnbmUsIGZl
cm1lIGFwcsOocyBsYSByw6lwb25zZSBhdSBjYWxjdWwuCmNhdCA+IC91c3IvbG9jYWwvYmluL3Nl
cnZlcl9tYXRoX3Nlc3Npb24uc2ggPDwnRU9GJwojIS9iaW4vYmFzaAp3aGlsZSByZWFkIC1yIC10
IDEyMCBpbnB1dCB8fCBbWyAtbiAiJGlucHV0IiBdXTsgZG8gICAjIGF1c3NpIHVuZSBkZXJuacOo
cmUgbGlnbmUgc2FucyByZXRvdXIKICAgICMgc2FuaXRpemUgaW5wdXQgKHN1cHByaW1lIENSLCBl
c3BhY2VzIGVuIHTDqnRlL2ZpbikKICAgIGlucHV0PSIkKHByaW50ZiAnJXMnICIkaW5wdXQiIHwg
dHIgLWQgJ1xyJyB8IHNlZCAtZSAncy9eW1s6c3BhY2U6XV0qLy8nIC1lICdzL1tbOnNwYWNlOl1d
KiQvLycpIgogICAgY2FzZSAiJGlucHV0IiBpbgogICAgICAgICJNZXJjaSEiICkgZWNobyAiQmll
bnZlbnVlLiBQb3VyIG9idGVuaXIgbGVzIMOpbMOpbWVudHMsIGVudm95ZXogJ29wJywgJ24xJyBv
dSAnbjInLiIgOzsKICAgICAgICAib3AiICkgICAgIGVjaG8gIiRvcCIgOzsKICAgICAgICAibjEi
ICkgICAgIGVjaG8gIiRuMSIgOzsKICAgICAgICAibjIiICkgICAgIGVjaG8gIiRuMiIgOzsKICAg
ICAgICAqKQogICAgICAgICAgICAjIGFjY2VwdGVyIGxhIHLDqXBvbnNlIG51bcOpcmlxdWUgZXhh
Y3RlIChzdXBwb3J0ZSBzaWduZSkKICAgICAgICAgICAgaWYgW1sgIiRpbnB1dCIgPX4gXi0/WzAt
OV0rJCBdXSAmJiAoKCAxMCMke2lucHV0Iy19ICogJHtpbnB1dCUlWzAtOV0qfTEgPT0gcmVzdWx0
ICkpOyB0aGVuCiAgICAgICAgICAgICAgICAjIExlY3R1cmUgZHUgZHJhcGVhdSBVTklRVUVNRU5U
IGljaSA6IG5pIGF1IGRlbWFycmFnZSBkdQogICAgICAgICAgICAgICAgIyBzZXJ2aWNlLCBuaSBh
IGNoYXF1ZSBjb25uZXhpb24uIEMnZXN0IGNldHRlIGxlY3R1cmUsIGV0IGVsbGUKICAgICAgICAg
ICAgICAgICMgc2V1bGUsIHF1aSBtYXJxdWUgbGEgcmV1c3NpdGUgZGUgbCdlbGV2ZS4KICAgICAg
ICAgICAgICAgIGNhdCAvcm9vdC9mbGFnX2NhbGN1bC50eHQKICAgICAgICAgICAgZWxzZQogICAg
ICAgICAgICAgICAgZWNobyAiUsOpcG9uc2UgaW5jb3JyZWN0ZS4iCiAgICAgICAgICAgIGZpCiAg
ICAgICAgICAgIGV4aXQgMCA7OwogICAgZXNhYwpkb25lCkVPRgoKIyBMZSBkcmFwZWF1IG4nZXN0
IHBsdXMgaW5zY3JpdCBkYW5zIGxlIGNvZGUgZHUgc2VydmV1ci4gT24gY29udHJvbGUgc2V1bGVt
ZW50CiMgcXVlIGxlIGZpY2hpZXIgZXhpc3RlIGV0IG4nZXN0IHBhcyB2aWRlIDogbGUgTElSRSBs
ZSBmZXJhaXQgY29tcHRlciBjb21tZQojIHRyb3V2ZSBwYXIgbCdlbGV2ZS4gRXQgb24gdmVyaWZp
ZSBxdSdpbCBuZSByZXN0ZSBhdWN1bmUgdHJhY2UgZW4gY2xhaXIuClsgLXMgL3Jvb3QvZmxhZ19j
YWxjdWwudHh0IF0gfHwgeyBlY2hvICJGaWNoaWVyIGR1IGRyYXBlYXUgZGUgY2FsY3VsIGFic2Vu
dCBvdSB2aWRlLiI7IGV4aXQgMTsgfQpncmVwIC1xRiAiJEZMQUdfQ0FMQyIgL3Vzci9sb2NhbC9i
aW4vc2VydmVyX21hdGhfZmxhZy5zaCAvdXNyL2xvY2FsL2Jpbi9zZXJ2ZXJfbWF0aF9zZXNzaW9u
LnNoIFwKICAgICYmIHsgZWNobyAiTGUgZHJhcGVhdSBkZSBjYWxjdWwgYXBwYXJhaXQgZW4gY2xh
aXIgZGFucyBsZSBjb2RlIGR1IHNlcnZldXIuIjsgZXhpdCAxOyB9CmNobW9kIDcwMCAvdXNyL2xv
Y2FsL2Jpbi9zZXJ2ZXJfbWF0aF9mbGFnLnNoIC91c3IvbG9jYWwvYmluL3NlcnZlcl9tYXRoX3Nl
c3Npb24uc2gKCiMgPT09IFNlcnZpY2Ugc3lzdGVtZCBwb3VyIGxlIHNlcnZldXIgbWF0aCA9PT0K
Y2F0IDw8J0VPRicgPiAvZXRjL3N5c3RlbWQvc3lzdGVtL3NlcnZlcl9tYXRoX2ZsYWcuc2Vydmlj
ZQpbVW5pdF0KRGVzY3JpcHRpb249U2VydmV1ciBUQ1AgVEQgRmxhZyBDYWxjdWwgZmlnw6kKQWZ0
ZXI9bmV0d29yay50YXJnZXQKCltTZXJ2aWNlXQpFeGVjU3RhcnQ9L3Vzci9sb2NhbC9iaW4vc2Vy
dmVyX21hdGhfZmxhZy5zaApSZXN0YXJ0PWFsd2F5cwpSZXN0YXJ0U2VjPTIKCltJbnN0YWxsXQpX
YW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldApFT0YKCiMgPT09IEFjdGl2ZXIgLyBkw6ltYXJyZXIg
bGVzIHNlcnZpY2VzID09PQpzeXN0ZW1jdGwgZGFlbW9uLXJlZXhlYyB8fCB0cnVlCnN5c3RlbWN0
bCBkYWVtb24tcmVsb2FkCnN5c3RlbWN0bCBlbmFibGUgcG9ydGtub2NrZF9seGMuc2VydmljZQpz
eXN0ZW1jdGwgZW5hYmxlIHNlcnZlcl9tYXRoX2ZsYWcuc2VydmljZQpzeXN0ZW1jdGwgcmVzdGFy
dCBwb3J0a25vY2tkX2x4Yy5zZXJ2aWNlIHx8IHRydWUKc3lzdGVtY3RsIHJlc3RhcnQgc2VydmVy
X21hdGhfZmxhZy5zZXJ2aWNlIHx8IHRydWUKCiMgPT09IENyw6lhdGlvbiBkdSBmbGFnIFNTSCAo
w6lwcmV1dmUga25vY2spID09PQpta2RpciAtcCAvaG9tZS9hZG1pbgplY2hvICIkRkxBR19DVEYz
IiA+IC9ob21lL2FkbWluL2ZsYWcudHh0CmNobW9kIDQwMCAvaG9tZS9hZG1pbi9mbGFnLnR4dApj
aG93biBhZG1pbjphZG1pbiAvaG9tZS9hZG1pbi9mbGFnLnR4dAoKIyA9PT0gUHJvdGVjdGlvbiBk
ZSBs4oCZaGlzdG9yaXF1ZSA9PT0KZWNobyAiZXhwb3J0IEhJU1RGSUxFPS9kZXYvbnVsbCIgPj4g
L2hvbWUvYWRtaW4vLmJhc2hyYwpjaG93biBhZG1pbjphZG1pbiAvaG9tZS9hZG1pbi8uYmFzaHJj
IHx8IHRydWUKCiMgPT09IFN1aXZpIENTViA9PT0KbWtkaXIgLXAgL29wdC9jdGZfdHJhY2tpbmcK
ZWNobyAiJE5VTSwkSE9TVE5BTUUsJEZMQUdfQ1RGMywkRkxBR19DQUxDIiA+PiAvb3B0L2N0Zl90
cmFja2luZy9mbGFncy5jc3YKCiMgPT09IFbDqXJpZmljYXRpb24gZGVzIHNlcnZpY2VzID09PQpz
bGVlcCAyCmZvciBzdmMgaW4gcG9ydGtub2NrZF9seGMgc2VydmVyX21hdGhfZmxhZzsgZG8KICAg
IGlmICEgc3lzdGVtY3RsIGlzLWFjdGl2ZSAtLXF1aWV0ICIkc3ZjIjsgdGhlbgogICAgICAgIGVj
aG8gIlNlcnZpY2UgJHN2YyBpbmFjdGlmLiIKICAgICAgICBleGl0IDEKICAgIGZpCmRvbmUKCiMg
PT09IFLDqXN1bcOpID09PQplY2hvCmVjaG8gIuKchSBWTSBwcsOqdGUgcG91ciDDqXR1ZGlhbnQg
JE5VTSIKZWNobyAi8J+UkiBQb3J0LWtub2NraW5nIGFjdGlmIDogJHtQT1JUU1sqXX0iCmVjaG8g
IvCfk6EgU2VydmV1ciBUQ1AgZmlnw6kgOiBwb3J0IDU0MzIxIChjb21tYW5kZSAnb3AnLCduMScs
J24yJyBwb3VyIHLDqWN1cMOpcmVyIGxlcyDDqWzDqW1lbnRzKSIKZWNobyAi8J+PgSBGTEFHIENU
RjMgOiAkRkxBR19DVEYzIgplY2hvICLwn4+BIEZMQUcgVEQgICA6ICRGTEFHX0NBTEMiCmVjaG8g
IvCfk4IgL3RtcC9vcGVyYXRpb24ubG9nIGNvbnRpZW50IGwnb3DDqXJhdGlvbiBmaWfDqWUiCgoK
ZXhpdCAwCg==
'



###################################################################
#                      SECTION 15 : PROGRAMME                     #
###################################################################

main() {
    lire_options "$@"
    # Lu depuis un tube (« curl … | bash ») : le menu prendrait les lignes suivantes
    # du script pour des réponses.
    if [[ ! -t 0 && ! -f "$0" ]]; then
        ko "Ce script se lance depuis un fichier : le télécharger, puis « bash ctf_creer.sh »."
        exit 1
    fi
    verifier_prerequis
    trap nettoyer EXIT
    trap interrompu INT TERM HUP
    detecter_infra
    chercher_image
    choisir_ctf
    inventorier_conteneurs
    choisir_action_autres
    if [[ "$ACTION_1B" != "supprimer_seul" ]]; then
        demander_parametres
        choisir_etudiants
        demander_progression
    fi
    afficher_resume
    confirmer
    if (( ${#A_CREER[@]} > 0 )); then
        preparer_creation || exit 1
    fi
    appliquer_choix_1b
    (( ${#A_CREER[@]} > 0 )) && creer_tous
    if [[ "$PROGRESSION" == "oui" ]]; then
        prog_installer || PROG_ERREUR=1
    fi
    afficher_bilan
}

main "$@"
