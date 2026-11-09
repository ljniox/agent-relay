#!/usr/bin/env python3
"""agent-relay : canal de discussion chiffré entre agents en ligne de commande.

Même protocole que ClipRelay (https://clip.niox.ovh) : un canal ntfy.sh dont le
nom et la clé AES-GCM vivent dans un fragment « uid!clé ». Un humain peut donc
suivre la conversation en ouvrant https://clip.niox.ovh/#uid!clé, et un agent
rejoint le canal avec un code à usage unique de 6 caractères (OTP), sans que
le secret ne transite jamais en clair.

  python relay.py nouveau               crée un canal (côté qui invite)
  python relay.py code                  publie un code à 6 caractères, valable 15 min
  python relay.py rejoindre [CODE]      rejoint un canal avec le code (demandé si absent)
  python relay.py envoyer "texte"       envoie un message (ou lit l'entrée standard)
  python relay.py fichier CHEMIN        envoie un fichier (14 Mo max, conservé ~3 h)
  python relay.py lire [--depuis 12h]   affiche les messages du canal
  python relay.py attendre [--delai 900]  attend le prochain message d'un autre participant
  python relay.py recuperer ID [DOSSIER]  télécharge et déchiffre un fichier reçu
  python relay.py lien                  affiche le lien de la page (secret : ne pas diffuser)
  python relay.py etat                  nom, canal (abrégé), dernier message lu

Option commune : --nom NOM (étiquette de l'émetteur, ASCII), --profil P (plusieurs canaux).
Dépendance unique : le paquet « cryptography » (python -m pip install cryptography).
"""
import argparse
import base64
import getpass
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # message clair plutôt qu'une trace Python
    sys.exit("Il manque le paquet « cryptography » : python -m pip install cryptography")

NTFY = "https://ntfy.sh/"
PAGE = "https://clip.niox.ovh/"
UA = {"User-Agent": "agent-relay/1.0"}
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
SEL_CODE = b"cliprelay-pair-v1"

for flux in (sys.stdout, sys.stderr):  # console Windows : forcer l'UTF-8
    try:
        flux.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ---------- base64 url sans bourrage (identique à la page) ----------
def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------- configuration locale ----------
def dossier_conf() -> Path:
    base = os.environ.get("AGENT_RELAY_HOME")
    return Path(base) if base else Path.home() / ".agent-relay"


def fichier_conf(profil: str) -> Path:
    return dossier_conf() / f"{profil}.json"


def charger(profil: str) -> dict:
    f = fichier_conf(profil)
    if not f.exists():
        sys.exit(f"Aucun canal pour le profil « {profil} » : lancer « relay.py rejoindre CODE » ou « relay.py nouveau ».")
    return json.loads(f.read_text(encoding="utf-8"))


def sauver(profil: str, conf: dict) -> None:
    d = dossier_conf()
    d.mkdir(parents=True, exist_ok=True)
    f = fichier_conf(profil)
    f.write_text(json.dumps(conf, ensure_ascii=False, indent=1), encoding="utf-8")
    try:
        os.chmod(d, 0o700)
        os.chmod(f, 0o600)
    except OSError:
        pass  # Windows : le dossier du profil utilisateur est déjà privé


def canal(conf: dict):
    uid, cle = conf["frag"].split("!")
    k = b64d(cle)
    if len(k) != 32:
        sys.exit("Clé de canal invalide.")
    return uid, AESGCM(k)


# ---------- chiffrement : IV de 12 octets préfixé ----------
def chiffrer(aes: AESGCM, donnees: bytes) -> bytes:
    iv = secrets.token_bytes(12)
    return iv + aes.encrypt(iv, donnees, None)


def dechiffrer(aes: AESGCM, brut: bytes) -> bytes:
    return aes.decrypt(brut[:12], brut[12:], None)


def enc_json(aes, obj) -> str:
    return b64e(chiffrer(aes, json.dumps(obj, ensure_ascii=False).encode()))


def dec_json(aes, s: str):
    return json.loads(dechiffrer(aes, b64d(s)).decode())


# ---------- HTTP ----------
def http(url, data=None, methode=None, entetes=None, delai=60) -> bytes:
    req = urllib.request.Request(url, data=data, method=methode, headers={**UA, **(entetes or {})})
    try:
        with urllib.request.urlopen(req, timeout=delai) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        sys.exit(f"ntfy a répondu HTTP {e.code} : {e.read()[:200].decode(errors='replace')}")
    except urllib.error.URLError as e:
        sys.exit(f"ntfy injoignable : {e.reason}")


def sondage(topic: str, depuis: str):
    brut = http(f"{NTFY}{topic}/json?poll=1&since={depuis}").decode()
    for ligne in brut.splitlines():
        try:
            n = json.loads(ligne)
        except ValueError:
            continue
        if n.get("event") == "message":
            yield n


# ---------- code à usage unique (même dérivation que la page) ----------
def cles_code(code: str):
    norme = "".join(c for c in code.upper() if c.isalnum())
    import hashlib
    bits = hashlib.pbkdf2_hmac("sha256", norme.encode(), SEL_CODE, 120000, 64)
    return "clippair-" + b64e(bits[:15]), AESGCM(bits[32:64])


# ---------- messages ----------
def decoder(aes, n: dict):
    """Rend (horodatage, émetteur, type, contenu) ou None si le message n'est pas lisible."""
    try:
        p = json.loads(n.get("message", ""))
    except ValueError:
        return None
    if not isinstance(p, dict) or p.get("v") != 1:
        return None
    try:
        if p.get("t") == "text":
            return n["time"], p.get("dev", "?"), "texte", dec_json(aes, p["data"])["text"]
        if p.get("t") == "file" and n.get("attachment"):
            meta = dec_json(aes, p["meta"])
            return n["time"], p.get("dev", "?"), "fichier", f"{meta['name']} ({meta['size']} o) — id {n['id']}"
    except Exception:
        return None
    return None


def afficher(n, d, fmt_json=False):
    ts, dev, typ, contenu = d
    if fmt_json:
        print(json.dumps({"id": n["id"], "heure": ts, "de": dev, "type": typ, "contenu": contenu}, ensure_ascii=False))
    else:
        h = time.strftime("%d/%m %H:%M", time.localtime(ts))
        print(f"--- {h} · {dev} · {typ} · {n['id']}\n{contenu}\n")


# ---------- commandes ----------
def cmd_nouveau(a):
    if fichier_conf(a.profil).exists() and not a.force:
        sys.exit(f"Le profil « {a.profil} » a déjà un canal (--force pour le remplacer).")
    frag = b64e(secrets.token_bytes(16)) + "!" + b64e(secrets.token_bytes(32))
    sauver(a.profil, {"frag": frag, "nom": a.nom or "agent", "vu": int(time.time()) - 5})
    print(f"Canal créé (profil « {a.profil} »). Lancer « relay.py code » pour inviter un autre agent.")


def cmd_code(a):
    conf = charger(a.profil)
    code = "".join(ALPHABET[b % 32] for b in secrets.token_bytes(6))
    topic, aes = cles_code(code)
    charge = json.dumps({"frag": conf["frag"], "exp": int(time.time() * 1000) + 15 * 60 * 1000}).encode()
    http(NTFY + topic, data=b64e(chiffrer(aes, charge)).encode(), methode="POST")
    print(f"Code : {code[:3]} {code[3:]}   (valable 15 min, à saisir avec « relay.py rejoindre »)")


def cmd_rejoindre(a):
    code = a.code or getpass.getpass("Code à 6 caractères : ")
    if len("".join(c for c in code if c.isalnum())) < 6:
        sys.exit("Le code fait 6 caractères.")
    topic, aes = cles_code(code)
    for n in reversed(list(sondage(topic, "1h"))):  # le plus récent d'abord
        try:
            obj = json.loads(dechiffrer(aes, b64d(n["message"])).decode())
        except Exception:
            continue
        if obj.get("frag") and obj.get("exp", 0) > time.time() * 1000:
            ancien = fichier_conf(a.profil)
            nom = a.nom or (json.loads(ancien.read_text(encoding="utf-8")).get("nom") if ancien.exists() else None) or "agent"
            sauver(a.profil, {"frag": obj["frag"], "nom": nom, "vu": int(time.time()) - 5})
            print(f"Canal rejoint (profil « {a.profil} », nom « {nom} »).")
            return
    sys.exit("Code introuvable ou expiré : en demander un nouveau.")


def nom_emetteur(a, conf):
    nom = a.nom or conf.get("nom") or "agent"
    if not nom.isascii():
        sys.exit("Le nom d'émetteur doit être en ASCII (il voyage dans un en-tête HTTP).")
    return nom


def cmd_envoyer(a):
    conf = charger(a.profil)
    uid, aes = canal(conf)
    texte = " ".join(a.texte) if a.texte else sys.stdin.read()
    if not texte.strip():
        sys.exit("Message vide.")
    corps = json.dumps({"v": 1, "t": "text", "dev": nom_emetteur(a, conf), "data": enc_json(aes, {"text": texte})})
    http(NTFY + "clip-" + uid, data=corps.encode(), methode="POST")
    print("Envoyé.")


def cmd_fichier(a):
    conf = charger(a.profil)
    uid, aes = canal(conf)
    p = Path(a.chemin)
    donnees = p.read_bytes()
    if len(donnees) > 14 * 1024 * 1024:
        sys.exit("Fichier trop lourd (14 Mo max).")
    import mimetypes
    meta = enc_json(aes, {"name": p.name, "mime": mimetypes.guess_type(p.name)[0] or "application/octet-stream", "size": len(donnees)})
    msg = json.dumps({"v": 1, "t": "file", "dev": nom_emetteur(a, conf), "meta": meta})
    http(NTFY + "clip-" + uid, data=chiffrer(aes, donnees), methode="PUT",
         entetes={"Filename": "blob.bin", "X-Message": msg}, delai=300)
    print(f"Fichier envoyé : {p.name}")


def cmd_lire(a):
    conf = charger(a.profil)
    uid, aes = canal(conf)
    dernier = conf.get("vu", 0)
    for n in sondage("clip-" + uid, a.depuis):
        d = decoder(aes, n)
        if d:
            afficher(n, d, a.json)
            dernier = max(dernier, n["time"])
    conf["vu"] = dernier
    sauver(a.profil, conf)


def cmd_attendre(a):
    conf = charger(a.profil)
    uid, aes = canal(conf)
    moi = nom_emetteur(a, conf)
    vu = conf.get("vu") or int(time.time())
    fin = time.time() + a.delai
    while time.time() < fin:
        nouveaux = []
        for n in sondage("clip-" + uid, str(vu)):
            d = decoder(aes, n)
            if d and n["time"] > conf.get("vu", 0) and d[1] != moi:
                nouveaux.append((n, d))
        if nouveaux:
            for n, d in nouveaux:
                afficher(n, d, a.json)
            conf["vu"] = max(n["time"] for n, _ in nouveaux)
            sauver(a.profil, conf)
            return
        time.sleep(a.pas)
    print("(aucun nouveau message)")
    sys.exit(2)


def cmd_recuperer(a):
    conf = charger(a.profil)
    uid, aes = canal(conf)
    for n in sondage("clip-" + uid, "12h"):
        if n["id"] != a.id:
            continue
        p = json.loads(n["message"])
        meta = dec_json(aes, p["meta"])
        donnees = dechiffrer(aes, http(n["attachment"]["url"], delai=300))
        cible = Path(a.dossier) / Path(meta["name"]).name  # jamais de chemin imposé par l'émetteur
        cible.parent.mkdir(parents=True, exist_ok=True)
        cible.write_bytes(donnees)
        print(f"Enregistré : {cible}")
        return
    sys.exit("Message introuvable (les fichiers expirent après ~3 h).")


def cmd_lien(a):
    print(PAGE + "#" + charger(a.profil)["frag"])
    print("Ce lien donne accès au canal : ne le publiez nulle part.", file=sys.stderr)


def cmd_etat(a):
    conf = charger(a.profil)
    uid, _ = canal(conf)
    vu = conf.get("vu", 0)
    print(f"profil {a.profil} · nom {conf.get('nom')} · canal clip-{uid[:6]}… · dernier lu "
          + (time.strftime('%d/%m %H:%M', time.localtime(vu)) if vu else "jamais"))


def main():
    ap = argparse.ArgumentParser(description="Canal chiffré entre agents (protocole ClipRelay).")
    ap.add_argument("--profil", default="defaut")
    ap.add_argument("--nom", help="étiquette de l'émetteur (ASCII)")
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("nouveau"); s.add_argument("--force", action="store_true"); s.set_defaults(f=cmd_nouveau)
    sp.add_parser("code").set_defaults(f=cmd_code)
    s = sp.add_parser("rejoindre"); s.add_argument("code", nargs="?"); s.set_defaults(f=cmd_rejoindre)
    s = sp.add_parser("envoyer"); s.add_argument("texte", nargs="*"); s.set_defaults(f=cmd_envoyer)
    s = sp.add_parser("fichier"); s.add_argument("chemin"); s.set_defaults(f=cmd_fichier)
    s = sp.add_parser("lire"); s.add_argument("--depuis", default="12h"); s.add_argument("--json", action="store_true"); s.set_defaults(f=cmd_lire)
    s = sp.add_parser("attendre"); s.add_argument("--delai", type=int, default=900); s.add_argument("--pas", type=int, default=10)
    s.add_argument("--json", action="store_true"); s.set_defaults(f=cmd_attendre)
    s = sp.add_parser("recuperer"); s.add_argument("id"); s.add_argument("dossier", nargs="?", default="."); s.set_defaults(f=cmd_recuperer)
    sp.add_parser("lien").set_defaults(f=cmd_lien)
    sp.add_parser("etat").set_defaults(f=cmd_etat)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
