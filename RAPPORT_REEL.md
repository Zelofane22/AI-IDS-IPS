# Rapport — PCAP réel CIC-IDS2017 et réentraînement sur features NFStream

Toutes les valeurs ci-dessous proviennent de commandes réellement exécutées sur cette machine
(`data/cic/*.stats.json`, `data/models/train_report.json`, `results/demo_extract_eval.json`,
`tests/smoke.sh`). Aucun chiffre n'a été inventé.

## 1. Problème corrigé

Le modèle précédent était entraîné sur des features **CICFlowMeter** (CSV CIC-IDS2017) mais
appliqué à des features **NFStream** (`flow-extractor`). Mêmes noms de colonnes, calculs différents
(timeouts, découpage des flux, sens). Sur la PCAP synthétique, l'IA sortait 0 suspect / 11 et les
vues « IA seule » et « hybride » restaient vides. Baisser le seuil a été écarté : ce serait régler
le modèle sur la démo.

Correction : le modèle est maintenant entraîné sur des flux **NFStream extraits du vrai PCAP du
vendredi**, avec le même `extract.py` et les mêmes timeouts que la prédiction. Les étiquettes
CIC-IDS2017 sont reportées sur ces flux par jointure sur des clés réelles.

## 2. Données

- Source : miroir Hugging Face non officiel `bencorn/CICIDS2017`, révision
  `811c007f08d693a8a8b4226c197c138391806ce6` (même miroir que les CSV),
  fichier `pcaps/Friday-WorkingHours.pcap` (pcapng), 8 839 309 056 octets.
- SHA-256 : `beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0`. Identique à
  l'empreinte LFS publiée par le miroir, mais non validé contre une empreinte UNB officielle.
- Téléchargé une seule fois, sur demande explicite du porteur du projet. Rangé dans
  `data/cic/raw/pcap/`, ignoré par git, jamais commité.

## 3. Chaîne de construction (`tools/build_real_dataset.sh`)

1. **NFStream sur toute la journée** (image `flow-extractor`, mêmes timeouts 120 s / 1800 s) :
   501 096 flux.
2. **Étiquetage** (`tools/label_nfstream_flows.py`) :
   - clé = 5-tuple non orienté (IP/port A, IP/port B, protocole) ;
   - temps = début du flux CIC (minute, heure locale ADT = UTC−3, horloge 12 h sans AM/PM),
     qui doit tomber dans l'intervalle NFStream ± 60 s ;
   - fuseau vérifié : le premier paquet du PCAP (11:59:39 UTC) correspond à 8:59 dans les CSV ;
     sur un test de 40 min, 99 % des flux trouvent une correspondance.

   | Étape | Flux |
   |---|---:|
   | NFStream (journée) | 501 096 |
   | Exclus (fenêtres de la démo) | 8 425 |
   | Sans correspondance CIC (écartés) | 1 027 |
   | Mixtes BENIGN + une attaque → attaque | 24 691 |
   | Conflits entre attaques (écartés) | 0 |
   | Étiquetés | 491 644 |
   | Après échantillonnage 1/4 (ordre temporel) | 122 911 |

   Répartition finale : BENIGN 68 505, PortScan 39 197, DDoS 14 903, Bot 306.

   **Règle « mixte ».** Sur la journée complète, avant exclusion des fenêtres de démo, 25 503 des
   26 212 flux mixtes sont des connexions LOIC
   `172.16.0.1 → 192.168.10.50:80`. CICFlowMeter découpe la connexion au FIN et étiquette le
   fragment de fermeture BENIGN : c'est un artefact connu de CIC-IDS2017 (Engelen et al., 2021).
   Ces flux NFStream contiennent bien le trafic d'attaque. Ils sont étiquetés avec l'attaque
   (`--mixed-policy attack`) et comptés à part ; `--mixed-policy drop` permet de les écarter.
3. **Extrait de démo réel** (`tools/slice_pcap.py`, bibliothèque standard uniquement) :
   `data/pcaps/cic_friday_extract.pcap`, 33 Mo, 56 517 paquets, 6 985 flux NFStream.

   | Empreinte de l'extrait | Valeur |
   |---|---|
   | SHA-256 | `5120fb2f88e3c237d4c6c2532676cae0a567c56c23438e0451294d86d0edcba6` |
   | Taille | 33 278 413 octets |
   | Paquets | 56 517 (libpcap, linktype 1 Ethernet) |
   | Premier / dernier paquet (UTC) | 2017-07-07 13:36:00.145 / 19:00:19.979 |

   Le découpage est déterministe : un nouveau découpage depuis le PCAP complet redonne le même
   SHA-256 (vérifié, 55 s).

   | Fenêtre (heure locale) | UTC | Attaque |
   |---|---|---|
   | 10:36:00–10:38:00 | 13:36:00–13:38:00 | Bot (ARES) |
   | 15:08:00–15:08:30 | 18:08:00–18:08:30 | PortScan |
   | 16:00:00–16:00:20 | 19:00:00–19:00:20 | DDoS (LOIC) |

   Les flux qui chevauchent ces fenêtres sont **exclus de l'entraînement**.

## 4. Évaluation du modèle (split temporel 75/25, seuil 0,5)

| | Valeur |
|---|---:|
| Train / test | 92 183 / 30 728 |
| Composition train | BENIGN 54 685, PortScan 37 192, Bot 306 |
| Composition test | DDoS 14 903, BENIGN 13 820, PortScan 2 005 |
| Matrice (tn / fp / fn / tp) | 13 742 / 78 / 10 177 / 6 731 |
| Précision | 0,989 |
| Rappel | 0,398 |
| FPR | 0,0056 |
| ROC-AUC / PR-AUC | 0,990 / 0,988 |
| RF sans `dst_port` ni protocole : rappel / AUC | 0,346 / 0,989 |

Source des chiffres : `results/nfstream_temporal.json` (log : `results/nfstream_temporal.log`,
cohérence vérifiée par `python3 tests/check_results.py`).

*Correction (audit) :* la première version publiait une composition (BENIGN 13 820) et une
matrice (13 803 négatifs) incohérentes. Cause : un bug de parsing des horodatages dans
`train.py` transformait 106 horodatages sans fraction de seconde en `NaT`, et le split temporel
les plaçait dans le test. Bug corrigé (commit séparé, test `tests/test_train_timestamps.py`).
Le tableau ci-dessus vient du split corrigé. Avant correction : matrice
13 730 / 73 / 10 418 / 6 507, rappel 0,384, FPR 0,0053, précision 0,989, ROC-AUC 0,990,
RF sans port 0,363 / 0,990. Le modèle déployé (`--final-fit all`) est identique avant et après :
les résultats de la section 5 ne changent pas. Détail : `RAPPORT_AUDIT.md`.

Avec des horodatages NFStream à la milliseconde, le DDoS (à partir de 18:56 UTC) tombe
**entièrement** dans le test. Ce split temporel est donc, de fait, un test **zero-day DDoS** :
rappel 0,40. C'est cohérent avec l'expérience e4 de `RAPPORT_POC.md` (0,44). L'ancien 0,998
mesurait un DDoS déjà vu à l'entraînement : les deux chiffres ne sont pas comparables.

**Modèle déployé.** Après cette évaluation, le modèle est réentraîné sur les 122 911 lignes
(`--final-fit all`). Les métriques ci-dessus restent celles du split. Les fenêtres de la démo
restent exclues, donc l'extrait reste du trafic jamais vu par le modèle.

## 5. Résultat sur l'extrait réel (`tools/eval_real_demo.sh`)

Les flux de l'extrait sont étiquetés par la même jointure CIC : 6 695 étiquetés, 301 sans
correspondance. La part signalée est mesurée pour chaque famille. Côté Suricata, un flux compte
comme détecté s'il partage sa 5-tuple avec une alerte.

| Famille | Flux | IA | Suricata | IA ou Suricata | Les deux (priorité haute) |
|---|---:|---:|---:|---:|---:|
| BENIGN | 3 046 | 0,073 | 0,006 | 0,077 | 0,001 |
| Bot | 64 | 1,000 | 0,000 | 1,000 | 0,000 |
| DDoS | 1 581 | 0,963 | 0,048 | 0,965 | 0,046 |
| PortScan | 2 004 | 1,000 | 0,037 | 1,000 | 0,037 |

**Faux positifs.** 215 des 221 flux « BENIGN » signalés par l'IA sont des flux
`172.16.0.1 → 192.168.10.50:80` pendant la fenêtre DDoS : l'attaquant vers la victime, mais
étiquetés BENIGN par CIC. Hors de ces flux, l'IA signale 6 flux bénins sur 2 831 (0,2 %).
L'étiquette CIC n'a pas été corrigée ; les deux lectures sont données.

**Ce qu'il faut retenir.**
- Ces flux n'ont jamais été vus à l'entraînement. En revanche, ils viennent du même jour, du
  même réseau et des mêmes campagnes d'attaque que les données d'entraînement. Ce n'est pas une
  mesure de généralisation à un autre réseau ni à une attaque inconnue (voir section 4 et e2–e4).
- Suricata ne tourne qu'avec des règles locales (aucun jeu ET/Snort téléchargé). Les seuils
  « SYN scan » et « HTTP GET flood » ne déclenchent qu'une alerte toutes les N occurrences, d'où
  une faible couverture par flux. Ce n'est pas une mesure de Suricata en production.
- Sur la PCAP synthétique, le nouveau modèle signale 3 flux sur 11. Ce trafic reste de la démo,
  pas un résultat.

## 6. Modifications

- `flow-extractor/app/extract.py` : colonne `last_seen_ms` (hors features, sert à l'alignement temporel).
- `ai-engine/app/train.py` : le CSV canonique (NFStream) garde `timestamp`/`first_seen_ms` pour le
  split temporel ; ajout de l'option `--final-fit train|all` ; source `nfstream_csv:<fichier>`.
- `ai-engine/entrypoint.sh` : utilise `data/cic/train_nfstream.csv` s'il existe (avec `--final-fit all`),
  sinon l'ancien CSV CICFlowMeter, avec un avertissement de décalage de domaine.
- `ai-engine/app/predict.py` : `source_pcap` par prédiction et `sources` (flux, suspects, synthétique) par capture.
- `suricata/suricata.yaml` : `pcap-file: true`, pour que chaque événement porte `pcap_filename`.
- `suricata/rules/local.rules` : 4 signatures génériques (SYN scan à seuil, NULL scan, XMAS scan,
  HTTP GET flood à seuil), écrites sans les régler sur les étiquettes CIC.
- `dashboard/app/dashboard.py` : sélecteur de capture, filtre sur `pcap_filename`/`source_pcap`
  (champ réel), avertissement « synthétique » limité à la PCAP synthétique, mention « extrait réel ».
- `tests/smoke.sh` : `--renew-anon-volumes` (voir section 7) ; `tests/check_outputs.py` : contrôles par source.
- Nouveaux outils : `tools/slice_pcap.py`, `tools/label_nfstream_flows.py`,
  `tools/build_real_dataset.sh`, `tools/eval_demo.py`, `tools/eval_real_demo.sh`.

## 7. Incidents

- **Configuration Suricata périmée (bug antérieur).** L'image `jasonish/suricata` déclare
  `VOLUME /etc/suricata`. Lors d'une recréation, `docker compose up` réutilisait l'ancien volume
  anonyme, si bien que les modifications de règles ou de `suricata.yaml` étaient ignorées : 5 règles
  chargées au lieu de 9. Corrigé avec `--renew-anon-volumes`.
- **Identifiants de flux NFStream instables entre deux exécutions** (meters multi-threads). Une
  première évaluation qui réutilisait des étiquettes d'une exécution précédente donnait des chiffres
  faux. `tools/eval_real_demo.sh` réétiquette toujours le `flows.csv` courant.
- L'ancien modèle CICFlowMeter est conservé localement dans `data/models/model_cicflowmeter.joblib`
  et `train_report_cicflowmeter.json` (fichiers ignorés par git).

## 8. Reproduire

```bash
# prérequis : data/cic/raw/pcap/Friday-WorkingHours.pcap + les 3 CSV du vendredi dans data/cic/raw/
docker compose build
bash tools/build_real_dataset.sh     # ~2-3 min : flux NFStream, étiquetage, extrait de démo
bash tests/smoke.sh                  # réentraîne (temporel + final-fit all), pipeline, dashboard
bash tools/eval_real_demo.sh         # tableau de la section 5
```

## 9. Sauvegarde pour la soutenance

L'extrait n'est pas dans git (données CIC-IDS2017) et le PCAP complet pèse 8,8 Go. Sans copie
locale, la démo réelle n'est pas reproductible.

1. **Copier** `data/pcaps/cic_friday_extract.pcap` (33 Mo) sur un support à part (clé USB,
   stockage personnel), puis le remettre dans `data/pcaps/` sur la machine de démo.
2. **Vérifier** l'intégrité :

   ```bash
   sha256sum data/pcaps/cic_friday_extract.pcap
   # attendu : 5120fb2f88e3c237d4c6c2532676cae0a567c56c23438e0451294d86d0edcba6
   ```
3. **Prévoir aussi** `data/cic/train_nfstream.csv` (25 Mo, le jeu d'entraînement) : sans lui,
   `entrypoint.sh` se rabat sur l'ancien CSV CICFlowMeter (décalage de domaine) et le modèle n'est
   plus celui de ce rapport. Autre option : copier `data/models/model.joblib`, mais `tests/smoke.sh`
   le supprime et le réentraîne, donc il faut lancer `docker compose up -d --renew-anon-volumes`
   directement.
4. **Secours**, si seul le PCAP complet est disponible (avec les 3 CSV du vendredi dans
   `data/cic/raw/`) :

   ```bash
   bash tools/build_real_dataset.sh   # recrée l'extrait (même SHA-256) et train_nfstream.csv
   ```
5. **Sans extrait**, la démo fonctionne quand même, en mode dégradé : seule la PCAP synthétique
   est analysée (11 flux, 8 alertes Suricata, 3 suspects IA). Le sélecteur de capture disparaît et
   le dashboard affiche l'avertissement « synthétique » sans erreur.

