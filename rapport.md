# Rapport d'audit technique — AI-IDS-IPS

**Date de l'audit :** 10 novembre 2026  
**Périmètre :** dépôt `/home/zelofane/projects/AI-IDS-IPS`  
**Principe :** aucun fichier du projet n'a été modifié. Ce rapport est le seul fichier créé.  
**Méthode :** lecture intégrale du code, des Dockerfiles, de la configuration Suricata, des scripts de test et des artefacts déjà produits ; exécution des contrôles locaux ne nécessitant pas Docker.

> **Avertissement méthodologique.** L'audit distingue explicitement :
> - ce qui a été **lu et vérifié dans le code** ;
> - ce qui a été **effectivement exécuté ou observé** ;
> - ce qui reste **non testé** (notamment un nouveau passage Docker complet, l'interface Streamlit en direct, et tout dataset réel CIC-IDS2017 / UNSW-NB15, absent du dépôt).

---

## 1. Synthèse exécutive

Le prototype est **techniquement cohérent et fonctionnel en mode démonstration hors ligne**. La chaîne d'artefacts existe réellement : PCAP synthétique → Suricata (`eve.json`) + NFStream (`flows.csv`) → Random Forest (`model.joblib`, `predictions.json`) → dashboard Streamlit. Les contrôles locaux passent.

En revanche, le projet **ne produit pas encore de résultat expérimental exploitable pour un mémoire** :

- le modèle courant est entraîné sur des **données synthétiques** (`data_source: synthetic_demo`) ;
- l'accuracy de **0,992** est un **résultat de démonstration**, pas une performance de détection réelle ;
- il existe une **fuite de données légère mais réelle** dans l'imputation : les médianes sont calculées sur l'ensemble des données **avant** la séparation train/test (`ai-engine/app/train.py:165` puis `:168`) ;
- le chemin CIC-IDS2017 force `src_port = 0` à l'entraînement (`ai-engine/app/train.py:83`) alors que la prédiction utilise les vrais ports source NFStream : **incohérence train/prédiction** ;
- la corrélation Suricata/IA repose sur la **5-tuple seule**, sans fenêtre temporelle ni identifiant de flux partagé : elle peut produire des faux appariements (réutilisation de 5-tuple, multi-PCAP, direction inverse) ;
- le conteneur `dashboard` n'a **pas** `read_only: true`, contrairement aux trois autres ;
- le volet « IPS » est une **simulation dans `st.session_state`** : aucun blocage réseau réel n'est effectué, ce qui est conforme à la règle du projet mais doit être assumé comme limite fonctionnelle.

**Verdict :** bon prototype d'ingénierie et bonne base pédagogique ; **pas encore un dispositif expérimental validé**.

---

## 2. Architecture générale

### 2.1 Rôle exact de chaque conteneur

| Service | Fichier principal | Rôle réel | Mode d'exécution |
|---|---|---|---|
| `suricata` | `suricata/entrypoint.sh`, `suricata/suricata.yaml` | IDS réseau hors ligne : analyse un ou plusieurs PCAP avec des règles locales, écrit `eve.json`, `fast.log`, `suricata.log` | **One-shot** (`restart: "no"`) |
| `flow-extractor` | `flow-extractor/app/extract.py` | Extraction de flux avec NFStream, calcul/normalisation des features statistiques, écriture de `data/flows/flows.csv` | **One-shot** |
| `ai-engine` | `ai-engine/app/train.py`, `predict.py`, `features.py` | Entraînement éventuel du Random Forest, puis prédiction sur `flows.csv`, écriture de `model.joblib` et `predictions.json` | **One-shot**, après `flow-extractor` terminé |
| `dashboard` | `dashboard/app/dashboard.py` | Lecture seule des artefacts, corrélation 5-tuple, décision hybride, vues Suricata / IA / hybride, simulation de blocage | **Long-running**, Streamlit sur `:8501` |

Points importants vérifiés :

- `suricata` ne capture pas en direct : `suricata -r "$WORK_DIR"` (`suricata/entrypoint.sh`). C'est bien un mode **offline PCAP**.
- `suricata` copie d'abord les `.pcap`/`.pcapng` dans un répertoire temporaire pour éviter de faire parser des fichiers parasites comme `.gitkeep`.
- `flow-extractor` ne dépend pas de Suricata et s'exécute en parallèle ; les deux lisent le même répertoire `data/pcaps`.
- `ai-engine` dépend de la **fin réussie** de `flow-extractor` (`docker-compose.yml:81-83`).
- `dashboard` dépend de la fin réussie de `ai-engine` **et** du démarrage de `suricata` (`docker-compose.yml:116-120`).
- `dashboard` est le seul service avec un `HEALTHCHECK` (`dashboard/Dockerfile:19-20`).

### 2.2 Circulation des données

```
data/pcaps/*.pcap
      │
      ├──► Suricata (offline) ──► logs/eve.json (+ fast.log, suricata.log)
      │
      └──► NFStream ───────────► data/flows/flows.csv
                                        │
                                        ▼
                              ai-engine (train si absent)
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
       data/models/model.joblib              data/predictions/predictions.json
                    │                                       │
                    └───────────────┬───────────────────────┘
                                    ▼
                         dashboard (lecture seule)
                         corrélation 5-tuple + décision
```

La corrélation n'est **pas** produite par un service dédié : elle est recalculée à chaque rafraîchissement par le dashboard (`dashboard/app/dashboard.py:100-135`). Aucun identifiant de flux commun n'est partagé entre Suricata et NFStream :

- Suricata possède son propre `flow_id` interne dans `eve.json` ;
- NFStream produit un `flow_id` synthétique de la forme `nom_du_pcap:id` (`flow-extractor/app/extract.py:84`) ;
- ces deux identifiants **ne sont jamais mis en correspondance** dans le code.

### 2.3 Fonctionnement réel du moteur de décision hybride

Le moteur est dans `dashboard/app/dashboard.py:100-135` :

1. normalisation des ports (les ports absents, notamment ICMP, deviennent `0`) ;
2. normalisation du protocole en majuscules ;
3. construction d'une clé `(src_ip, dst_ip, src_port, dst_port, protocole)` ;
4. agrégation des alertes Suricata par clé (`alert_count`, `signatures`) ;
5. jointure `predictions LEFT JOIN alert_summary` sur cette clé ;
6. décision :
   - `high_priority` si IA suspecte **et** alerte Suricata ;
   - `suricata_log` si alerte seule ;
   - `ai_alert` si IA seule ;
   - `normal` sinon.

Cette politique est conforme à la règle du projet (`AGENTS.md`, « Decision policy »).

**Limite structurelle :** la jointure part des prédictions IA (`how="left"`). Une alerte Suricata qui ne correspond à **aucun flux prédit** n'apparaît pas dans l'onglet hybride ; elle reste visible uniquement dans l'onglet « Suricata seul ». De plus, si `predictions.json` est vide, la table hybride est vide même si `eve.json` contient des alertes (`dashboard/app/dashboard.py:100-102`).

### 2.4 Nature réelle du système

Ce n'est pas un IDS/IPS « temps réel » :

- Suricata, NFStream et l'IA s'exécutent **une seule fois** au démarrage ;
- le dashboard rafraîchit seulement la **lecture des fichiers** toutes les 5 secondes (`dashboard/app/dashboard.py:306`), pas la capture ni le pipeline ;
- un nouveau PCAP déposé après le démarrage ne sera pas analysé sans relancer les services ;
- le « rafraîchissement » est donc un **polling de fichiers statiques**, pas une boucle de détection continue.

---

## 3. Suricata

### 3.1 Configuration utilisée

Fichiers vérifiés :

- `suricata/suricata.yaml` ;
- `suricata/rules/local.rules` ;
- `suricata/entrypoint.sh` ;
- `suricata/Dockerfile` ;
- service `suricata` dans `docker-compose.yml`.

Configuration réelle :

- image de base : `jasonish/suricata:8.0.8` ;
- mode : analyse de fichiers PCAP (`-r`), `--runmode single` ;
- réseau domestique : `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `127.0.0.1/32` ;
- `EXTERNAL_NET: "!$HOME_NET"` ;
- 5 règles locales, aucune règles ET/Open ni téléchargement automatique ;
- app-layer HTTP, DNS, TLS activés ;
- sorties EVE : `alert`, `flow`, `http`, `dns`, `tls`, `anomaly`, plus `fast.log` ;
- statistiques Suricata désactivées (`stats.enabled: no`) ;
- permissions : `chmod -R a+rX /etc/suricata` dans le Dockerfile, nécessaire car le conteneur tourne avec l'UID hôte.

Les 5 règles (`suricata/rules/local.rules`) sont :

1. ICMP echo request ;
2. URI HTTP contenant `/admin` ;
3. tentative SSH vers le port 22 ;
4. tentative Telnet vers le port 23 ;
5. tentative RDP vers le port 3389.

### 3.2 Analyse réelle du PCAP

Artefacts observés :

- `data/pcaps/synthetic_demo.pcap` : **97 paquets**, version 2.4, linktype Ethernet, snaplen 65535, validé par `tests/verify_pcap.py` ;
- `logs/suricata.log` : Suricata 8.0.8, **5 règles chargées**, 0 échec, **97 paquets lus**, 18 012 octets ;
- `logs/eve.json` : 11 événements `flow`, 8 `alert`, 2 `http`, 2 `dns`, 2 `anomaly`.

Alertes réellement produites :

| Signature | Occurrences | Flux concerné |
|---|---:|---|
| DEMO ICMP echo request | 1 | `synthetic_demo:6` |
| DEMO suspicious HTTP URI /admin | 1 | `synthetic_demo:3` |
| DEMO SSH connection attempt | 4 | `synthetic_demo:1` |
| DEMO Telnet connection attempt | 1 | `synthetic_demo:7` |
| DEMO RDP connection attempt | 1 | `synthetic_demo:8` |

Toutes les alertes ont `action: allowed` et une sévérité 3. C'est cohérent avec un **IDS sans blocage**.

### 3.3 Génération des événements EVE JSON

Le fichier `logs/eve.json` est bien du JSON Lines : une ligne = un événement JSON. Le dashboard filtre sur `event_type == "alert"` (`dashboard/app/dashboard.py:41-72`).

Points notables :

- les événements `anomaly` existent mais ne sont **pas exploités** par le dashboard ;
- les événements `flow` de Suricata ne sont pas utilisés pour la corrélation, alors qu'ils pourraient fournir des métriques et des identifiants utiles ;
- la règle SSH génère **4 alertes** pour un même flux, ce qui gonfle `alert_count` sans déduplication. Cela traduit un comportement au niveau paquet plutôt qu'un déclenchement unique par flux.

### 3.4 Limites Suricata

- Jeu de règles **de démonstration**, sans prétention de détection réelle.
- Aucune gestion de version/signature de règles, aucune règle communautaire.
- Aucune capture live, aucun IPS (`drop`), aucun blocage.
- Le PCAP est synthétique : les alertes prouvent le **fonctionnement de la chaîne**, pas la qualité de détection.
- Aucune vérité terrain associée aux paquets/flux, donc impossible de calculer précision/rappel Suricata sur ce jeu.

---

## 4. Intelligence artificielle

### 4.1 Algorithme

`ai-engine/app/train.py:172-179` :

```python
RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=args.seed,
    n_jobs=1,
)
```

- forêt aléatoire de 200 arbres ;
- profondeur non bornée ;
- `class_weight="balanced"` ;
- graine fixée (`42` par défaut) pour la reproductibilité ;
- `n_jobs=1` pour rester prévisible dans le conteneur.

### 4.2 Caractéristiques utilisées

Liste canonique dans `ai-engine/app/features.py:21-34` :

1. `duration_ms`
2. `protocol_num`
3. `src_port`
4. `dst_port`
5. `packets`
6. `bytes`
7. `bytes_per_s`
8. `packets_per_s`
9. `mean_pkt_size`
10. `min_pkt_size`
11. `max_pkt_size`
12. `stddev_pkt_size`

Le contrat est contrôlé par `tests/check_contract.py` : les 12 features de l'IA sont bien émises par `flow-extractor` (6 colonnes d'identité + 10 colonnes de features, avec recouvrement attendu sur `protocol_num`, `src_port`, `dst_port`).

L'imputation est centralisée dans `build_feature_matrix` (`ai-engine/app/features.py:56-77`) :

- valeurs non numériques → `NaN` ;
- `+inf`/`-inf` → `NaN` ;
- remplacement par la médiane ;
- à l'entraînement, médianes calculées sur le DataFrame fourni ;
- à la prédiction, médianes restaurées depuis le bundle.

C'est un bon point de conception : **une seule fonction** pour l'entraînement et la prédiction, et un bundle qui contient l'ordre exact des features, les médianes et le seuil.

### 4.3 Origine des données

Deux chemins existent :

1. **CSV fourni par l'utilisateur** (`--data`) :
   - soit un CSV au format canonique (features + colonne `label`) ;
   - soit un CSV de style CIC-IDS2017, converti par `_load_cic` (`ai-engine/app/train.py:60-85`) à partir de `CIC_COLUMN_MAP` (`:38-52`).
2. **Données synthétiques** (`--demo`), générées par `make_synthetic_frame` (`ai-engine/app/train.py:100-144`) :
   - 4 000 lignes par défaut ;
   - 35 % d'attaques ;
   - distributions volontairement différentes entre bénin et attaque ;
   - injection de 1 % de valeurs manquantes pour tester l'imputation.

Le modèle **actuellement présent** a été entraîné sur `synthetic_demo` :

- `data/models/train_report.json` : `data_source: synthetic_demo`, `demo: true`, 4 000 lignes, accuracy 0,992 ;
- `data/predictions/predictions.json` : `data_source: synthetic_demo`, `demo: true`.

Aucun échantillon CIC n'est présent : `data/cic/` ne contient que `.gitkeep`.

**Important :** l'entrypoint `ai-engine/entrypoint.sh` n'entraîne que si le modèle est **absent**. Si un `model.joblib` existe déjà, un nouveau `data/cic/train.csv` ne sera pas pris en compte automatiquement ; il faut supprimer le modèle ou lancer `train.py` manuellement.

### 4.4 Séparation entraînement / test

`ai-engine/app/train.py:168-170` :

```python
x_train, x_test, y_train, y_test = train_test_split(
    matrix, labels, test_size=0.25, random_state=args.seed, stratify=labels
)
```

- séparation **75 % / 25 %** ;
- stratification sur les labels ;
- graine fixée ;
- pas de jeu de validation séparé ;
- pas de validation croisée ;
- pas de séparation par capture, par jour ou par session.

### 4.5 Calcul des métriques

`ai-engine/app/train.py:182-184` :

- `accuracy_score` ;
- `classification_report` (précision, rappel, F1 par classe) ;
- rapport sauvegardé dans `model.joblib` et `data/models/train_report.json`.

Le résultat courant est une accuracy de **0,992** sur 1 000 lignes de test synthétiques. Ce chiffre est **reproductible et cohérent avec le code**, mais il ne mesure pas une capacité de détection réelle.

Ne sont pas calculés :

- matrice de confusion dédiée ;
- ROC-AUC / PR-AUC ;
- taux de faux positifs à seuil fixe ;
- calibration des probabilités ;
- intervalles de confiance ou variabilité multi-graines ;
- métriques par type d'attaque (le problème est binaire).

### 4.6 Risques de fuite de données et biais

#### Fuite réelle n°1 — médianes calculées avant le split

`ai-engine/app/train.py:165` construit la matrice et calcule les médianes sur **tout** le jeu de données, puis `:168` sépare train/test. Les médianes d'imputation utilisées pour le test contiennent donc une information issue du test.

L'effet est faible sur 4 000 lignes synthétiques, mais la méthode est **scientifiquement incorrecte** : les statistiques d'imputation doivent être apprises uniquement sur le train.

#### Fuite/ biais n°2 — séparation aléatoire sur des flux potentiellement corrélés

Avec CIC-IDS2017, des flux issus d'une même session, d'une même capture ou d'une même attaque peuvent se retrouver à la fois en train et en test. Un split aléatoire peut alors surestimer les performances. Il faudrait grouper par capture/session/jour, ou utiliser un split temporel.

#### Incohérence majeure n°3 — `src_port` forcé à 0 pour CIC

`ai-engine/app/train.py:83` :

```python
out["src_port"] = 0
```

Le modèle apprend donc avec un port source **constant** pour les données CIC, alors que la prédiction sur les flux NFStream utilise le **vrai port source éphémère** (`flow-extractor/app/extract.py:88`). C'est une divergence de distribution entre entraînement et prédiction. Elle peut dégrader fortement les performances réelles, ou rendre la feature inutile.

#### Biais n°4 — données synthétiques trivialement séparables

`make_synthetic_frame` génère deux populations avec des lois nettement différentes :

- attaques : durées et nombres de paquets plus faibles, ports 22/23/3389/80/443/0 ;
- bénin : durées plus longues, ports 80/443/53/22/8080/123.

Le Random Forest peut atteindre 0,992 en apprenant ces différences artificielles. **Ce n'est pas une performance de détection.**

#### Biais n°5 — les ports comme raccourci

Les features incluent `src_port` et `dst_port`. Sur CIC-IDS2017, certains ports sont fortement associés à certaines attaques (HTTP/DoS, SSH, etc.). Le modèle peut apprendre des **artefacts du dataset** plutôt que des comportements d'attaque. Il faut analyser l'importance des features et tester sans les ports.

#### Biais n°6 — décalage de domaine CSV CIC → flux NFStream

Même avec des noms de features identiques, les définitions ne sont pas nécessairement identiques entre les colonnes CIC-IDS2017 et les sorties NFStream :

- `Flow Duration` CIC est en microsecondes, converti en ms par `/1000` (`train.py:68`) ;
- les compteurs de paquets/octets sont reconstruits par somme (`packets_fwd + packets_bwd`, `bytes_fwd + bytes_bwd`) ;
- NFStream calcule ses propres statistiques bidirectionnelles.

Un modèle entraîné sur un CSV CIC n'est donc pas automatiquement valide sur des flux NFStream. Une validation sur des flux réels extraits d'un PCAP étiqueté est nécessaire.

---

## 5. Corrélation Suricata / IA

### 5.1 Correspondance par 5-tuple : ce qui est réellement fait

Clé construite dans `dashboard/app/dashboard.py:85-97` :

```python
(src_ip, dst_ip, src_port, dst_port, protocol.upper())
```

- `src_ip`/`dst_ip` : chaînes ;
- ports : numériques, valeurs manquantes remplacées par `0` ;
- protocole : majuscules.

La jointure est faite sur cette clé (`:119`) après agrégation des alertes (`:109-117`).

### 5.2 Vérification sur les artefacts existants

J'ai recalculé la logique de corrélation sur les fichiers réellement présents (sans lancer Streamlit) :

- 11 flux prédits ;
- 8 alertes Suricata brutes ;
- 5 clés d'alerte distinctes ;
- toutes les clés d'alerte correspondent à un flux prédit ;
- 5 flux sont donc en concordance ;
- décisions calculées :
  - **5 `high_priority`** : flux `1` (SSH), `3` (HTTP /admin), `6` (ICMP), `7` (Telnet), `8` (RDP) ;
  - **4 `ai_alert`** : flux `0` (HTTP), `4` (DNS), `9` (DNS), `10` (TLS) ;
  - **2 `normal`** : flux `2` (TLS), `5` (HTTP) ;
  - **0 `suricata_log`** sur ce jeu de démonstration.

La 5-tuple SSH apparaît **4 fois** dans `eve.json` ; le compteur `alert_count` du flux SSH vaut donc 4, alors qu'il s'agit du même flux. Les signatures sont dédupliquées dans la colonne `signatures`, mais pas les occurrences.

### 5.3 Vérification de la gestion des cas particuliers

- **ICMP** : Suricata ne fournit pas de ports (`None`), le dashboard les convertit en `0` ; NFStream émet `0` pour l'ICMP. La correspondance fonctionne sur ce cas.
- **Protocole** : `str(event.get("proto")).upper()` côté Suricata et `protocol` en clair côté NFStream (`TCP`, `UDP`, `ICMP`) ; la normalisation est cohérente pour IPv4.
- **Alertes sans flux associé** : elles restent visibles dans l'onglet Suricata, mais sont absentes de la décision hybride.
- **Flux sans alerte** : correctement classés `ai_alert` ou `normal`.

### 5.4 Limites de la corrélation

1. **Absence de temps** : la clé ne contient ni timestamp ni fenêtre temporelle. Deux flux réutilisant la même 5-tuple à des moments différents sont fusionnés.
2. **Absence d'identifiant de flux partagé** : le `flow_id` Suricata et le `flow_id` NFStream ne sont pas liés. Le seul lien est la 5-tuple.
3. **Multi-PCAP** : `flow-extractor` traite tous les PCAP d'un répertoire et concatène les flux. Deux captures différentes contenant la même 5-tuple peuvent être corrélées à tort.
4. **Direction du flux** : NFStream définit la direction à partir du premier paquet observé ; Suricata peut alerter dans l'autre sens (réponse serveur, trafic retour). La correspondance exacte peut échouer.
5. **Granularité différente** : Suricata alerte au niveau paquet/événement, NFStream agrège au niveau flux. Le comptage `alert_count` n'est pas un nombre de flux distincts.
6. **Aucune déduplication temporelle** : 4 alertes SSH = `alert_count: 4`.
7. **Alertes non appariées invisibles dans l'hybride** : la jointure part des prédictions.
8. **Pas de vérité terrain** : impossible de mesurer si les correspondances sont correctes, seulement de constater qu'elles existent.
9. **Pas de gestion IPv6** : `PROTOCOL_NAMES` ne couvre que 1, 6, 17 ; tout autre protocole devient `OTHER` (`flow-extractor/app/extract.py:18,93`), alors que Suricata peut produire `ICMPv6`, etc.

---

## 6. Sécurité

### 6.1 Contrôles présents

| Contrôle | État | Preuve |
|---|---|---|
| Pas de `privileged` | OK | absent de `docker-compose.yml` |
| `cap_drop: ALL` | OK sur les 4 services | `docker-compose.yml:11-12,39-40,65-66,100-101` |
| `no-new-privileges` | OK sur les 4 services | `docker-compose.yml:9-10,37-38,63-64,98-99` |
| Utilisateur non-root | Configuré via `${HOST_UID:-1000}:${HOST_GID:-1000}` | `docker-compose.yml:8,36,62,97` |
| Rootfs en lecture seule | OK pour Suricata, flow-extractor, ai-engine | `docker-compose.yml:20,46,78` |
| `/tmp` en `tmpfs` | OK sur les 4 services | `docker-compose.yml:21-22,47-48,79-80,114-115` |
| Montages en lecture seule | PCAP, flows pour l'IA, logs/flows/predictions pour le dashboard | volumes du compose |
| Limites CPU/mémoire | Déclarées via `deploy.resources.limits` | chaque service |
| Port publié | Un seul : `8501` | `docker-compose.yml:112-113` |
| Healthcheck | Dashboard uniquement | `dashboard/Dockerfile:19-20` |
| Secrets | Aucun secret en clair | lecture du dépôt |

### 6.2 Problèmes de sécurité détectés

1. **`dashboard` n'a pas `read_only: true`.**
   - Les trois autres services l'ont ; le dashboard non (`docker-compose.yml:93-128`).
   - Il possède bien `tmpfs: /tmp`, mais son rootfs reste inscriptible.
   - Le dashboard n'écrit pas sur le disque dans le code actuel, donc le risque est contenu, mais la politique « containers read-only » du projet n'est pas respectée.

2. **Port `8501` exposé sur toutes les interfaces.**
   - `ports: - "8501:8501"` publie sur `0.0.0.0`.
   - Aucune authentification, aucun TLS, aucun contrôle d'accès.
   - Pour un prototype local, préférer `127.0.0.1:8501:8501`.

3. **Utilisateur dépendant de l'environnement hôte.**
   - `${HOST_UID:-1000}:${HOST_GID:-1000}` : si l'utilisateur exporte `HOST_UID=0`, les conteneurs tournent en root.
   - Aucun contrôle ne vérifie que l'UID effectif est non nul.
   - Cela peut aussi provoquer des erreurs de permissions sur les volumes si l'UID hôte n'est pas 1000.

4. **Images non épinglées par digest.**
   - `jasonish/suricata:8.0.8` et `python:3.12-slim` sont des tags, pas des digests.
   - Les dépendances Python sont épinglées par version, mais sans hash.
   - Risque de chaîne d'approvisionnement, faible mais réel.

5. **Réseau sans restriction de sortie.**
   - Réseau bridge `idsnet`, sans `internal: true` ni politique de sortie.
   - Les conteneurs n'ont pas besoin d'Internet pour fonctionner en offline.
   - Une politique réseau plus stricte réduirait la surface.

6. **Données potentiellement sensibles non ignorées.**
   - `.gitignore` ignore les sorties générées, mais pas `data/pcaps/*.pcap` ni `data/cic/*.csv`.
   - Des PCAP réels ou des datasets peuvent être volumineux ou sensibles ; ils pourraient être versionnés par erreur.
   - Le dépôt n'est actuellement pas un dépôt Git (`git status` échoue), mais la règle reste pertinente pour la suite.

7. **Artefacts lisibles par tous localement.**
   - `model.joblib`, `eve.json`, `flows.csv` sont en `644`, propriétaire `zelofane:zelofane`.
   - Sur un poste partagé, des captures ou métadonnées réseau sont lisibles par tout utilisateur local.

8. **Pas de rotation/limite de logs.**
   - `eve.json` et `fast.log` grossissent sans rotation.
   - Le dashboard relit tout `eve.json` à chaque rafraîchissement (`dashboard/app/dashboard.py:41-72`), ce qui devient coûteux sur un gros fichier.

### 6.3 Limites de la simulation de prévention

Le « blocage » est uniquement :

```python
st.session_state["simulated_blocked"]
```

(`dashboard/app/dashboard.py:264-282`)

Il n'y a :

- aucun appel à `iptables`, `nftables`, `tc`, Suricata `drop`, ou API de pare-feu ;
- aucune modification d'interface réseau ;
- aucune persistance au-delà de la session Streamlit ;
- aucune trace d'audit, aucun acteur, aucun horodatage de décision ;
- aucun contrôle d'accès : tout utilisateur du dashboard peut cliquer ;
- aucune vérification que le flux existe encore.

C'est conforme à la règle « No real network blocking », mais cela signifie que **le volet IPS est purement cosmétique**. Le nom « AI-IDS-IPS » est donc trompeur si l'on entend « prevention system ».

---

## 7. Qualité scientifique

### 7.1 Ce qui peut être présenté dans un mémoire

Comme **travail d'ingénierie et de prototypage**, sont défendables :

- l'architecture dockerisée et la séparation des responsabilités ;
- la chaîne d'artefacts reproductible PCAP → EVE/CSV → modèle → prédictions → dashboard ;
- le contrat de features centralisé et testé (`tests/check_contract.py`) ;
- la politique de décision hybride et les trois vues (Suricata seule, IA seule, hybride) ;
- les mesures de durcissement des conteneurs (`cap_drop`, `no-new-privileges`, read-only, limites) ;
- la démonstration fonctionnelle de bout en bout sur un PCAP synthétique ;
- l'explicitation du caractère synthétique des données (`demo`, `data_source`, avertissement dashboard) ;
- les limites elles-mêmes, si elles sont présentées honnêtement.

### 7.2 Ce qui ne peut pas être présenté comme résultat expérimental

- **Accuracy 0,992** : issue de données synthétiques trivialement séparables, **pas** une performance de détection.
- **9 flux suspects sur 11** : conséquence d'un modèle synthétique appliqué à un PCAP synthétique, sans vérité terrain.
- **8 alertes Suricata** : produites par 5 règles de démonstration, sans mesure de précision/rappel.
- **5 décisions `high_priority`** : illustrent le mécanisme de corrélation, pas la qualité du système.
- Toute comparaison « IA vs Suricata vs hybride » sur ce jeu : non significative, faute de labels de référence et de volume.

### 7.3 Tests techniques vs résultats expérimentaux

| Élément | Nature | Statut |
|---|---|---|
| `tests/verify_pcap.py` | Test technique de structure PCAP | **Exécuté**, OK (97 paquets) |
| `tests/check_contract.py` | Test statique de contrat de features | **Exécuté**, OK (12 features) |
| `tests/check_outputs.py` | Test de cohérence des artefacts | **Exécuté**, OK (11 flux, 8 alertes, 11 prédictions) |
| `tests/smoke.sh` | Test d'intégration Docker de bout en bout | **Non relancé pendant cet audit** ; artifacts existants cohérents |
| `train_report.json` | Métriques sur données synthétiques | **Démo**, pas expérimental |
| `predictions.json` | Prédictions sur PCAP synthétique | **Démo**, pas expérimental |
| `eve.json` | Alertes sur PCAP synthétique | **Démo**, pas expérimental |
| Dashboard en direct | Interface Streamlit | **Non lancé pendant cet audit** ; code lu |

### 7.4 Expériences nécessaires avec un dataset réel

#### Avec CIC-IDS2017

1. Fournir un échantillon compatible dans `data/cic/train.csv` (aucun téléchargement automatique).
2. Corriger la gestion de `src_port` : ne pas forcer `0`, ou retirer la feature du modèle, ou garantir la même définition à l'entraînement et à la prédiction.
3. Dédupliquer les flux et vérifier les colonnes, les valeurs infinies et les labels.
4. Remplacer le split aléatoire par un split **groupé ou temporel** (par capture, session, jour) pour éviter les fuites.
5. Calculer les médianes d'imputation **sur le train uniquement**.
6. Mesurer : précision, rappel, F1, matrice de confusion, ROC-AUC, PR-AUC, taux de faux positifs à seuil fixe, performance par type d'attaque.
7. Faire une validation croisée et répéter avec plusieurs graines, avec intervalles de confiance.
8. Comparer plusieurs baselines : règles seules, Random Forest seul, hybride, éventuellement un modèle linéaire ou un gradient boosting.
9. Tester l'importance des features et l'effet de la suppression des ports.
10. Évaluer la **généralisation** : entraînement CIC → test sur des flux réels extraits d'un PCAP distinct, si disponible.

#### Avec UNSW-NB15

Mêmes étapes, en adaptant le mapping des colonnes. UNSW-NB15 permet en outre une séparation par type d'attaque et un test de transfert inter-datasets.

#### Pour le volet hybride (Suricata + IA)

1. Constituer ou obtenir des **PCAP étiquetés** (le CSV CIC ne suffit pas : Suricata a besoin de paquets). Sans PCAP, on ne peut pas évaluer la corrélation réelle.
2. Définir une vérité terrain par flux et par alerte.
3. Mesurer :
   - nombre d'alertes Suricata correctement appariées ;
   - nombre de flux IA correctement appariés ;
   - faux appariements 5-tuple ;
   - précision/rappel de la décision hybride ;
   - apport réel du hybride par rapport à Suricata seul et IA seule (ablation).
4. Tester la robustesse au multi-PCAP et aux 5-tuples réutilisées.
5. Mesurer le coût (latence, CPU, mémoire) et la stabilité des décisions dans le temps.
6. Définir un protocole de seuil : 0,5 n'est pas justifié expérimentalement.

### 7.5 Limites scientifiques du prototype

1. **Pas de données réelles** dans l'état actuel : uniquement un PCAP synthétique et un modèle synthétique.
2. **Pas de vérité terrain** pour les flux du PCAP de démonstration.
3. **Pas de protocole expérimental** : pas de split groupé, pas de validation croisée, pas d'intervalles de confiance.
4. **Fuite d'imputation** avant split.
5. **Incohérence train/prédiction** sur `src_port` pour le chemin CIC.
6. **Features limitées à 12** alors que CIC-IDS2017 en propose beaucoup plus ; la justification de ce sous-ensemble n'est pas fournie.
7. **Problème binaire** : les types d'attaques sont fusionnés en `attack`, ce qui limite l'interprétation.
8. **Corrélation sans temps ni identifiant de flux partagé** : appariements potentiellement faux.
9. **Aucune mesure de faux positifs en conditions réelles**, donc pas de discussion crédible du coût opérationnel.
10. **Aucune prévention réelle** : le système est un IDS batch avec simulation d'IPS.
11. **Aucune évaluation de la dérive** (concept drift) ni de la qualité des probabilités (calibration).
12. **Aucune analyse de l'importance des features** ni de l'explicabilité des décisions, alors que c'est souvent attendu pour un mémoire sur un IDS.

---

## 8. Problèmes détectés, classés par priorité

### P0 — bloquants pour toute affirmation expérimentale

1. **Fuite d'imputation avant séparation train/test** (`ai-engine/app/train.py:165-170`).
2. **`src_port = 0` pour l'entraînement CIC** (`ai-engine/app/train.py:83`) alors que la prédiction utilise les vrais ports (`flow-extractor/app/extract.py:88`).
3. **Métriques synthétiques présentées comme résultat** : 0,992 sur données séparables artificiellement.
4. **Absence de vérité terrain et de PCAP étiquetés** pour évaluer la détection et la corrélation.
5. **Split aléatoire non groupé** : risque de fuite sur CIC-IDS2017 (flux/sessions proches).

### P1 — qualité et robustesse

6. **Corrélation 5-tuple sans temps ni `flow_id` partagé** : faux appariements possibles, surtout en multi-PCAP.
7. **Alertes Suricata non appariées absentes de la vue hybride** (jointure `left` depuis les prédictions).
8. **Duplication des alertes** (4 alertes SSH pour un flux) sans déduplication par flux.
9. **`dashboard` sans `read_only: true`**.
10. **Port 8501 exposé sur `0.0.0.0` sans authentification**.
11. **Pipeline one-shot** : pas de surveillance continue, pas de réanalyse automatique des nouveaux PCAP.
12. **Modèle non réentraîné automatiquement** si un nouveau dataset est fourni alors qu'un modèle existe déjà.

### P2 — durcissement et maintenabilité

13. **Images non épinglées par digest**, dépendances sans hash.
14. **Réseau bridge sans restriction de sortie**.
15. **`.gitignore` incomplet** pour `data/pcaps/*.pcap` et `data/cic/*.csv`.
16. **Pas de rotation des logs** ; relecture complète de `eve.json` toutes les 5 s.
17. **Protocoles non IPv4/non TCP-UDP-ICMP** mal normalisés (`OTHER`).
18. **Pas de métriques avancées** (AUC, FPR, calibration, importance des features).
19. **Pas de tests unitaires** sur la corrélation et la décision hybride ; les tests actuels vérifient surtout la présence des artefacts.
20. **Pas de healthcheck** pour les services one-shot (moins critique).

---

## 9. Améliorations prioritaires recommandées

### Avant de produire des chiffres pour un mémoire

1. **Séparer avant d'imputer** : découper train/test d'abord, calculer les médianes sur le train seul, les appliquer au test et à la prédiction.
2. **Rendre `src_port` cohérent** : soit le retirer des features, soit le renseigner correctement pour CIC, soit documenter et tester la différence de distribution.
3. **Construire un vrai protocole expérimental** :
   - dataset réel fourni par l'utilisateur ;
   - déduplication ;
   - split groupé/temporel ;
   - validation croisée ;
   - métriques complètes et variabilité multi-graines.
4. **Évaluer séparément puis conjointement** : Suricata seul, IA seule, hybride, avec vérité terrain.
5. **Obtenir des PCAP étiquetés** pour que la corrélation soit évaluable ; sinon, assumer que seule la classification sur flux est mesurable.

### Ensuite

6. **Renforcer la corrélation** : fenêtre temporelle, date de début de flux, éventuellement mapping vers le `flow_id` Suricata si une clé commune peut être construite.
7. **Dédupliquer les alertes** par flux et par signature avant agrégation.
8. **Afficher les alertes non appariées** dans une vue « Suricata uniquement non corrélées » et les inclure explicitement dans la politique de décision.
9. **Passer `dashboard` en `read_only`**, publier le port sur `127.0.0.1`, ajouter une authentification si le dashboard doit être exposé.
10. **Rendre le pipeline répétable** : relance planifiée ou watcher de répertoire, ou documenter clairement le caractère batch.
11. **Ajouter des tests unitaires** sur `build_hybrid`, les cas ICMP, les alertes non appariées, les doublons et les 5-tuples réutilisées.
12. **Compléter `.gitignore`** et documenter la politique de données sensibles.
13. **Épingler les images par digest** et envisager un réseau `internal`.
14. **Ajouter une rotation/limite** sur `eve.json` et une lecture incrémentale côté dashboard.

---

## 10. Conclusion

Le projet remplit bien son objectif de **prototype pédagogique et d'ingénierie** : les conteneurs ont des rôles clairs, les données circulent de façon traçable, le contrat de features est centralisé, la corrélation est explicite et la politique de décision est lisible. Les tests techniques locaux passent et les artefacts existants sont cohérents.

Il ne faut cependant **pas** présenter les chiffres actuels comme des résultats de détection :

- le modèle est entraîné sur des données synthétiques ;
- l'accuracy de 0,992 est un artefact de séparabilité ;
- la corrélation n'a pas été évaluée contre une vérité terrain ;
- le système n'est ni temps réel ni préventif.

Les priorités avant toute soutenance expérimentale sont claires : corriger la fuite d'imputation, aligner `src_port` entre entraînement et prédiction, introduire un dataset réel avec un split rigoureux, et évaluer le hybride contre ses composants sur des PCAP étiquetés.

---

## Annexe A — Commandes exécutées pendant cet audit

```bash
python3 tests/verify_pcap.py
# OK: data/pcaps/synthetic_demo.pcap version=2.4 snaplen=65535 packets=97

python3 tests/check_contract.py
# OK: 12 AI features are all emitted by flow-extractor (6 identity + 10 feature columns)

python3 tests/check_outputs.py
# Artifact check
#   - 1 pcap file(s)
#   - eve.json events={'alert': 8, 'http': 2, 'anomaly': 2, 'dns': 2, 'flow': 11}, alerts=8
#   - flows.csv rows=11
#   - model size=1139805 bytes
#   - predictions=11 suspicious=9 data_source=synthetic_demo
#   - predictions flagged as synthetic DEMO data
# OK: all required artifacts are present and coherent
```

Un recalcul indépendant de la logique `build_hybrid` sur les artefacts a donné :

- 5 `high_priority` ;
- 4 `ai_alert` ;
- 2 `normal` ;
- 0 `suricata_log` ;
- 5 clés d'alerte distinctes, toutes appariées à un flux ;
- 8 alertes brutes, dont 4 occurrences SSH pour un même flux.

**Non exécuté pendant cet audit :**

- `docker compose build` / `up` / `tests/smoke.sh` (pas de relance complète) ;
- lancement interactif du dashboard Streamlit ;
- entraînement ou prédiction sur CIC-IDS2017 / UNSW-NB15 (datasets absents) ;
- inspection des importances de features du modèle (nécessiterait un environnement Python avec scikit-learn, absent sur l'hôte selon `AGENTS.md`).

## Annexe B — Fichiers de code examinés

- `docker-compose.yml`
- `suricata/Dockerfile`, `suricata/entrypoint.sh`, `suricata/suricata.yaml`, `suricata/rules/local.rules`
- `flow-extractor/Dockerfile`, `flow-extractor/requirements.txt`, `flow-extractor/app/extract.py`
- `ai-engine/Dockerfile`, `ai-engine/entrypoint.sh`, `ai-engine/requirements.txt`, `ai-engine/app/features.py`, `ai-engine/app/train.py`, `ai-engine/app/predict.py`
- `dashboard/Dockerfile`, `dashboard/requirements.txt`, `dashboard/.streamlit/config.toml`, `dashboard/app/dashboard.py`
- `tests/smoke.sh`, `tests/check_contract.py`, `tests/check_outputs.py`, `tests/verify_pcap.py`
- `traffic-generator/generate_demo_pcap.py`
- `AGENTS.md`, `.gitignore`
- Artefacts : `data/pcaps/synthetic_demo.pcap`, `data/flows/flows.csv`, `data/models/model.joblib`, `data/models/train_report.json`, `data/predictions/predictions.json`, `logs/eve.json`, `logs/fast.log`, `logs/suricata.log`
