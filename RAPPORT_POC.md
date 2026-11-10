# Rapport PoC — évaluation sur données réelles CIC-IDS2017 et régénération du modèle

Branche : `poc-real-eval`. Commit de départ : `f472b6b`.
Toutes les valeurs de ce rapport proviennent des fichiers `results/*.json`, `results/*.log`,
`data/models/train_report.json`, `data/predictions/predictions.json` et des sorties de commandes
réellement exécutées sur cette machine. Aucun chiffre n'a été inventé.

## 1. Résumé exécutif

Le dataset CIC-IDS2017 (vendredi, `GeneratedLabelledFlows.zip`) a été téléchargé depuis un miroir
Hugging Face non officiel, vérifié, puis un échantillon systématique de 140 649 lignes a été
construit (`tools/build_cic_sample.py`). Sept entraînements Docker ont été exécutés : split temporel,
trois expériences zero-day (PortScan, Bot, DDoS) et trois graines en split aléatoire. Le modèle de
démo a été régénéré à partir de `e1_temporal` et le bandeau `demo_traffic` a été ajouté.
Le `smoke.sh` final passe et retombe exactement sur les métriques de `e1_temporal`.
Point critique : le split temporel ne place **que DDoS** (plus BENIGN) dans le test ; les scores
quasi parfaits ne mesurent donc que la détection de DDoS vu à l'entraînement.

Trois chiffres clés : accuracy temporelle **0,9984** ; ROC-AUC temporelle **0,99975** ;
rappel zero-day PortScan **0,0006** (RF supervisé) — l'inverse d'une généralisation aux attaques inconnues.

## 2. Environnement

- Docker : `Docker version 29.9.3, build 5457199`
- Docker Compose : `v5.7.0`
- Hôte : WSL2 (Linux), Python hôte 3.12.3 sans numpy/pandas/sklearn ; les expériences ont tourné
  dans l'image `ai-ids-ips-ai-engine` (pandas 2.2.3, numpy 1.26.4, scikit-learn 1.5.2, joblib 1.4.2).
- Espace disque au départ : 944 Go libres sur `/dev/sdd` (> 3 Go requis).
- Commit de départ : `f472b6b`. Commits créés avant ce rapport :
  - `c0c711f` — correction horodatages CIC / holdout / encodage CSV
  - `834b9c8` — bandeau `demo_traffic`
  - `d4a4c4b` — builder d'échantillon CIC (stdlib)
  - `eab0adf` — résultats des expériences (`results/`)
- Durées mesurées (`/usr/bin/time`, autour de `docker compose run`) :

| Run | Durée |
|---|---|
| `e1_temporal` | 132,77 s |
| `e2_zeroday_portscan` | 165,78 s |
| `e3_zeroday_bot` | 178,32 s |
| `e4_zeroday_ddos` | 171,32 s |
| `e5_random_seed1` | 162,61 s |
| `e5_random_seed2` | 169,30 s |
| `e5_random_seed3` | 171,80 s |

Aucun run n'a été tué : pas d'exit 137, pas de dépassement de la limite mémoire de 1 Go, donc aucune
override mémoire temporaire n'a été nécessaire. La durée du `smoke.sh` final n'a pas été chronométrée
précisément (elle inclut build, Suricata, NFStream, réentraînement et attente du dashboard).

## 3. Téléchargement

- Source : miroir **non officiel** Hugging Face `bencorn/CICIDS2017` (type dataset).
- Révision du dépôt : `811c007f08d693a8a8b4226c197c138391806ce6`.
- Fichier : `csvs/GeneratedLabelledFlows.zip`.
- Taille : `283 876 488` octets (≈ 270,7 MiB).
- SHA-256 : `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`.
- Intégrité : `unzip` n'est pas installé sur l'hôte ; le test a été fait avec `zipfile.ZipFile.testzip()`
  (bibliothèque standard Python) : résultat `None` (aucun fichier corrompu), 9 entrées listées.
- Le miroir `c01dsnap/CIC-IDS2017` a aussi été interrogé mais n'a retourné aucun fichier exploitable.
- Seuls les 3 CSV du vendredi ont été extraits, dans `data/cic/raw/` :
  `Friday-WorkingHours-Morning.pcap_ISCX.csv`,
  `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`,
  `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`.
- Rappel : la source de référence est la page UNB officielle (`https://www.unb.ca/cic/datasets/ids-2017.html`),
  qui exige un formulaire. Le miroir utilisé est non officiel ; son contenu n'a pas été validé
  cryptographiquement contre une empreinte UNB.

## 4. Dataset

Fichier entraîné : `data/cic/train.csv`, 54 720 028 octets, 140 649 lignes de données (+ en-tête).
Builder : `tools/build_cic_sample.py` (stdlib uniquement), concaténation
Morning → PortScan → DDoS puis échantillonnage systématique 1 ligne sur `k = 5`.

Comptes par Label **avant** échantillonnage (703 245 lignes) :

| Label | Lignes |
|---|---:|
| BENIGN | 414 322 |
| Bot | 1 966 |
| DDoS | 128 027 |
| PortScan | 158 930 |

Comptes par Label **après** échantillonnage (140 649 lignes) :

| Label | Lignes |
|---|---:|
| BENIGN | 82 871 |
| Bot | 402 |
| DDoS | 25 606 |
| PortScan | 31 770 |

Aucune famille ne tombe sous 200 lignes (Bot : 402). `k` n'a donc pas été baissé.

Horodatages bruts min/max par fichier (chaînes lexicographiques, telles quelles) :

| Fichier | min brut | max brut |
|---|---|---|
| Friday-WorkingHours-Morning | `7/7/2017 10:00` | `7/7/2017 9:59` |
| Friday-WorkingHours-Afternoon-PortScan | `7/7/2017 1:00` | `7/7/2017 3:29` |
| Friday-WorkingHours-Afternoon-DDos | `7/7/2017 3:30` | `7/7/2017 5:02` |

Horodatages **corrigés** (heures 1–7 → +12 h) par famille, sur l'échantillon :

| Famille | Premier | Dernier | Lignes |
|---|---|---|---|
| BENIGN | 2017-07-07 08:59 | 2017-07-07 17:02 | 82 871 |
| Bot | 2017-07-07 10:04 | 2017-07-07 12:59 | 402 |
| PortScan | 2017-07-07 13:05 | 2017-07-07 15:23 | 31 770 |
| DDoS | 2017-07-07 15:56 | 2017-07-07 16:16 | 25 606 |

Verdict sur l'hypothèse AM/PM : **cohérente**. Bot est le matin, PortScan l'après-midi,
DDoS en fin d'après-midi, et BENIGN couvre toute la journée. La correction des heures 1–7 en
après-midi est donc confirmée par l'ordre obtenu.

Split temporel (25 % final) : **train = 105 486**, **test = 35 163**.
Composition :

| Ensemble | BENIGN | Bot | PortScan | DDoS |
|---|---:|---:|---:|---:|
| Train | 68 540 | 402 | 31 770 | 4 774 |
| Test | 14 331 | 0 | 0 | 20 832 |

**Signal d'alerte majeur** : le test temporel ne contient **aucune ligne Bot ni PortScan**.
Les métriques dites « holdout » ne mesurent que la détection de DDoS, famille largement vue à
l'entraînement (4 774 lignes DDoS dans le train).

## 5. Résultats par expérience

### `e1_temporal` — split temporel, seuil 0,5

Matrice de confusion (test) :

| | prédit bénin | prédit attaque |
|---|---:|---:|
| réel bénin | TN = 14 322 | FP = 9 |
| réel attaque | FN = 46 | TP = 20 786 |

| Accuracy | Précision | Rappel | F1 | FPR | ROC-AUC | PR-AUC |
|---:|---:|---:|---:|---:|---:|---:|
| 0,998436 | 0,999567 | 0,997792 | 0,998679 | 0,000628 | 0,999749 | 0,999853 |

Baselines (même split, même seuil) :

| Modèle | Précision | Rappel | F1 | FPR | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Régression logistique | 0,919195 | 0,513297 | 0,658740 | 0,065592 | 0,923652 | 0,888176 |
| Arbre de profondeur 3 | 0,999615 | 0,623416 | 0,767916 | 0,000349 | 0,943983 | 0,946833 |
| RF sans `dst_port` ni `protocol_num` | 0,931153 | 0,984255 | 0,956968 | 0,105785 | 0,953743 | 0,935763 |

Top-5 importances RF complet (`e1_temporal`) :

| Feature | Importance |
|---|---:|
| `bytes` | 0,236097 |
| `mean_pkt_size` | 0,227988 |
| `max_pkt_size` | 0,136015 |
| `stddev_pkt_size` | 0,135871 |
| `duration_ms` | 0,098287 |

`e2_zeroday_portscan`, `e3_zeroday_bot` et `e4_zeroday_ddos` réutilisent le même split et le même
classifieur principal ; leurs sections `random_forest`, `baselines` et `feature_importance` sont donc
identiques à `e1_temporal`. Seule la section `zero_day` change et est reportée ci-dessous.

### `e5_random_seed1..3` — split aléatoire stratifié

| Graine | Accuracy | Précision | Rappel | F1 | FPR | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0,997668 | 0,997644 | 0,996677 | 0,997160 | 0,001641 | 0,999890 | 0,999856 |
| 2 | 0,997611 | 0,997782 | 0,996400 | 0,997090 | 0,001545 | 0,999926 | 0,999906 |
| 3 | 0,997867 | 0,997714 | 0,997092 | 0,997403 | 0,001593 | 0,999958 | 0,999940 |

Baselines en split aléatoire (graine 1, valeurs stables sur les 3 graines) :

| Modèle | Précision | Rappel | F1 | FPR | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Régression logistique | 0,862376 | 0,984285 | 0,919307 | 0,109518 | 0,960499 | 0,891226 |
| Arbre de profondeur 3 | 0,760827 | 0,949810 | 0,844880 | 0,208176 | 0,886216 | 0,755486 |
| RF sans `dst_port` ni `protocol_num` | 0,975648 | 0,990170 | 0,982855 | 0,017231 | 0,997510 | 0,996100 |

Importances moyennes sur les 3 graines (split aléatoire) : `dst_port` ≈ 0,1833, `bytes` ≈ 0,1503,
`mean_pkt_size` ≈ 0,1244, `min_pkt_size` ≈ 0,1172, `stddev_pkt_size` ≈ 0,0988.
Contrairement au split temporel, `dst_port` est la feature dominante en split aléatoire.

## 6. Zero-day (famille masquée de l'entraînement)

Rappel mesuré sur **toutes** les lignes de la famille masquée (train + test, puisque la famille
n'est jamais vue en apprentissage) ; FPR mesuré sur les flux bénins du test.

| Famille masquée | Flux masqués | Rappel RF supervisé | FPR RF | Rappel Isolation Forest | FPR IF |
|---|---:|---:|---:|---:|---:|
| PortScan | 31 770 | 0,000598 | 0,000628 | 0,002298 | 0,216245 |
| Bot | 402 | 0,000000 | 0,000140 | 0,014925 | 0,216245 |
| DDoS | 25 606 | 0,435562 | 0,000628 | 0,636843 | 0,216524 |

Le RF supervisé ne détecte quasiment pas une famille jamais vue (PortScan, Bot). L'Isolation Forest
détecte un peu mieux DDoS mais au prix d'un FPR d'environ 21,6 %. Aucune des deux approches ne
constitue une détection zero-day fiable sur cet échantillon.

## 7. Variabilité (split aléatoire, graines 1–3)

Moyenne ± écart-type (échantillon, n = 3) :

| Métrique | Moyenne ± écart-type |
|---|---|
| Accuracy | 0,997715 ± 0,000134 |
| Précision | 0,997713 ± 0,000069 |
| Rappel | 0,996723 ± 0,000348 |
| F1 | 0,997218 ± 0,000164 |
| FPR | 0,001593 ± 0,000048 |
| ROC-AUC | 0,999925 ± 0,000034 |
| PR-AUC | 0,999900 ± 0,000042 |

## 8. Régénération du modèle de démo

**Avant** (modèle synthétique) : `data_source = synthetic_demo`, `demo = true`, 4 000 lignes,
accuracy de holdout **0,992** ; `predictions.json` : 11 flux, **9 suspects / 2 bénins**.

**Après** (modèle CIC-IDS2017) : `model.joblib` et `train_report.json` recopiés depuis
`e1_temporal` ; `data_source = cic_ids2017:train.csv`, `demo = false`, 140 649 lignes,
accuracy **0,9984**. `predictions.json` : `flow_count = 11`, `suspicious_count = 0`,
`demo = false`, `demo_traffic = true`, seuil 0,5.

Sortie de `python3 tests/check_outputs.py` après le `smoke.sh` final :

```
Artifact check
  - 1 pcap file(s)
  - eve.json events={'alert': 8, 'http': 2, 'anomaly': 2, 'dns': 2, 'flow': 11}, alerts=8
  - flows.csv rows=11
  - model size=10738006 bytes
  - predictions=11 suspicious=0 data_source=cic_ids2017:train.csv
  - flows are synthetic DEMO traffic; model may be real-data trained
OK: all required artifacts are present and coherent
```

Résultat du `smoke.sh` : **OK**. Il réentraîne depuis `data/cic/train.csv` ; la section `evaluation`
obtenue est **strictement égale** à `results/e1_temporal.json` (accuracy 0,9984358558712283,
mêmes matrices et mêmes métriques). Les fichiers `.joblib` ne sont pas identiques octet pour octet
(le bundle contient `trained_at`), mais les métriques et le modèle appris le sont.

Prédictions sur le PCAP synthétique de démo (seuil 0,5) :

| flow_id | 5-tuple | attack_probability | label |
|---|---|---:|---|
| synthetic_demo:0 | 192.168.1.10:49152 → 192.168.1.50:80/TCP | 0,034770 | benign |
| synthetic_demo:1 | 192.168.1.10:49157 → 93.184.216.34:443/TCP | 0,017003 | benign |
| synthetic_demo:10 | 192.168.1.10:49156 → 192.168.1.50:80/TCP | 0,027115 | benign |
| synthetic_demo:2 | 192.168.1.10:0 → 192.168.1.50:0/ICMP | 0,091670 | benign |
| synthetic_demo:3 | 192.168.1.10:5353 → 8.8.8.8:53/UDP | 0,049427 | benign |
| synthetic_demo:4 | 192.168.1.10:49159 → 192.168.1.50:80/TCP | 0,008938 | benign |
| synthetic_demo:5 | 192.168.1.10:49154 → 192.168.1.50:23/TCP | 0,101670 | benign |
| synthetic_demo:6 | 192.168.1.10:49155 → 192.168.1.50:3389/TCP | 0,077598 | benign |
| synthetic_demo:7 | 192.168.1.10:5354 → 8.8.8.8:53/UDP | 0,049427 | benign |
| synthetic_demo:8 | 192.168.1.10:49153 → 192.168.1.50:22/TCP | 0,057770 | benign |
| synthetic_demo:9 | 192.168.1.10:49158 → 93.184.216.34:443/TCP | 0,000000 | benign |

**Décalage de domaine** : l'ancien modèle synthétique avait appris des distributions artificielles et
signalait 9 flux sur 11. Le nouveau modèle a appris des features CICFlowMeter sur du trafic CIC-IDS2017
réel ; les flux de démo sont produits par NFStream sur un PCAP synthétique. Les échelles et les
corrélations entre features ne sont pas les mêmes (ex. `bytes_per_s`, `packets_per_s`, tailles de
paquets). Tous les flux de démo tombent donc sous le seuil, ce qui ne prouve ni une bonne ni une
mauvaise détection : cela montre surtout que le modèle n'est pas calibré pour ce trafic synthétique.

## 9. Modifications de code

- `ai-engine/app/train.py`
  - Correction des horodatages CIC lus en horloge 12 h sans AM/PM : `format="mixed"` puis +12 h
    pour les heures 1–7, avant le tri du split temporel.
  - Lecture CSV avec `encoding_errors="replace"` pour tolérer les octets non UTF-8.
  - Expérience zero-day réécrite pour mesurer le rappel sur **toute** la famille masquée
    (train + test) au lieu du seul test, et FPR sur les bénins du test.
- `ai-engine/app/predict.py`
  - Ajout de `demo_traffic` dans le JSON de sortie (vrai si au moins un `flow_id` commence par
    `synthetic_demo`), y compris dans la branche « aucun flux ».
- `dashboard/app/dashboard.py`
  - Le bandeau d'avertissement s'affiche si `demo` **ou** `demo_traffic` est vrai, avec un texte
    distinguant trafic de démo synthétique et modèle CIC-IDS2017. Les trois vues sont conservées.
- `tests/check_outputs.py`
  - Note informative quand `demo_traffic` est vrai (le test ne devient pas bloquant).
- `tools/build_cic_sample.py` (nouveau)
  - Construction stdlib de l'échantillon vendredi, contrôle des colonnes, échantillonnage
    systématique, comptes par Label et bornes brutes des timestamps.
- `.gitignore`
  - Ajout de `data/cic/raw/` et `data/models/*/` (les dossiers d'expériences restent hors git,
    `results/` est suivi).
- `AGENTS.md`
  - Mise à jour de l'état courant (modèle entraîné sur CIC-IDS2017, métriques temporelles,
    `demo_traffic`) et de la règle de téléchargement.
- `results/*.json` / `results/*.log`
  - Rapports et sorties console des 7 runs.

## 10. Écarts et incidents

- `poc-fixes.patch` était présent mais `git apply --check poc-fixes.patch` a échoué : le commit
  `f472b6b` avait déjà appliqué une partie du patch (`split_frame`, features sans `src_port`,
  métriques, baselines...). Les hunks restants (correction des timestamps, `encoding_errors`,
  zero-day complet) ont été appliqués manuellement dans `train.py`. Aucun conflit non résolu.
- `unzip` absent sur l'hôte : intégrité vérifiée via `zipfile` (stdlib), pas via `unzip -t`.
- Le téléchargement est passé par un miroir non officiel ; aucune empreinte officielle UNB n'a pu
  être comparée.
- Aucun OOM, aucun exit 137, aucune override mémoire.
- `rapport.md` (ancien rapport d'audit) a été supprimé volontairement par le propriétaire du projet ; la suppression est committée dans `fcf2f18`.
- `PROMPT_OPENCODE.md` et `poc-fixes.patch` restent non suivis (non committés).

## 11. Signaux d'alerte

- **ROC-AUC ≈ 1,000** (0,99975 en temporel, 0,99993 en aléatoire), précision et rappel > 0,996.
  Ces valeurs sont atypiques pour de la détection d'intrusion et suggèrent des fuites ou des
  raccourcis (features très discriminantes, familles d'attaque séparables).
- **Le test temporel ne contient qu'une famille d'attaque (DDoS)** : les métriques ne mesurent pas
  la détection de PortScan ou Bot, qui sont pourtant dans le dataset. On ne peut donc pas généraliser
  les 0,998 à l'ensemble des attaques du vendredi.
- **Le RF sans `dst_port`/`protocol_num` chute** (F1 0,957 vs 0,999 ; FPR 0,106 vs 0,0006 en
  temporel) et `dst_port` devient la première importance en split aléatoire : le modèle exploite
  en partie le port de destination comme raccourci.
- **Zero-day très faible** : rappel 0,0006 (PortScan), 0,0000 (Bot), 0,436 (DDoS) pour le RF
  supervisé. L'Isolation Forest a un FPR d'environ 21,6 %. Aucune détection fiable d'inconnu.
- **Aucune feature ne dépasse ~24 %** d'importance, donc pas de domination absolue d'une seule
  feature en temporel ; mais `dst_port` domine en aléatoire.
- Conséquence pour un mémoire : ces résultats décrivent surtout la capacité à reconnaître des
  motifs de DDoS déjà vus sur un échantillon particulier du vendredi, pas une performance générale
  d'IDS ni une capacité zero-day.

## 12. Ce qu'il ne faut PAS affirmer

- Ne pas affirmer une performance sur du **trafic réseau réel** : les tests portent sur des flux
  CICFlowMeter déjà agrégés, pas sur une capture live.
- Ne pas affirmer une **comparaison Suricata / IA / hybride** : les 8 alertes Suricata et les
  prédictions IA du PCAP de démo ne sont pas un benchmark, et le PCAP est synthétique.
- Ne pas utiliser les prédictions sur le **PCAP de démo** (0 suspect / 11) comme preuve de qualité :
  c'est un décalage de domaine assumé, sur un trafic artificiel.
- Ne pas présenter les métriques temporelles comme une évaluation multi-familles : le test ne
  contient que DDoS + BENIGN.
- Ne pas présenter le zero-day comme résolu : les rappels sont proches de zéro, sauf DDoS partiel,
  avec un FPR élevé pour l'Isolation Forest.
- Ne pas affirmer que le dataset est officiel : le ZIP vient d'un miroir Hugging Face non officiel.

## 13. Annexe — sections `evaluation` complètes

### `e1_temporal.json`

```json
{
  "split": "temporal",
  "train_rows": 105486,
  "test_rows": 35163,
  "random_forest": {
    "threshold": 0.5,
    "confusion_matrix": {
      "tn": 14322,
      "fp": 9,
      "fn": 46,
      "tp": 20786
    },
    "precision": 0.9995672036547247,
    "recall": 0.9977918586789555,
    "f1": 0.9986787421625387,
    "fpr": 0.0006280092108017584,
    "roc_auc": 0.9997494250350046,
    "pr_auc": 0.9998531987232013
  },
  "baselines": {
    "logistic_regression": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 13391,
        "fp": 940,
        "fn": 10139,
        "tp": 10693
      },
      "precision": 0.9191953924181209,
      "recall": 0.5132968509984639,
      "f1": 0.6587401817341753,
      "fpr": 0.06559207312818366,
      "roc_auc": 0.9236518773793526,
      "pr_auc": 0.8881763777106932
    },
    "decision_tree_depth3": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 14326,
        "fp": 5,
        "fn": 7845,
        "tp": 12987
      },
      "precision": 0.9996151477832512,
      "recall": 0.6234158986175116,
      "f1": 0.7679162724692525,
      "fpr": 0.0003488940060009769,
      "roc_auc": 0.943982642228437,
      "pr_auc": 0.9468326070334425
    },
    "rf_without_dst_port_and_protocol": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 12815,
        "fp": 1516,
        "fn": 328,
        "tp": 20504
      },
      "precision": 0.9311534968210717,
      "recall": 0.9842549923195084,
      "f1": 0.9569681695136749,
      "fpr": 0.10578466261949619,
      "roc_auc": 0.9537432518352308,
      "pr_auc": 0.935762528266973
    }
  },
  "feature_importance": {
    "bytes": 0.23609676825990392,
    "mean_pkt_size": 0.22798768050333929,
    "max_pkt_size": 0.13601522667083127,
    "stddev_pkt_size": 0.13587130888776808,
    "duration_ms": 0.09828667659027956,
    "bytes_per_s": 0.04306115852119021,
    "packets_per_s": 0.040545609647350836,
    "min_pkt_size": 0.03259023584629436,
    "dst_port": 0.02459689756086171,
    "packets": 0.023147215895702355,
    "protocol_num": 0.0018012216164784863
  }
}
```

### `e2_zeroday_portscan.json`

```json
{
  "split": "temporal",
  "train_rows": 105486,
  "test_rows": 35163,
  "random_forest": {
    "threshold": 0.5,
    "confusion_matrix": {
      "tn": 14322,
      "fp": 9,
      "fn": 46,
      "tp": 20786
    },
    "precision": 0.9995672036547247,
    "recall": 0.9977918586789555,
    "f1": 0.9986787421625387,
    "fpr": 0.0006280092108017584,
    "roc_auc": 0.9997494250350046,
    "pr_auc": 0.9998531987232013
  },
  "baselines": {
    "logistic_regression": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 13391,
        "fp": 940,
        "fn": 10139,
        "tp": 10693
      },
      "precision": 0.9191953924181209,
      "recall": 0.5132968509984639,
      "f1": 0.6587401817341753,
      "fpr": 0.06559207312818366,
      "roc_auc": 0.9236518773793526,
      "pr_auc": 0.8881763777106932
    },
    "decision_tree_depth3": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 14326,
        "fp": 5,
        "fn": 7845,
        "tp": 12987
      },
      "precision": 0.9996151477832512,
      "recall": 0.6234158986175116,
      "f1": 0.7679162724692525,
      "fpr": 0.0003488940060009769,
      "roc_auc": 0.943982642228437,
      "pr_auc": 0.9468326070334425
    },
    "rf_without_dst_port_and_protocol": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 12815,
        "fp": 1516,
        "fn": 328,
        "tp": 20504
      },
      "precision": 0.9311534968210717,
      "recall": 0.9842549923195084,
      "f1": 0.9569681695136749,
      "fpr": 0.10578466261949619,
      "roc_auc": 0.9537432518352308,
      "pr_auc": 0.935762528266973
    }
  },
  "feature_importance": {
    "bytes": 0.23609676825990392,
    "mean_pkt_size": 0.22798768050333929,
    "max_pkt_size": 0.13601522667083127,
    "stddev_pkt_size": 0.13587130888776808,
    "duration_ms": 0.09828667659027956,
    "bytes_per_s": 0.04306115852119021,
    "packets_per_s": 0.040545609647350836,
    "min_pkt_size": 0.03259023584629436,
    "dst_port": 0.02459689756086171,
    "packets": 0.023147215895702355,
    "protocol_num": 0.0018012216164784863
  },
  "zero_day": {
    "hidden_family": "PortScan",
    "hidden_family_flows": 31770,
    "benign_test_flows": 14331,
    "random_forest_supervised": {
      "recall_on_hidden_family": 0.000598048473402581,
      "fpr_on_benign": 0.0006280092108017584
    },
    "isolation_forest_benign_only": {
      "recall_on_hidden_family": 0.0022977651872836007,
      "fpr_on_benign": 0.21624450491940547
    }
  }
}
```

### `e3_zeroday_bot.json`

```json
{
  "split": "temporal",
  "train_rows": 105486,
  "test_rows": 35163,
  "random_forest": {
    "threshold": 0.5,
    "confusion_matrix": {
      "tn": 14322,
      "fp": 9,
      "fn": 46,
      "tp": 20786
    },
    "precision": 0.9995672036547247,
    "recall": 0.9977918586789555,
    "f1": 0.9986787421625387,
    "fpr": 0.0006280092108017584,
    "roc_auc": 0.9997494250350046,
    "pr_auc": 0.9998531987232013
  },
  "baselines": {
    "logistic_regression": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 13391,
        "fp": 940,
        "fn": 10139,
        "tp": 10693
      },
      "precision": 0.9191953924181209,
      "recall": 0.5132968509984639,
      "f1": 0.6587401817341753,
      "fpr": 0.06559207312818366,
      "roc_auc": 0.9236518773793526,
      "pr_auc": 0.8881763777106932
    },
    "decision_tree_depth3": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 14326,
        "fp": 5,
        "fn": 7845,
        "tp": 12987
      },
      "precision": 0.9996151477832512,
      "recall": 0.6234158986175116,
      "f1": 0.7679162724692525,
      "fpr": 0.0003488940060009769,
      "roc_auc": 0.943982642228437,
      "pr_auc": 0.9468326070334425
    },
    "rf_without_dst_port_and_protocol": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 12815,
        "fp": 1516,
        "fn": 328,
        "tp": 20504
      },
      "precision": 0.9311534968210717,
      "recall": 0.9842549923195084,
      "f1": 0.9569681695136749,
      "fpr": 0.10578466261949619,
      "roc_auc": 0.9537432518352308,
      "pr_auc": 0.935762528266973
    }
  },
  "feature_importance": {
    "bytes": 0.23609676825990392,
    "mean_pkt_size": 0.22798768050333929,
    "max_pkt_size": 0.13601522667083127,
    "stddev_pkt_size": 0.13587130888776808,
    "duration_ms": 0.09828667659027956,
    "bytes_per_s": 0.04306115852119021,
    "packets_per_s": 0.040545609647350836,
    "min_pkt_size": 0.03259023584629436,
    "dst_port": 0.02459689756086171,
    "packets": 0.023147215895702355,
    "protocol_num": 0.0018012216164784863
  },
  "zero_day": {
    "hidden_family": "Bot",
    "hidden_family_flows": 402,
    "benign_test_flows": 14331,
    "random_forest_supervised": {
      "recall_on_hidden_family": 0.0,
      "fpr_on_benign": 0.00013955760240039075
    },
    "isolation_forest_benign_only": {
      "recall_on_hidden_family": 0.014925373134328358,
      "fpr_on_benign": 0.21624450491940547
    }
  }
}
```

### `e4_zeroday_ddos.json`

```json
{
  "split": "temporal",
  "train_rows": 105486,
  "test_rows": 35163,
  "random_forest": {
    "threshold": 0.5,
    "confusion_matrix": {
      "tn": 14322,
      "fp": 9,
      "fn": 46,
      "tp": 20786
    },
    "precision": 0.9995672036547247,
    "recall": 0.9977918586789555,
    "f1": 0.9986787421625387,
    "fpr": 0.0006280092108017584,
    "roc_auc": 0.9997494250350046,
    "pr_auc": 0.9998531987232013
  },
  "baselines": {
    "logistic_regression": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 13391,
        "fp": 940,
        "fn": 10139,
        "tp": 10693
      },
      "precision": 0.9191953924181209,
      "recall": 0.5132968509984639,
      "f1": 0.6587401817341753,
      "fpr": 0.06559207312818366,
      "roc_auc": 0.9236518773793526,
      "pr_auc": 0.8881763777106932
    },
    "decision_tree_depth3": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 14326,
        "fp": 5,
        "fn": 7845,
        "tp": 12987
      },
      "precision": 0.9996151477832512,
      "recall": 0.6234158986175116,
      "f1": 0.7679162724692525,
      "fpr": 0.0003488940060009769,
      "roc_auc": 0.943982642228437,
      "pr_auc": 0.9468326070334425
    },
    "rf_without_dst_port_and_protocol": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 12815,
        "fp": 1516,
        "fn": 328,
        "tp": 20504
      },
      "precision": 0.9311534968210717,
      "recall": 0.9842549923195084,
      "f1": 0.9569681695136749,
      "fpr": 0.10578466261949619,
      "roc_auc": 0.9537432518352308,
      "pr_auc": 0.935762528266973
    }
  },
  "feature_importance": {
    "bytes": 0.23609676825990392,
    "mean_pkt_size": 0.22798768050333929,
    "max_pkt_size": 0.13601522667083127,
    "stddev_pkt_size": 0.13587130888776808,
    "duration_ms": 0.09828667659027956,
    "bytes_per_s": 0.04306115852119021,
    "packets_per_s": 0.040545609647350836,
    "min_pkt_size": 0.03259023584629436,
    "dst_port": 0.02459689756086171,
    "packets": 0.023147215895702355,
    "protocol_num": 0.0018012216164784863
  },
  "zero_day": {
    "hidden_family": "DDoS",
    "hidden_family_flows": 25606,
    "benign_test_flows": 14331,
    "random_forest_supervised": {
      "recall_on_hidden_family": 0.4355619776614856,
      "fpr_on_benign": 0.0006280092108017584
    },
    "isolation_forest_benign_only": {
      "recall_on_hidden_family": 0.6368429274388815,
      "fpr_on_benign": 0.21652362012420626
    }
  }
}
```

### `e5_random_seed1.json`

```json
{
  "split": "random",
  "train_rows": 105486,
  "test_rows": 35163,
  "random_forest": {
    "threshold": 0.5,
    "confusion_matrix": {
      "tn": 20684,
      "fp": 34,
      "fn": 48,
      "tp": 14397
    },
    "precision": 0.9976439609174693,
    "recall": 0.9966770508826583,
    "f1": 0.9971602715057486,
    "fpr": 0.0016410850468191911,
    "roc_auc": 0.9998899861867907,
    "pr_auc": 0.9998558066982484
  },
  "baselines": {
    "logistic_regression": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 18449,
        "fp": 2269,
        "fn": 227,
        "tp": 14218
      },
      "precision": 0.8623764177837083,
      "recall": 0.9842852197992384,
      "f1": 0.9193068666752877,
      "fpr": 0.10951829327155131,
      "roc_auc": 0.9604986238081933,
      "pr_auc": 0.8912261166081185
    },
    "decision_tree_depth3": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 16405,
        "fp": 4313,
        "fn": 725,
        "tp": 13720
      },
      "precision": 0.7608273720401486,
      "recall": 0.949809622706819,
      "f1": 0.8448796108134738,
      "fpr": 0.20817646490974032,
      "roc_auc": 0.8862163775629696,
      "pr_auc": 0.7554859115049661
    },
    "rf_without_dst_port_and_protocol": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 20361,
        "fp": 357,
        "fn": 142,
        "tp": 14303
      },
      "precision": 0.9756480218281037,
      "recall": 0.9901696088611976,
      "f1": 0.9828551795224189,
      "fpr": 0.017231392991601507,
      "roc_auc": 0.997510152236008,
      "pr_auc": 0.9961001248960634
    }
  },
  "feature_importance": {
    "dst_port": 0.1831584401312031,
    "bytes": 0.15089920996466158,
    "mean_pkt_size": 0.12020931617139784,
    "min_pkt_size": 0.10879341424724044,
    "stddev_pkt_size": 0.10620105465560463,
    "max_pkt_size": 0.07656072419898254,
    "protocol_num": 0.07612208969694317,
    "packets": 0.07369567800415372,
    "bytes_per_s": 0.0578935997694871,
    "duration_ms": 0.029615807822478638,
    "packets_per_s": 0.016850665337847282
  }
}
```

### `e5_random_seed2.json`

```json
{
  "split": "random",
  "train_rows": 105486,
  "test_rows": 35163,
  "random_forest": {
    "threshold": 0.5,
    "confusion_matrix": {
      "tn": 20686,
      "fp": 32,
      "fn": 52,
      "tp": 14393
    },
    "precision": 0.9977816291161179,
    "recall": 0.9964001384562132,
    "f1": 0.9970904052649809,
    "fpr": 0.0015445506323004152,
    "roc_auc": 0.9999261322937156,
    "pr_auc": 0.9999057023260548
  },
  "baselines": {
    "logistic_regression": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 18294,
        "fp": 2424,
        "fn": 238,
        "tp": 14207
      },
      "precision": 0.8542480909145571,
      "recall": 0.9835237106265143,
      "f1": 0.9143390397734587,
      "fpr": 0.11699971039675644,
      "roc_auc": 0.9600368441352803,
      "pr_auc": 0.8953971530064858
    },
    "decision_tree_depth3": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 16312,
        "fp": 4406,
        "fn": 727,
        "tp": 13718
      },
      "precision": 0.7568969322445376,
      "recall": 0.9496711664935964,
      "f1": 0.8423961435721085,
      "fpr": 0.2126653151848634,
      "roc_auc": 0.8838712261651636,
      "pr_auc": 0.7516490575566281
    },
    "rf_without_dst_port_and_protocol": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 20377,
        "fp": 341,
        "fn": 152,
        "tp": 14293
      },
      "precision": 0.9766981003143365,
      "recall": 0.9894773277950848,
      "f1": 0.9830461845317927,
      "fpr": 0.016459117675451298,
      "roc_auc": 0.9977814376650822,
      "pr_auc": 0.996601772610799
    }
  },
  "feature_importance": {
    "dst_port": 0.19684417040847738,
    "bytes": 0.1520118801981571,
    "mean_pkt_size": 0.12830095545838868,
    "min_pkt_size": 0.1187712244941751,
    "stddev_pkt_size": 0.09483210276415185,
    "packets": 0.0843186846639075,
    "max_pkt_size": 0.06628313009624891,
    "bytes_per_s": 0.05701510547715223,
    "protocol_num": 0.055536788755979234,
    "duration_ms": 0.02539168859602961,
    "packets_per_s": 0.020694269087332403
  }
}
```

### `e5_random_seed3.json`

```json
{
  "split": "random",
  "train_rows": 105486,
  "test_rows": 35163,
  "random_forest": {
    "threshold": 0.5,
    "confusion_matrix": {
      "tn": 20685,
      "fp": 33,
      "fn": 42,
      "tp": 14403
    },
    "precision": 0.9977140482128013,
    "recall": 0.9970924195223261,
    "f1": 0.9974031370104913,
    "fpr": 0.001592817839559803,
    "roc_auc": 0.9999575034723487,
    "pr_auc": 0.9999397178576964
  },
  "baselines": {
    "logistic_regression": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 18385,
        "fp": 2333,
        "fn": 238,
        "tp": 14207
      },
      "precision": 0.8589480048367594,
      "recall": 0.9835237106265143,
      "f1": 0.917024366629014,
      "fpr": 0.11260739453615214,
      "roc_auc": 0.9588720657038153,
      "pr_auc": 0.8902410423493561
    },
    "decision_tree_depth3": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 16302,
        "fp": 4416,
        "fn": 708,
        "tp": 13737
      },
      "precision": 0.7567344240621385,
      "recall": 0.9509865005192109,
      "f1": 0.8428124424811338,
      "fpr": 0.2131479872574573,
      "roc_auc": 0.883962045033956,
      "pr_auc": 0.7516885876032362
    },
    "rf_without_dst_port_and_protocol": {
      "threshold": 0.5,
      "confusion_matrix": {
        "tn": 20390,
        "fp": 328,
        "fn": 155,
        "tp": 14290
      },
      "precision": 0.9775619099740046,
      "recall": 0.9892696434752509,
      "f1": 0.9833809310807555,
      "fpr": 0.015831643981079255,
      "roc_auc": 0.9977357667624291,
      "pr_auc": 0.996338300326887
    }
  },
  "feature_importance": {
    "dst_port": 0.1698674366247957,
    "bytes": 0.14783839034877483,
    "mean_pkt_size": 0.12470503142758316,
    "min_pkt_size": 0.12414659493501048,
    "stddev_pkt_size": 0.09540266201636352,
    "packets": 0.0811940504273271,
    "max_pkt_size": 0.07385884031418763,
    "protocol_num": 0.07103184081864324,
    "bytes_per_s": 0.060646739269401624,
    "duration_ms": 0.029760877569303974,
    "packets_per_s": 0.02154753624860862
  }
}
```

