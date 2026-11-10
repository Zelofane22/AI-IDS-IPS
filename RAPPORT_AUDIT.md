# Rapport d'audit — `RAPPORT_REEL.md` §4, vérifiabilité, démo réelle

Branche : `audit-fixes`, créée depuis `origin/main` (`bf59197`, PR #2 et #3 déjà fusionnées).
Docker : `Docker version 29.9.3, build 5457199`. Tous les chiffres ci-dessous viennent de
commandes exécutées pendant cet audit. Les fichiers d'audit locaux, ignorés par git, sont dans
`data/models/audit/`.

## 1. Résumé

- **Sujet 1, fait.** L'écart de 17 flux ne venait pas des étiquettes (0 incohérence
  famille/label). Il cachait un **vrai bug** dans `train.py` : 106 horodatages devenaient `NaT`
  et passaient dans le test. Le bug est corrigé (commit séparé + test).
- **Les métriques du split temporel changent** : rappel 0,384 → **0,398**, FPR 0,0053 → **0,0056**.
  Le modèle déployé ne change pas (prédictions identiques), donc §5 reste valable.
- **Sujet 2, fait.** `results/nfstream_temporal.json`, `.log`, `nfstream_dataset_stats.json` et
  `tests/check_results.py` sont committés. Le contrôle passe.
- **Sujet 3, fait.** Empreinte de l'extrait relevée, procédure de sauvegarde écrite, `smoke.sh` OK
  avec l'extrait (139,85 s) et sans (132,12 s), dashboard sans exception dans les deux cas.

## 2. Sujet 1 — incohérence de 17 flux (§4)

**Méthode.** Le split a été recalculé avec les fonctions mêmes de `train.py`
(`load_training_frame`, `split_frame("temporal", 42)`) dans l'image `ai-engine`. Le run documenté
a aussi été rejoué : `train.py --data /data/cic/train_nfstream.csv --final-fit all`, sortie dans
`/data/models/audit/prefix/`, modèle déployé non modifié. Sa section `evaluation` est
**identique** à celle de `data/models/train_report.json` d'origine (comparaison `==` en Python : `True`).

**Tableau croisé `attack_family` × `label`, code d'origine :**

| Partie | Famille | label 0 | label 1 |
|---|---|---:|---:|
| train | BENIGN | 54 702 | 0 |
| train | Bot | 0 | 306 |
| train | PortScan | 0 | 37 175 |
| test | BENIGN | 13 803 | 0 |
| test | DDoS | 0 | 14 903 |
| test | PortScan | 0 | 2 022 |

Lignes `BENIGN` avec `label == 1`, ou l'inverse : **0**. Le CSV brut ne contient aucune incohérence
entre `attack_family` et `label` non plus (0 sur 122 911).

**Lecture correcte.** La matrice (13 730 + 73 = 13 803 négatifs) était juste. La composition
publiée (BENIGN 13 820, PortScan 2 005) venait d'un script de contrôle lancé sur l'hôte, qui triait
sur `first_seen_ms` et non sur la colonne `timestamp` utilisée par `train.py`. La règle « mixte →
attaque », la casse et `resolve_labels` ne sont pas en cause.

**Cause de l'écart : bug de parsing.**
- `ai-engine/app/train.py:113` (avant correction) :
  `pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)`. Pandas 2.2.3 déduit le format de
  la première ligne (`2017-07-07 11:59:50.315000+00:00`, avec fraction de seconde). Les horodatages
  sans fraction (`2017-07-07 12:16:17+00:00`) deviennent alors `NaT`.
- Ces horodatages sont écrits par `tools/label_nfstream_flows.py:145` pour les 106 flux dont
  `first_seen_ms` est un multiple de 1000 (vérifié : 106 lignes, 0 exception).
- `ai-engine/app/train.py:175` (avant correction) : `sort_values` place les `NaT` **en dernier**.
  Ces 106 flux du matin (BENIGN 68, PortScan 28, DDoS 10) tombaient donc dans le test.
- Reproduction minimale dans l'image : `pd.to_datetime([...315000+00:00, ...17+00:00],
  errors="coerce", utc=True)` → `[Timestamp(...), NaT]`.

Exemples (3 lignes `NaT` du test, flux CIC publics) :

| flow_id | src | dst | proto | first_seen_ms | famille | timestamp écrit |
|---|---|---|---|---:|---|---|
| Friday-WorkingHours:54830 | 192.168.10.5:53779 | 192.168.10.3:53 | UDP | 1499429777000 | BENIGN | 2017-07-07 12:16:17+00:00 |
| Friday-WorkingHours:57169 | 192.168.10.3:61434 | 192.168.10.1:53 | UDP | 1499430130000 | BENIGN | 2017-07-07 12:22:10+00:00 |
| Friday-WorkingHours:75808 | 192.168.10.9:1678 | 90.85.36.9:443 | TCP | 1499431609000 | BENIGN | 2017-07-07 12:46:49+00:00 |

**Décision et correction** (commit `4bf8df9`, séparé) :
- `train.py:117` parse désormais avec `format="ISO8601"`.
- `train.py` (split temporel) affiche un avertissement s'il reste des `NaT`.
- Test : `tests/test_train_timestamps.py` (exécuté dans l'image `ai-engine`).
  - Sur l'image d'**avant** la correction, il échoue (`2 timestamp(s) parsed as NaT`, test = lignes `[1, 3]`).
  - **Après** la correction : `OK: all timestamps parsed; temporal test = latest rows only`.

**Tableau croisé après correction :** train = BENIGN 54 685, PortScan 37 192, Bot 306 ;
test = BENIGN 13 820, DDoS 14 903, PortScan 2 005. NaT : 0. Les familles sont toutes cohérentes
avec le label (0 incohérence).

**Impact sur les métriques** (split temporel, seuil 0,5) :

| Métrique | Avant | Après |
|---|---:|---:|
| Matrice tn / fp / fn / tp | 13 730 / 73 / 10 418 / 6 507 | 13 742 / 78 / 10 177 / 6 731 |
| Accuracy | 0,659 | 0,666 |
| Précision | 0,988906 | 0,988545 |
| Rappel | 0,384461 | 0,398096 |
| F1 | 0,553669 | 0,567610 |
| FPR | 0,005289 | 0,005644 |
| ROC-AUC | 0,989687 | 0,989844 |
| PR-AUC | 0,987753 | 0,988090 |
| RF sans port : rappel / FPR / AUC | 0,363309 / 0,006303 / 0,990449 | 0,346108 / 0,006151 / 0,988972 |
| Régression logistique : rappel / AUC | 0,118641 / 0,829763 | 0,117696 / 0,830201 |
| Arbre profondeur 3 : rappel / AUC | 0,119527 / 0,557194 | 0,118642 / 0,556694 |

**Modèle déployé.** Avec `--final-fit all`, le modèle est réentraîné sur toutes les lignes, quel
que soit l'ordre. Comparé au modèle déployé d'origine sur le `flows.csv` courant : médianes
identiques, écart maximal de probabilité **0,0**, 4 050 suspects dans les deux cas. Les résultats
de §5 (extrait réel) ne changent pas.

**Mises à jour :** `RAPPORT_REEL.md` §4 (tableau, note de correction avec les anciennes valeurs,
« rappel 0,38 » → « 0,40 ») et `AGENTS.md` (0.384/0.0053 → 0.398/0.0056). Le grep
`0.384|0,384|0.0053|0,0053` ne trouve plus que les anciennes valeurs, citées volontairement dans la
note de correction de §4 et dans ce rapport.

## 3. Sujet 2 — section 4 vérifiable depuis le dépôt

**Régénération.** `docker compose run --rm --no-deps --entrypoint python ai-engine
/app/app/train.py --data /data/cic/train_nfstream.csv --out /data/models/audit/fixed/model.joblib
--final-fit all`, avec les mêmes arguments que `entrypoint.sh` et le code corrigé.
- Comparaison avec le run d'origine : la section `evaluation` du code d'origine rejoué
  (`audit/prefix`) est identique à `data/models/train_report.json`.
- Celle du code corrigé diffère, comme attendu (section 2) : c'est elle qui est publiée.

**Fichiers ajoutés (committés) :**
- `results/nfstream_temporal.json` : commande, commit du code (`4bf8df9`), `data_source`, `rows`,
  `accuracy` et la section `evaluation` complète (split, matrices, baselines, importances, `final_fit`).
- `results/nfstream_temporal.log` : commande et sortie console.
- `results/nfstream_dataset_stats.json` : **copie** de `data/cic/train_nfstream.stats.json`
  (non recalculée). Contient les familles avant et après échantillonnage, les exclus (8 425), les
  flux sans correspondance (1 027), les mixtes (24 691), k = 4 et les 122 911 lignes.
- `tests/check_results.py` (bibliothèque standard uniquement).
- `RAPPORT_REEL.md` §4 : ligne « Source des chiffres : `results/nfstream_temporal.json` ».

**Sortie de `python3 tests/check_results.py`** (code 0) :

```
results/nfstream_temporal.json: split=temporal train_rows=92183 test_rows=30728
  random_forest: tn=13742 fp=78 fn=10177 tp=6731 sum=30728 precision=0.988545 recall=0.398096 f1=0.567610 fpr=0.005644
  baselines.logistic_regression: tn=13730 fp=90 fn=14918 tp=1990 sum=30728 precision=0.956731 recall=0.117696 f1=0.209606 fpr=0.006512
  baselines.decision_tree_depth3: tn=13698 fp=122 fn=14902 tp=2006 sum=30728 precision=0.942669 recall=0.118642 f1=0.210759 fpr=0.008828
  baselines.rf_without_dst_port_and_protocol: tn=13735 fp=85 fn=11056 tp=5852 sum=30728 precision=0.985683 recall=0.346108 f1=0.512322 fpr=0.006151
OK: matrices sum to test_rows; precision/recall/F1/FPR match (tol 1e-9)
```

Contrôle négatif : sur une copie où `fp` est augmenté de 17, le script échoue (code 1 ; somme
30 745 ≠ 30 728, précision et FPR divergents).

## 4. Sujet 3 — reproductibilité de la démo réelle

**Extrait** `data/pcaps/cic_friday_extract.pcap` (non committé) :

| | Valeur |
|---|---|
| SHA-256 | `5120fb2f88e3c237d4c6c2532676cae0a567c56c23438e0451294d86d0edcba6` |
| Taille | 33 278 413 octets |
| Paquets | 56 517 (compte bibliothèque standard via `tools/slice_pcap.py`, linktype 1) |
| Plage UTC | 2017-07-07 13:36:00.145 → 19:00:19.979 |

Un nouveau découpage depuis le PCAP complet donne le **même SHA-256** (55,06 s). Ajouté à
`RAPPORT_REEL.md` §3, plus une section 9 « Sauvegarde pour la soutenance ».

**Avec l'extrait** (`bash tests/smoke.sh`, code 0) :
- Durée : **139,85 s** (`/usr/bin/time`, user 2,87 s, sys 2,07 s).
- 2 PCAP, 9 règles Suricata chargées, 726 alertes, 6 996 flux.
- 4 050 suspects, dont 4 047 dans l'extrait et 3 dans la PCAP synthétique.
- L'entraînement affiche `recall=0.398 fpr=0.0056`.
- Rendu du dashboard (`streamlit.testing` `AppTest`, image dashboard, mêmes montages) :
  - exceptions `[]`, sélecteur `Toutes / cic_friday_extract / synthetic_demo` ;
  - avertissement « synthétique », info « Extrait réel » ;
  - métriques 6 996 flux / 726 alertes / 4 050 suspects / **154 priorité haute**.

**Sans l'extrait** (déplacé hors de `data/pcaps/`, puis remis en place ; hash revérifié) :
`smoke.sh` OK (code 0) en **132,12 s**.
- 1 PCAP, 11 flux, 8 alertes, 3 suspects. Aucune erreur dans les journaux.
- Dashboard : exceptions `[]`, pas de sélecteur (une seule capture), avertissement « synthétique ».
- Métriques : 11 flux / 8 alertes / 3 suspects / 3 priorité haute.

Le pipeline se dégrade donc proprement : rien ne plante.

**État laissé.** `smoke.sh` supprime et réentraîne `model.joblib`. L'original a été sauvegardé
(`data/models/audit/original/`) puis remis en place : SHA-256 `6e991c63…`. Le pipeline a ensuite
été relancé avec l'extrait, et `check_outputs.py` passe. Le fichier réentraîné avait un autre hash
(`a553e269…`) : métriques embarquées différentes et horodatage d'entraînement, alors que les
prédictions sont identiques (section 2).

## 5. Incidents et écarts

- La composition publiée au départ dans §4 venait d'un script hôte non aligné sur `train.py` :
  c'était mon erreur, désormais corrigée.
- `docker compose run` a rejoué l'entraînement avec l'image reconstruite. Le run « avant
  correction » a été fait **avant** la reconstruction de l'image ; le test de régression a tourné
  sur l'ancienne image (échec attendu), puis sur la nouvelle (succès).
- Le premier contrôle négatif de `check_results.py` affichait `exit=0` à cause d'un `| tail` dans
  la commande. Relancé sans pipe : code 1.
- **Non vérifié par exécution** : le repli de `entrypoint.sh` sur le CSV CICFlowMeter quand
  `train_nfstream.csv` est absent (`RAPPORT_REEL.md` §9, point 3). Cette affirmation repose sur la
  lecture du code, pas sur un test.
- Le premier commit (`3d69732`) aligne la composition de §4 sur le split bogué (13 803). Le commit
  suivant corrige le bug, et le commit de documentation `b1849b7` remet 13 820, qui correspond
  désormais au split corrigé. L'historique est conservé tel quel.

## 6. Étapes non terminées

Aucune. La PR est ouverte vers `main` mais n'est pas fusionnée : la revue revient au propriétaire.
