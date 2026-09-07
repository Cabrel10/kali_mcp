# Brief formel — Bug Bounty Copilot

**Statut :** proposition de cadrage, soumise à validation humaine  
**Version :** 0.1  
**Date :** 2026-08-06  
**Portée de ce document :** exigences de sécurité, architecture fonctionnelle et critères d'acceptation. Ce document n'autorise aucune exécution sur une cible externe.

## 1. Décision de sécurité fondamentale

Le Bug Bounty Copilot est un assistant d'analyse et de préparation. Il n'est pas un agent de pentest autonome.

Les règles suivantes sont non négociables :

1. **Aucune cible externe sans scope exact, allowlist explicite, référence d'autorisation valide et approbation humaine.**
2. **Aucune exploitation automatique.** Les modules d'exploitation, post-exploitation, credential attack, persistence, lateral movement, destructive testing et denial of service restent désactivés au niveau de la gateway.
3. Une instruction du modèle, une recommandation d'outil, un résultat positif ou un paiement ne constitue jamais une autorisation.
4. Toute ambiguïté de scope, toute donnée invalide, toute expiration ou tout échec de contrôle produit un arrêt **fail-closed**.
5. Une tâche en arrière-plan doit être annulée dès que son autorisation expire, que le scope change ou qu'un kill switch est activé.
6. Aucun mécanisme de proxy, rotation d'identité ou « stealth » ne doit être utilisé pour contourner un WAF, un rate limit, un blocage ou les règles d'un programme.
7. Le présent brief doit être validé par un humain avant toute implémentation d'orchestration. Une seconde approbation est requise avant toute campagne réelle.

## 2. Objectif du produit

Le Copilot doit aider un chercheur autorisé à :

- formaliser et vérifier le périmètre d'un programme ;
- préparer un plan de reconnaissance proportionné ;
- exécuter, après approbation, des contrôles bornés et non destructifs ;
- agréger les résultats de plusieurs outils ;
- dédupliquer et réduire les faux positifs ;
- conserver des preuves reproductibles et minimales ;
- produire un rapport lisible pour HackerOne, Bugcrowd ou Intigriti ;
- mémoriser l'état d'une campagne sans réutiliser une autorisation expirée.

Le Copilot ne doit pas :

- choisir seul une cible ;
- élargir le scope par inférence DNS, wildcard implicite, redirection ou relation de propriété supposée ;
- transformer automatiquement une détection en exploitation ;
- contourner une défense, un quota ou une restriction du programme ;
- soumettre automatiquement un rapport à une plateforme ;
- stocker des secrets, tokens, cookies ou données personnelles non nécessaires.

## 3. Modèle d'autorisation et de scope

### 3.1 Campaign Authorization Record

Chaque campagne doit posséder un enregistrement signé ou immuable contenant au minimum :

```json
{
  "campaign_id": "uuid",
  "program_platform": "hackerone|bugcrowd|intigriti|private",
  "program_reference": "URL-or-contract-reference",
  "authorization_reference": "program-policy-or-SOW-id",
  "approved_by": "human-identity",
  "approved_at": "RFC3339 timestamp",
  "valid_from": "RFC3339 timestamp",
  "valid_until": "RFC3339 timestamp",
  "allowed_assets": [],
  "excluded_assets": [],
  "allowed_methods": [],
  "forbidden_methods": [],
  "rate_limits": {},
  "data_handling": {},
  "emergency_contact": "contact-reference",
  "status": "draft|approved|paused|revoked|expired"
}
```

Une campagne `draft`, `paused`, `revoked` ou `expired` ne peut générer aucun trafic externe.

### 3.2 Allowlist exacte

L'allowlist doit être typée et canonique :

- hôte DNS exact ;
- wildcard uniquement si le texte du programme l'autorise explicitement ;
- URL avec schéma, hôte, port et préfixe de chemin, si le scope est limité à une application ;
- adresse IP ou CIDR explicitement autorisé ;
- identifiant d'application mobile ou de dépôt, sans le convertir implicitement en cible réseau.

Règles de résolution :

- normaliser casse, point terminal DNS, IDN/punycode et ports par défaut ;
- vérifier la cible **avant chaque requête**, pas seulement au début du workflow ;
- revalider après chaque redirection ;
- refuser les redirections vers un autre hôte, une autre IP, un schéma non autorisé ou une ressource interne ;
- prévenir DNS rebinding en liant les résolutions autorisées à la tâche et en revalidant les adresses ;
- traiter les CDN, SaaS tiers et domaines apparentés comme hors scope sauf inclusion explicite ;
- appliquer les exclusions avant les inclusions ; une exclusion gagne toujours.

### 3.3 Portée des approbations humaines

Une approbation active doit être :

- à usage unique ;
- liée à `campaign_id`, outil, cible canonique, méthode, paramètres bornés et durée ;
- attribuée à une identité humaine auditée ;
- de courte durée ;
- non transférable et non rejouable ;
- consommée avant le démarrage du sous-processus ;
- revalidée au passage d'une phase à une autre.

Une approbation globale du type « scan tout » est invalide.

## 4. Classification des activités et gates

Le terme « passif » est réservé aux opérations qui ne contactent pas la cible. Une requête DNS, HTTP ou TCP vers un actif est une activité réseau, même si elle est peu intrusive.

| Niveau | Exemples | Exigence |
|---|---|---|
| L0 — hors ligne | import du scope, parsing, corrélation, déduplication, rédaction | campagne créée ; aucun trafic |
| L1 — source tierce | lecture de sources publiques autorisées, archives, CT logs | scope validé ; règles de la source respectées |
| L2 — actif faible impact | résolution DNS, requête HTTP, crawl borné, détection Nuclei non intrusive | campagne approuvée + approbation humaine liée à la tâche |
| L3 — validation contrôlée | reproduction minimale d'un finding avec requêtes prédéfinies | approbation humaine distincte par finding |
| L4 — exploitation | extraction, modification, auth bypass, shell, pivot, brute force | désactivé ; hors périmètre du Copilot |
| L5 — destructif | DoS, suppression, corruption, persistance, exfiltration | interdit sans exception |

### Gates obligatoires

1. **Gate A — import :** le programme, ses règles et ses exclusions sont capturés.
2. **Gate B — normalisation :** la machine produit la liste canonique des actifs ; un humain la valide.
3. **Gate C — plan :** outils, options, volumes, concurrence et durée sont présentés avant exécution.
4. **Gate D — lancement :** un token lié à la tâche est consommé.
5. **Gate E — promotion :** un résultat de détection ne passe pas en validation sans nouvelle approbation.
6. **Gate F — rapport :** les preuves sont relues et les données sensibles expurgées.
7. **Gate G — soumission :** l'humain décide seul de soumettre ou non.

## 5. Pipeline proposé

### 5.1 Phase 0 — préparation hors ligne

- importer les règles du programme ;
- extraire inclusions, exclusions, fenêtres horaires, limites de débit et méthodes interdites ;
- afficher les ambiguïtés sans les résoudre automatiquement ;
- construire le `Campaign Authorization Record` ;
- obtenir la validation humaine du scope canonique.

### 5.2 Phase 1 — reconnaissance à partir de sources tierces

Outils envisagés, sous réserve des conditions du programme et des sources :

- **subfinder** pour les sources passives configurées ;
- **gau** et **Wayback** pour les URL historiques ;
- sources CT et DNS publiques autorisées.

Contraintes :

- aucun actif découvert n'est automatiquement ajouté au scope ;
- un sous-domaine découvert reste `candidate_out_of_scope` jusqu'à validation exacte ;
- les URL archivées ne sont pas rejouées automatiquement ;
- les secrets ou données personnelles découverts sont masqués et ne sont jamais validés par tentative de connexion.

### 5.3 Phase 2 — vérification active à faible impact

Après Gate C et Gate D :

- **httpx** : vérification HTTP(S) bornée, sans suivi de redirection hors scope ;
- **naabu** : uniquement si le port scanning est explicitement autorisé, avec ports et débit plafonnés ;
- **Katana** : crawl en lecture seule, profondeur, nombre d'URL et domaines strictement bornés ;
- **ffuf** : seulement si le content discovery est autorisé, avec wordlist approuvée, méthodes sûres et budget de requêtes ;
- **Nuclei** : détection seulement, templates allowlistés, exclusion de `dos`, `fuzz`, `intrusive`, `bruteforce`, `code` et `headless` par défaut.

Chaque outil doit être lancé par vecteur d'arguments, sans shell, avec timeout, limite de sortie, répertoire de travail isolé et groupe de processus annulable.

### 5.4 Phase 3 — corrélation et triage hors ligne

- normaliser les résultats dans un schéma commun ;
- corréler actif, endpoint, paramètre, technologie, template et preuve ;
- dédupliquer les variantes d'un même finding ;
- calculer confiance et sévérité séparément ;
- identifier les contradictions entre outils ;
- marquer les éléments insuffisants comme `unverified`, jamais comme vulnérabilités confirmées.

### 5.5 Phase 4 — validation contrôlée

La validation est une reproduction minimale, non une exploitation complète.

Avant chaque validation :

- présenter l'hypothèse, le nombre maximal de requêtes et l'impact attendu ;
- obtenir une approbation humaine distincte ;
- utiliser une méthode prédéfinie et bornée ;
- interdire toute extraction massive, persistance, pivot ou modification durable ;
- arrêter dès que la preuve minimale est obtenue ;
- ne jamais tester sur des comptes ou données de tiers.

Si une preuve sûre n'est pas possible, le finding reste non confirmé et le rapport explique la limite.

### 5.6 Phase 5 — rapport humain

Le Copilot prépare un brouillon, mais ne le soumet pas. Le rapport doit contenir :

- actif et endpoint exacts ;
- référence du scope ;
- préconditions ;
- étapes minimales de reproduction ;
- résultat attendu et résultat observé ;
- impact démontré sans extrapolation ;
- horodatage, versions d'outils et identifiants des preuves ;
- recommandations ;
- limites et incertitudes ;
- statut de validation humaine.

## 6. Corrélation, déduplication et faux positifs

### 6.1 Identité canonique d'un finding

La clé de déduplication doit combiner, selon le type :

- campagne ;
- actif canonique ;
- port et protocole ;
- méthode HTTP ;
- chemin normalisé ;
- paramètre ou composant ;
- classe de vulnérabilité ;
- empreinte stable de la preuve, sans secret.

Les occurrences restent conservées comme observations liées ; elles ne deviennent pas plusieurs rapports.

### 6.2 Score de confiance

Le score de confiance est distinct de la sévérité :

- qualité et fraîcheur de la source ;
- reproductibilité ;
- accord entre outils indépendants ;
- présence d'une preuve minimale ;
- stabilité de la réponse par rapport à un baseline ;
- risques connus de faux positif du template ;
- effet possible d'un WAF, cache, CDN ou honeypot.

Aucun LLM ne peut augmenter seul un finding à `confirmed`. Le modèle peut résumer ou signaler une contradiction, mais la promotion exige une règle déterministe et une validation humaine.

### 6.3 Réduction des faux positifs

- conserver request/response minimales et redacted ;
- comparer à un baseline ;
- répéter au maximum selon un budget approuvé ;
- ne pas considérer 200/301/302 comme preuve suffisante d'exposition ;
- ne pas considérer une bannière ou une version comme preuve d'exploitabilité ;
- mettre en quarantaine les sorties mal formées ;
- demander une revue manuelle si les outils se contredisent.

## 7. Scoring par plateforme

Le moteur conserve un score technique interne et génère une vue adaptée, sans prétendre prédire la décision de la plateforme.

### HackerOne

- utiliser CVSS lorsque pertinent ;
- séparer sévérité technique, impact métier et confiance ;
- signaler les catégories souvent informatives ou dépendantes du programme.

### Bugcrowd

- produire une proposition de priorité compatible avec la VRT ;
- conserver la version de VRT utilisée ;
- ne jamais forcer une catégorie en l'absence des préconditions requises.

### Intigriti

- présenter type, asset, impact et qualité de preuve ;
- appliquer les règles spécifiques du programme avant toute taxonomie générique.

Dans tous les cas, les règles du programme priment sur les valeurs par défaut du Copilot.

## 8. WAF, rate limits et comportement adaptatif

Le WAF et le rate limit sont des limites à respecter, pas des obstacles à contourner.

Comportement obligatoire :

- limites par hôte, outil, campagne et fenêtre de temps ;
- concurrence minimale par défaut ;
- backoff exponentiel borné sur 429/503 ;
- arrêt après seuil de 403, 429, CAPTCHA, challenge ou anomalie ;
- aucune rotation de proxy ou d'identité pour poursuivre ;
- aucune augmentation automatique du débit ;
- pause et demande humaine si le comportement du service change ;
- prise en compte des fenêtres horaires du programme.

Les budgets maximaux de requêtes et de durée sont calculés avant lancement. Un retry consomme le budget.

## 9. Exécution sûre des outils

Chaque intégration doit :

- utiliser `create_subprocess_exec` ou équivalent avec une liste d'arguments ;
- interdire `shell=True`, concaténation de commande et interpolation de cible ;
- résoudre le chemin de l'exécutable depuis une allowlist ;
- épingler et enregistrer la version de l'outil ;
- filtrer les options à travers un schéma strict ;
- isoler stdout, stderr et fichiers temporaires ;
- plafonner temps, mémoire, CPU, processus, taille de sortie et espace disque ;
- terminer le groupe de processus en cas de timeout, révocation ou arrêt ;
- empêcher les plugins, templates ou wordlists non approuvés ;
- ne jamais transmettre de secrets dans la ligne de commande ou les logs.

Les commandes proposées par Phi-4, dolphin ou tout autre modèle ne sont jamais exécutées directement. Le modèle produit une intention structurée, ensuite validée par schéma et convertie en arguments par du code déterministe.

## 10. Contrat JSONL et provenance

### 10.1 Événements

Chaque ligne JSONL représente un événement autonome :

```json
{
  "schema_version": "1.0",
  "event_id": "uuid",
  "campaign_id": "uuid",
  "task_id": "uuid",
  "timestamp": "RFC3339",
  "event_type": "plan|approval|execution|observation|finding|decision|stop|error",
  "scope_snapshot_hash": "sha256",
  "authorization_reference": "reference",
  "tool": {"name": "string", "version": "string"},
  "target": {"canonical": "string", "scope_status": "in_scope"},
  "risk_level": "L0|L1|L2|L3",
  "data": {},
  "evidence_refs": [],
  "redaction": {"applied": true, "fields": []}
}
```

### 10.2 Validation fail-closed

- UTF-8 strict ;
- un objet JSON par ligne ;
- taille maximale par ligne et par fichier ;
- schéma versionné ;
- champs inconnus refusés pour les événements de contrôle ;
- ligne mal formée : tâche en erreur, sortie mise en quarantaine, aucun parsing partiel silencieux ;
- aucun résultat d'outil ne peut modifier les champs d'autorisation ou de scope.

### 10.3 Provenance et intégrité

- hash SHA-256 des artefacts ;
- horodatage ;
- version de l'outil et configuration redacted ;
- chaînage ou signature des événements de décision ;
- distinction entre sortie brute, interprétation déterministe et résumé LLM.

## 11. Preuves et protection des données

Principes : minimisation, reproductibilité, intégrité et durée de conservation limitée.

- captures limitées à la preuve nécessaire ;
- tokens, cookies, mots de passe, clés, PII et données de tiers masqués à l'ingestion ;
- chiffrement au repos ;
- contrôle d'accès par campagne ;
- journal d'accès aux preuves ;
- rétention configurable selon le programme ;
- suppression vérifiable à échéance ;
- aucune preuve envoyée à un LLM distant sans autorisation explicite et politique compatible ;
- les modèles locaux reçoivent une vue redacted par défaut.

## 12. Mémoire des campagnes

La mémoire doit conserver :

- snapshots versionnés du scope et des règles ;
- plans approuvés ;
- événements et décisions ;
- actifs candidats séparés des actifs autorisés ;
- observations et findings avec provenance ;
- doublons et motifs de rejet ;
- état de validation et de rapport.

Elle ne doit jamais :

- transférer une allowlist ou une approbation entre campagnes ;
- relancer une tâche au redémarrage sans revalidation ;
- convertir automatiquement un actif historique en actif autorisé ;
- conserver des secrets en clair ;
- masquer qu'un finding dépend d'une donnée obsolète.

## 13. Kill switches et limites

### 13.1 Kill switches

- global : bloque toute activité réseau ;
- campagne : pause et annule toutes les tâches de la campagne ;
- cible : bloque immédiatement un actif ;
- outil : désactive une intégration ;
- approbation : révoque un token et annule la tâche liée.

Le kill switch doit :

1. empêcher tout nouveau lancement ;
2. envoyer une terminaison gracieuse aux groupes de processus ;
3. forcer l'arrêt après un délai court ;
4. vérifier l'absence de processus enfant ;
5. émettre un événement `stop` ;
6. exiger une nouvelle approbation pour reprendre.

### 13.2 Arrêts automatiques

- expiration ou révocation de l'autorisation ;
- cible ou redirection hors scope ;
- dépassement du budget de requêtes, temps, données ou erreurs ;
- réponse 429/403 répétée, CAPTCHA ou WAF challenge ;
- changement DNS non conforme ;
- sortie mal formée ou schéma invalide ;
- outil/version/template non allowlisté ;
- tentative de méthode interdite ;
- détection d'un impact non prévu ;
- impossibilité de journaliser les décisions.

## 14. État actuel et écarts à traiter avant implémentation

Garanties déjà observées dans le dépôt :

- gateway fail-closed pour les outils inconnus ;
- allowlist d'hôtes exacte et référence d'autorisation ;
- approbations actives liées, courtes et non rejouables ;
- outils destructifs désactivés à la gateway ;
- Nuclei limité à HTTP(S), templates allowlistés et mode détection ;
- parsing Nuclei JSONL strict ;
- exécution Nuclei par vecteur d'arguments sans shell.

Écarts connus à fermer avant une campagne externe :

1. certains outils réseau sont classés `PASSIVE` alors qu'ils contactent potentiellement la cible ;
2. plusieurs chemins historiques construisent encore des commandes shell à partir d'entrées ;
3. certains wrappers Nuclei internes n'acheminent pas encore la référence d'autorisation ;
4. le code historique contient des fonctions d'exploitation et d'évasion ; leur désactivation gateway doit être complétée par des contrôles aux couches internes ;
5. les contrôles de redirection, DNS rebinding, expiration pendant l'exécution et annulation de tâche restent à démontrer ;
6. la limitation globale actuelle ne suffit pas à garantir des budgets par cible et par campagne ;
7. la PR courante ne dispose d'aucun check CI GitHub ; la mergeability ne constitue donc pas une validation sécurité.

Ces écarts interdisent toute orchestration externe autonome dans l'état actuel.

## 15. Plan d'implémentation proposé

### Lot 1 — modèle de campagne, sans réseau

- schémas `CampaignAuthorization`, `ScopeAsset`, `ToolPlan` et événements JSONL ;
- normalisation et tests du scope ;
- import/export local ;
- génération de plans sans exécution.

### Lot 2 — policy et approbations

- classification L0–L5 ;
- approbations liées à tous les paramètres critiques ;
- revalidation avant requête et au changement de phase ;
- kill switches et expiration en cours de tâche.

### Lot 3 — adaptateurs d'outils

- adaptateurs sans shell ;
- budgets, templates et wordlists allowlistés ;
- démarrage avec une cible locale synthétique uniquement ;
- activation séparée de chaque outil après tests.

### Lot 4 — corrélation et reporting

- normalisation, déduplication et confiance ;
- preuves redacted ;
- brouillons HackerOne/Bugcrowd/Intigriti ;
- aucune soumission automatique.

### Lot 5 — revue indépendante

- threat model ;
- revue des bypass de scope ;
- tests d'expiration/révocation ;
- tests de processus orphelins ;
- validation humaine formelle avant toute campagne réelle.

## 16. Critères d'acceptation

Le Copilot n'est pas autorisé sur une cible externe tant que tous les critères suivants ne sont pas satisfaits :

### Scope et autorisation

- [ ] deny-by-default démontré ;
- [ ] exact host/path/port/CIDR et exclusions testés ;
- [ ] wildcard explicite uniquement ;
- [ ] redirections et DNS rebinding testés ;
- [ ] autorisation expirée/révoquée bloque et annule ;
- [ ] approbation à usage unique liée au plan complet.

### Exécution

- [ ] tous les adaptateurs utilisent un vecteur d'arguments sans shell ;
- [ ] versions, templates, options et wordlists allowlistés ;
- [ ] limites par campagne/cible/outil testées ;
- [ ] groupes de processus et enfants toujours nettoyés ;
- [ ] aucun retry ne contourne un blocage ;
- [ ] kill switches testés sous charge.

### Outils

- [ ] subfinder limité aux sources approuvées ;
- [ ] naabu désactivé sans autorisation explicite de port scan ;
- [ ] httpx bloque les redirections hors scope ;
- [ ] Katana applique domaines, profondeur et budget ;
- [ ] gau/Wayback ne rejouent pas automatiquement les URL ;
- [ ] ffuf exige wordlist, débit, méthodes et budget approuvés ;
- [ ] Nuclei reste en détection non intrusive et JSONL strict.

### Données et résultats

- [ ] JSONL versionné et fail-closed ;
- [ ] provenance et hashes présents ;
- [ ] secrets et PII redacted ;
- [ ] déduplication déterministe testée ;
- [ ] confiance séparée de la sévérité ;
- [ ] LLM incapable de confirmer ou d'exécuter seul ;
- [ ] rapport humain sans soumission automatique.

### Validation opérationnelle

- [ ] tests unitaires et d'intégration locaux réussis ;
- [ ] cible synthétique locale uniquement pendant le développement ;
- [ ] revue sécurité indépendante terminée ;
- [ ] CI obligatoire présente et réussie ;
- [ ] brief validé par le propriétaire ;
- [ ] scope réel et allowlist validés séparément ;
- [ ] approbation humaine finale documentée.

## 17. Questions nécessitant une décision humaine

Avant l'implémentation :

1. Quelles plateformes et quels formats de règles sont prioritaires ?
2. Les sources tierces L1 doivent-elles elles aussi exiger une approbation par tâche ?
3. Quels plafonds par défaut retenir pour concurrence, requêtes, durée et volume ?
4. Quelle durée de rétention et quel stockage chiffré utiliser pour les preuves ?
5. Quels outils doivent être exclus du premier lot, même en environnement local ?
6. Quelle personne ou quel rôle peut approuver L2 et L3 ?
7. Quelle revue indépendante est exigée avant la première campagne réelle ?

## 18. Gate final

La validation de ce document autorise uniquement la conception et les tests locaux sur cibles synthétiques contrôlées. Elle n'autorise ni scan externe, ni validation active sur un programme réel, ni exploitation.

Pour toute cible réelle, il faudra un second dossier contenant le scope exact, l'allowlist canonique, la référence d'autorisation, les limites du programme, le plan d'outils et l'approbation humaine liée à la campagne.
