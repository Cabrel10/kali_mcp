# Rapport d'évaluation de sécurité - tsotsa.org

**Date :** 2025-10-26
**Cible :** tsotsa.org
**Adresse IP :** 194.95.114.28 (identifiée par Nmap)

## 1. Résumé des Constats

### 1.1 Informations Générales
*   **Serveur Web :** Apache
*   **Framework :** Next.js
*   **Email trouvé :** tsotsa@gmail.com

### 1.2 Ports et Services Ouverts (Nmap)
*   **80/tcp :** http
*   **443/tcp :** https
*   **1081/tcp :** pvuniwien
*   **2000/tcp : :** cisco-sccp
*   **5060/tcp :** sip

### 1.3 Vulnérabilités et Misconfigurations (Nikto - résultats partiels)
*   **En-tête X-Frame-Options manquant :** Vulnérabilité potentielle au clickjacking.
*   **En-tête X-Content-Type-Options manquant :** Vulnérabilité potentielle au reniflage de type MIME.
*   **En-tête inhabituel 'x-template' sur `/archive.pem` :** Indique un système de templating interne ou une mauvaise configuration.

### 1.4 Découverte de Répertoires (Gobuster - résultats partiels)
*   Des chemins comme `/_notes` et `/_vti_cnf` ont été identifiés, mais ont renvoyé des erreurs "503 Service Unavailable". Cela suggère la présence d'un WAF ou d'une limitation de débit.

### 1.5 Fichiers Sensibles Connus (Well-known Files Check)
*   Aucun fichier sensible accessible n'a été trouvé.

### 1.6 Vulnérabilités LFI (Advanced LFI Scan)
*   Aucune vulnérabilité LFI n'a été détectée.

### 1.7 Tentative de Scan SQL Injection (SQLMap)
*   **Détection de WAF/IPS :** SQLMap a détecté la présence d'un WAF (Web Application Firewall) ou d'un IPS (Intrusion Prevention System) protégeant la cible. Cela a entraîné de nombreuses erreurs HTTP (502 Bad Gateway, 400 Bad Request) et a rendu le scan inefficace.
*   **Paramètres non injectables :** Le paramètre `q` testé sur l'URL `https://tsotsa.org/_next/image?url=/images/food-demo/eru1.png&w=1200&q=75` n'a pas semblé être injectable.

### 1.8 Résultats du Scan Nuclei (après correction)
*   **WAF Apache générique confirmé :** `[waf-detect:apachegeneric]`
*   **Email exposé :** `tsotsa@gmail.com` (confirmé)
*   **Serveur Apache détecté :** Confirmé
*   **Support TLS :** TLS 1.2 et 1.3 supportés
*   **Méthodes HTTP autorisées :** GET, HEAD
*   **En-têtes de sécurité MANQUANTS :**
    *   `Cross-Origin-Opener-Policy`
    *   `Cross-Origin-Resource-Policy`
    *   `Strict-Transport-Security`
    *   `Permissions-Policy`
    *   `X-Permitted-Cross-Domain-Policies`
    *   `Referrer-Policy`
    *   `Clear-Site-Data`
    *   `Cross-Origin-Embedder-Policy`
*   **Informations WHOIS (via RDAP) :**
    *   Statut : `client transfer prohibited`
    *   Date d'enregistrement : 2025-07-18
    *   Dernière modification : 2025-07-23
    *   Date d'expiration : 2026-07-18
    *   Serveurs de noms : `ns01.tib.eu`, `ns02.tib.eu`, `ns03.tib.eu`
    *   DNSSEC : `false` (Non activé)
*   **Certificat SSL :** Émis par Let's Encrypt.
*   **Vulnérabilités critiques, élevées et moyennes :** Aucun match trouvé par Nuclei.
*   **Vulnérabilités spécifiques aux technologies et erreurs de configuration :**
    *   Re-confirmation des en-têtes de sécurité manquants listés ci-dessus.

### 1.9 Tests Manuels de Contournement WAF et XSS

*   **HTTP Parameter Pollution (HPP) - Test XSS :**
    *   Tentative d'injection XSS via HPP sur `_next/image?url=...` a échoué avec la réponse : `"url" parameter cannot be an array`. Cela indique que le serveur rejette les paramètres dupliqués pour cet endpoint.
*   **HTTP Parameter Pollution (HPP) - Test SQLi :**
    *   Tentative d'injection SQLi via HPP sur `_next/image?q=...` a échoué avec la réponse : `"url" parameter is required`. Cela indique que l'endpoint `_next/image` nécessite le paramètre `url` et n'est pas adapté pour tester `q` de cette manière.
*   **Vérification de l'en-tête HSTS :**
    *   L'en-tête `Strict-Transport-Security` est **manquant** sur l'URL racine (`https://tsotsa.org/`).
    *   Le test avec `curl -H "X-Forwarded-Proto: http"` a renvoyé le contenu de la page, ce qui est attendu. L'absence de HSTS expose les utilisateurs à des attaques de rétrogradation SSL/TLS.
*   **Test XSS pour le CSP manquant (via `_next/image?url=javascript:alert(1)`) :**
    *   L'injection de `javascript:alert(1)` dans le paramètre `url` de l'endpoint `_next/image` a provoqué une **erreur 500 Internal Server Error**. La page d'erreur divulgue des informations internes telles que `Fehlertemplate...: 500-error.tmpl.html`, `ServerIP.........: 194.95.114.29`, `RemoteIP.........: 165.211.32.40`. Ceci indique une mauvaise gestion des entrées inattendues et une potentielle vulnérabilité à la divulgation d'informations ou au déni de service.

## 2. Recommandations et Prochaines Étapes

### 2.1 Corrections Immédiates

*   **Ajouter les en-têtes de sécurité manquants :**
    *   **X-Frame-Options :** Implémenter l'en-tête `X-Frame-Options` pour prévenir le clickjacking. Pour Apache, cela peut être fait dans le fichier de configuration (`httpd.conf` ou un fichier `.htaccess`) :
        ```apache
        Header always append X-Frame-Options SAMEORIGIN
        ```
        (Utiliser `DENY` si le site ne doit jamais être intégré dans une iframe, ou `SAMEORIGIN` s'il peut l'être par des pages du même domaine).
    *   **X-Content-Type-Options :** Implémenter l'en-tête `X-Content-Type-Options: nosniff` pour prévenir le reniflage de type MIME. Pour Apache :
        ```apache
        Header always set X-Content-Type-Options "nosniff"
        ```
    *   **Autres en-têtes de sécurité critiques :** Implémenter les en-têtes suivants pour renforcer la sécurité :
        *   `Strict-Transport-Security` (HSTS) - **Manquant, à ajouter impérativement.**
        *   `Content-Security-Policy` (CSP) - Nécessite une configuration minutieuse. La politique actuelle (`unsafe-inline`) devrait être renforcée.
        *   `Referrer-Policy`
        *   `Permissions-Policy`
        *   `Cross-Origin-Opener-Policy`
        *   `Cross-Origin-Resource-Policy`
        *   `Clear-Site-Data`
        *   `X-Permitted-Cross-Domain-Policies`
        *   `Cross-Origin-Embedder-Policy`

*   **Contrôle de la divulgation d'informations (Apache) :**
    *   **Masquer la version d'Apache et l'OS :** Modifier le fichier de configuration Apache pour masquer ces informations :
        ```apache
        ServerTokens Prod
        ServerSignature Off
        ```
    *   **Désactiver l'affichage des répertoires :** S'assurer que l'affichage des répertoires est désactivé pour éviter de lister le contenu des dossiers :
        ```apache
        Options -Indexes
        ```

*   **Activer DNSSEC :** L'activation de DNSSEC peut aider à protéger contre l'empoisonnement du cache DNS.

*   **Gérer les erreurs 500 :**
    *   Corriger la cause de l'erreur 500 provoquée par l'injection de `javascript:alert(1)` dans le paramètre `url` de l'endpoint `_next/image`. (Priorité : Élevée)
    *   S'assurer que les pages d'erreur ne divulguent aucune information interne sensible (chemins de fichiers, adresses IP internes, versions de logiciels). (Priorité : Élevée)

### 2.2 Investigations Supplémentaires

*   **Analyser les erreurs 503 et la présence d'un WAF :**
    *   Examiner les logs du serveur pour comprendre pourquoi les requêtes vers `/_notes` et `/_vti_cnf` ont renvoyé des erreurs 503. Cela pourrait révéler des tentatives de blocage par un WAF ou une limitation de débit.
    *   Si un WAF est en place, il est important de le configurer correctement pour bloquer les attaques sans impacter les utilisateurs légitimes.

*   **Vérifier `/archive.pem` et l'en-tête 'x-template' :**
    *   Investiguer la signification de l'en-tête `x-template` et le contenu de `/archive.pem` pour s'assurer qu'il ne divulgue pas d'informations sensibles ou n'indique pas une vulnérabilité de templating.

*   **Évaluation de la sécurité des services ouverts :**
    *   Examiner les services ouverts sur les ports 1081 (pvuniwien), 2000 (cisco-sccp) et 5060 (sip) pour s'assurer qu'ils sont correctement configurés, mis à jour et sécurisés. Ces services peuvent être des points d'entrée pour des attaques s'ils sont mal protégés.

*   **Sécurité spécifique à Next.js :**
    *   **Validation et assainissement des entrées :** S'assurer que toutes les entrées utilisateur et les données provenant d'APIs externes sont rigoureusement validées et assainies pour prévenir les injections (XSS, SQLi). Utiliser des bibliothèques comme Zod, Valibot ou DOMPurify.
    *   **Gestion des secrets :** Vérifier que les informations sensibles (clés API, identifiants de base de données) ne sont jamais exposées côté client et sont gérées via des variables d'environnement sécurisées (`.env.local`) ou des gestionnaires de secrets en production.
    *   **Mises à jour des dépendances :** S'assurer que toutes les dépendances du projet Next.js sont régulièrement mises à jour pour bénéficier des derniers correctifs de sécurité.

### 2.3 Tests de Vulnérabilité Futurs

*   **Scan SQL Injection ciblé (avec SQLMap et contournement de WAF) :**
    *   Étant donné la détection d'un WAF/IPS, toute tentative future de scan SQL Injection avec SQLMap devra utiliser des techniques de contournement (tamper scripts). SQLMap suggère d'utiliser l'option `--tamper` (par exemple, `--tamper=space2comment`) et/ou de changer l'agent utilisateur (`--random-agent`).
    *   Il est crucial d'identifier manuellement des points d'injection SQL potentiels (par exemple, via l'analyse des formulaires ou des paramètres d'URL) pour cibler SQLMap et augmenter les chances de succès.

*   **Fuzzing d'applications web (avec Wfuzz) :** Utiliser Wfuzz pour tester des points d'entrée spécifiques de l'application web (formulaires, paramètres d'URL) pour d'autres vulnérabilités, en se basant sur les technologies identifiées (Next.js, Apache).

*   **Tests XSS/CSRF manuels avec `curl` :** Utiliser des charges utiles XSS/CSRF avec `curl` pour vérifier la réflexion dans la réponse HTML, en ciblant les paramètres d'URL ou les champs de formulaire.

---