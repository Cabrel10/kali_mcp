# ⚡ Quick Start - Phishing Exploitation

## 🎯 Commandes Essentielles

### 1️⃣ Vérifier si c'est du phishing (2 min)
```bash
run_full_osint_analysis(domain="exxspecial.com")
```
**Résultat**: Score de phishing + indicateurs

---

### 2️⃣ Tester TOUS les exploits (10 min)
```bash
run_phishing_exploit_suite()
```
**Résultat**: Toutes les vulnérabilités testées

---

### 3️⃣ Tester SSRF (CRITIQUE) (2 min)
```bash
test_phishing_ssrf()
```
**Si trouvé**: Accès aux métadonnées AWS possible

---

### 4️⃣ Tester OTP Bypass (3 min)
```bash
test_phishing_otp_bypass(phone="+221123456789", num_requests=50)
```
**Si trouvé**: Création de compte sans OTP valide

---

### 5️⃣ Tester IDOR (2 min)
```bash
test_phishing_idor(code_range_start=1000, code_range_end=9999)
```
**Si trouvé**: Énumération de codes d'invitation

---

### 6️⃣ Tester Fichiers Sensibles (1 min)
```bash
test_phishing_sensitive_files()
```
**Si trouvé**: Leak de source code, credentials, etc.

---

### 7️⃣ Tester CSRF (1 min)
```bash
test_phishing_csrf()
```
**Si trouvé**: Attaques CSRF possibles

---

### 8️⃣ Tester DOM XSS (1 min)
```bash
test_phishing_dom_xss()
```
**Si trouvé**: Vol de session possible

---

### 9️⃣ Tester Endpoints (5 min)
```bash
run_full_endpoint_test(phone="+221123456789", invitation_code="1234")
```
**Résultat**: Vulnérabilités par endpoint

---

### 🔟 Trouver l'IP réelle (2 min)
```bash
locate_origin(domain="exxspecial.com")
```
**Résultat**: IP réelle derrière Cloudflare

---

## 🚀 Scénarios Rapides

### Scénario A: Vérification Rapide (5 min)
```bash
# 1. Vérifier légitimité
run_full_osint_analysis(domain="exxspecial.com")

# 2. Tester SSRF (le plus critique)
test_phishing_ssrf()

# 3. Résultat
# → Si phishing confirmé + SSRF trouvé = CRITIQUE
```

---

### Scénario B: Exploitation Complète (20 min)
```bash
# 1. Analyse OSINT
run_full_osint_analysis(domain="exxspecial.com")

# 2. Tous les exploits
run_phishing_exploit_suite()

# 3. Trouver l'IP réelle
locate_origin(domain="exxspecial.com")

# 4. Reconnaissance sur l'IP
tactical_recon(target="IP_TROUVÉE")

# 5. Résultat
# → Plan d'attaque complet
```

---

### Scénario C: Test Spécifique (3 min)
```bash
# Tester un endpoint spécifique
test_sendSms_endpoint(phone="+221123456789")

# Ou
test_register_endpoint(phone="+221123456789", invitation_code="1234")

# Ou
test_doLogin_endpoint()
```

---

## 📊 Interprétation des Résultats

### OSINT Analysis
```
Phishing Score > 70% → PROBABLEMENT DU PHISHING
Phishing Score < 30% → PROBABLEMENT LÉGITIME
```

### SSRF Test
```
"vulnerable": true → SSRF TROUVÉ (CRITIQUE)
"critical_findings": [...] → Détails des vulnérabilités
```

### OTP Bypass
```
"bypass_successful": true → OTP BYPASS TROUVÉ (CRITIQUE)
"successful_registrations": [...] → Codes qui passent
```

### IDOR Test
```
"valid_codes": [1000, 1001, ...] → CODES VALIDES TROUVÉS (CRITIQUE)
"exploitation_possible": true → Énumération possible
```

### Sensitive Files
```
"files_found": [...] → FICHIERS EXPOSÉS (CRITIQUE)
"files_not_found": [...] → Fichiers non accessibles
```

---

## 🎯 Tableau de Décision

```
┌─────────────────────────────────────────────────────────┐
│ RÉSULTAT OSINT                                          │
├─────────────────────────────────────────────────────────┤
│ Phishing Score > 70%                                    │
│ ↓                                                       │
│ → Continuer avec run_phishing_exploit_suite()          │
│                                                         │
│ Phishing Score < 30%                                    │
│ ↓                                                       │
│ → Site probablement légitime, arrêter                  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ RÉSULTAT EXPLOITS                                       │
├─────────────────────────────────────────────────────────┤
│ SSRF trouvé                                             │
│ ↓                                                       │
│ → test_phishing_ssrf() pour détails                    │
│ → Accès aux métadonnées AWS possible                   │
│                                                         │
│ OTP Bypass trouvé                                       │
│ ↓                                                       │
│ → test_phishing_otp_bypass() pour détails             │
│ → Création de compte sans OTP valide                   │
│                                                         │
│ IDOR trouvé                                             │
│ ↓                                                       │
│ → test_phishing_idor() pour détails                   │
│ → Énumération de codes d'invitation                    │
│                                                         │
│ Fichiers sensibles trouvés                              │
│ ↓                                                       │
│ → test_phishing_sensitive_files() pour détails        │
│ → Leak de source code ou credentials                   │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ RÉSULTAT LOCATE_ORIGIN                                  │
├─────────────────────────────────────────────────────────┤
│ IP réelle trouvée                                       │
│ ↓                                                       │
│ → tactical_recon(target="IP_TROUVÉE")                  │
│ → Reconnaissance complète sur l'IP réelle              │
│                                                         │
│ IP non trouvée                                          │
│ ↓                                                       │
│ → Cloudflare bien configuré                            │
│ → Continuer avec les exploits trouvés                  │
└─────────────────────────────────────────────────────────┘
```

---

## 💡 Conseils Pratiques

### 1. Commencer par OSINT
```bash
run_full_osint_analysis(domain="exxspecial.com")
```
- Rapide (2-3 min)
- Donne une première indication
- Pas de risque de détection

### 2. Si phishing confirmé, tester les exploits
```bash
run_phishing_exploit_suite()
```
- Complet (10 min)
- Teste tous les vecteurs
- Peut être détecté par WAF

### 3. Si exploits trouvés, approfondir
```bash
test_phishing_ssrf()  # ou autre exploit
```
- Détails spécifiques
- Permet de valider les résultats

### 4. Trouver l'IP réelle
```bash
locate_origin(domain="exxspecial.com")
```
- Contourner Cloudflare
- Accès direct au serveur

### 5. Reconnaissance complète
```bash
tactical_recon(target="IP_TROUVÉE")
```
- Plan d'attaque complet
- Tous les vecteurs d'exploitation

---

## ⏱️ Temps Estimés

| Commande | Temps | Risque |
|----------|-------|--------|
| `run_full_osint_analysis()` | 2-3 min | Bas |
| `test_phishing_ssrf()` | 1-2 min | Moyen |
| `test_phishing_otp_bypass()` | 2-3 min | Moyen |
| `test_phishing_idor()` | 2-3 min | Moyen |
| `test_phishing_sensitive_files()` | 1 min | Bas |
| `test_phishing_csrf()` | 1 min | Bas |
| `test_phishing_dom_xss()` | 1 min | Bas |
| `run_phishing_exploit_suite()` | 10 min | Moyen |
| `run_full_endpoint_test()` | 5 min | Moyen |
| `locate_origin()` | 2 min | Bas |
| `tactical_recon()` | 5-15 min | Moyen |

---

## 🔐 Sécurité

### Avant de tester:
1. ✅ Vérifier que vous avez l'autorisation
2. ✅ Utiliser un VPN si nécessaire
3. ✅ Activer ghost_mode si disponible
4. ✅ Vérifier les logs après

### Pendant les tests:
1. ✅ Monitorer les résultats
2. ✅ Arrêter si détecté
3. ✅ Utiliser les délais appropriés
4. ✅ Respecter les rate limits

### Après les tests:
1. ✅ Sauvegarder les résultats
2. ✅ Analyser les findings
3. ✅ Documenter les vulnérabilités
4. ✅ Nettoyer les traces

---

## 📋 Checklist

- [ ] Redémarrer le serveur MCP
- [ ] Vérifier que les nouveaux outils sont disponibles
- [ ] Tester `run_full_osint_analysis()`
- [ ] Tester `run_phishing_exploit_suite()`
- [ ] Analyser les résultats
- [ ] Documenter les findings
- [ ] Planifier l'exploitation

---

## 🆘 Troubleshooting

### Erreur: "Command not found"
```
→ Vérifier que les outils sont installés
→ Vérifier le PATH
→ Redémarrer le serveur
```

### Erreur: "Timeout"
```
→ Augmenter le timeout
→ Réduire le nombre de requêtes
→ Vérifier la connexion réseau
```

### Erreur: "Connection refused"
```
→ Vérifier que le site est accessible
→ Vérifier le firewall
→ Vérifier les proxies
```

### Pas de résultats
```
→ Vérifier les logs
→ Augmenter le verbosity
→ Tester manuellement avec curl
```

---

## 📞 Commandes Utiles

```bash
# Vérifier l'état du serveur
server_health()

# Lister les tâches
list_tasks()

# Vérifier une tâche spécifique
check_task(task_id="...")

# Annuler une tâche
cancel_task(task_id="...")

# Exécuter une commande personnalisée
execute_command(command="curl -I https://exxspecial.com")
```

---

**Dernière mise à jour**: 22 Décembre 2025
**Version**: 1.0
**Status**: ✅ Prêt à l'emploi
