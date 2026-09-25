#!/usr/bin/env python3
"""
Création de 4 comptes Skill Money
Avec code de parrainage E948ED0E
"""

import asyncio
import json
import sys
import time
sys.path.insert(0, '/home/morningstar/Bureau/kali_mcp/MCP-Kali-Server')

async def create_accounts():
    """Créer 4 comptes sur skillmoney.8unb.xyz"""
    
    from kali_mcp_server import run_command_shell
    
    referral_code = "E948ED0E"
    
    accounts = [
        {
            "num": 1,
            "email": "poiuyt@poiuyt.com",
            "password": "poiuyt",
            "firstname": "Test",
            "lastname": "User1",
            "phone": "+2216600000001"
        },
        {
            "num": 2,
            "email": "testuser2@skill.money.test",
            "password": "TestPass@2024",
            "firstname": "Test",
            "lastname": "User2",
            "phone": "+2216600000002"
        },
        {
            "num": 3,
            "email": "testuser3@skill.money.test",
            "password": "TestPass@2024",
            "firstname": "Test",
            "lastname": "User3",
            "phone": "+2216600000003"
        },
        {
            "num": 4,
            "email": "testuser4@skill.money.test",
            "password": "TestPass@2024",
            "firstname": "Test",
            "lastname": "User4",
            "phone": "+2216600000004"
        }
    ]
    
    print(f"""
    ╔══════════════════════════════════════════════╗
    ║   CRÉATION DE 4 COMPTES SKILL MONEY          ║
    ║   Plateforme: skillmoney.8unb.xyz            ║
    ║   Code parrainage: {referral_code}               ║
    ╚══════════════════════════════════════════════╝
    """)
    
    created_accounts = []
    failed_accounts = []
    
    for account in accounts:
        print(f"\n[*] Création Compte {account['num']}: {account['email']}")
        
        # Tenter création via différentes méthodes
        
        # Méthode 1: POST JSON
        print(f"    [+] Tentative 1: POST JSON /api/auth/register")
        
        json_data = json.dumps({
            "email": account['email'],
            "password": account['password'],
            "firstname": account['firstname'],
            "lastname": account['lastname'],
            "phone": account['phone'],
            "referral_code": referral_code
        })
        
        cmd_json = f"""curl -s -X POST https://skillmoney.8unb.xyz/api/auth/register \\
            -H "Content-Type: application/json" \\
            -H "Accept: application/json" \\
            -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)" \\
            -d '{json_data}' 2>&1 | head -200"""
        
        result_json = await run_command_shell(cmd_json, timeout=15)
        response_json = result_json.get('stdout', '')
        
        if 'success' in response_json.lower() or 'token' in response_json.lower():
            print(f"    ✓ SUCCÈS (Méthode JSON)")
            print(f"    Réponse: {response_json[:200]}")
            created_accounts.append({**account, "method": "JSON", "response": response_json[:500]})
            time.sleep(1)
            continue
        elif response_json:
            print(f"    Response: {response_json[:300]}")
        
        # Méthode 2: Form data URL encoded
        print(f"    [+] Tentative 2: POST Form-data /api/auth/register")
        
        form_data = f"email={account['email']}&password={account['password']}&firstname={account['firstname']}&lastname={account['lastname']}&phone={account['phone']}&referral_code={referral_code}"
        
        cmd_form = f"""curl -s -X POST https://skillmoney.8unb.xyz/api/auth/register \\
            -H "Content-Type: application/x-www-form-urlencoded" \\
            -H "Accept: application/json" \\
            -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)" \\
            -d "{form_data}" 2>&1 | head -200"""
        
        result_form = await run_command_shell(cmd_form, timeout=15)
        response_form = result_form.get('stdout', '')
        
        if 'success' in response_form.lower() or 'token' in response_form.lower():
            print(f"    ✓ SUCCÈS (Méthode Form)")
            print(f"    Réponse: {response_form[:200]}")
            created_accounts.append({**account, "method": "Form", "response": response_form[:500]})
            time.sleep(1)
            continue
        elif response_form:
            print(f"    Response: {response_form[:300]}")
        
        # Méthode 3: Essayer /register (sans /api)
        print(f"    [+] Tentative 3: POST /register (endpoint alternatif)")
        
        cmd_alt = f"""curl -s -X POST https://skillmoney.8unb.xyz/register \\
            -H "Content-Type: application/json" \\
            -H "Accept: application/json" \\
            -d '{json_data}' 2>&1 | head -200"""
        
        result_alt = await run_command_shell(cmd_alt, timeout=15)
        response_alt = result_alt.get('stdout', '')
        
        if 'success' in response_alt.lower() or 'token' in response_alt.lower() or 'created' in response_alt.lower():
            print(f"    ✓ SUCCÈS (Endpoint /register)")
            print(f"    Réponse: {response_alt[:200]}")
            created_accounts.append({**account, "method": "Alt", "response": response_alt[:500]})
            time.sleep(1)
            continue
        else:
            print(f"    ✗ Échec toutes les méthodes")
            failed_accounts.append({**account, "reason": "No working endpoint found"})
    
    # Résumé
    print(f"\n{'='*60}")
    print(f"RÉSUMÉ CRÉATION DE COMPTES")
    print(f"{'='*60}")
    print(f"✓ Créés: {len(created_accounts)}")
    print(f"✗ Échoués: {len(failed_accounts)}")
    
    if created_accounts:
        print(f"\n✓ Comptes créés:")
        for acc in created_accounts:
            print(f"  - {acc['email']} (via {acc['method']})")
    
    if failed_accounts:
        print(f"\n✗ Comptes échoués:")
        for acc in failed_accounts:
            print(f"  - {acc['email']}")
    
    # Tenter login avec chaque compte créé
    print(f"\n[*] Test login avec les comptes créés...")
    
    for account in created_accounts:
        print(f"\n  Testing login: {account['email']}")
        
        login_data = json.dumps({
            "email": account['email'],
            "password": account['password']
        })
        
        cmd_login = f"""curl -s -X POST https://skillmoney.8unb.xyz/api/auth/login \\
            -H "Content-Type: application/json" \\
            -d '{login_data}' 2>&1 | head -100"""
        
        result_login = await run_command_shell(cmd_login, timeout=10)
        response = result_login.get('stdout', '')
        
        if response:
            print(f"  Response: {response[:200]}")
            if 'token' in response.lower() or 'success' in response.lower():
                print(f"  ✓ LOGIN SUCCÈS!")
            else:
                print(f"  ℹ️ Response reçue")
    
    # Sauvegarder résultats
    results = {
        "timestamp": int(time.time()),
        "platform": "skillmoney.8unb.xyz",
        "referral_code": referral_code,
        "created_accounts": created_accounts,
        "failed_accounts": failed_accounts,
        "subdomains_info": {
            "count": 35,
            "all_nginx_default": True,
            "notable": ["admin", "api", "db", "git", "jenkins"]
        }
    }
    
    with open("/tmp/skillmoney_creation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✓ Résultats sauvegardés: /tmp/skillmoney_creation_results.json")
    
    return results

if __name__ == "__main__":
    asyncio.run(create_accounts())
