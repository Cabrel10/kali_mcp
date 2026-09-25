#!/bin/bash
# Vérification complète de la configuration SSH Connect

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║       SSH Connect for Kiro - Configuration Verification       ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# 1. Vérifier l'extension
echo "1️⃣  Extension SSH Connect..."
if kiro --list-extensions | grep -i ssh-connect > /dev/null; then
    echo "   ✅ Extension SSH Connect installée"
else
    echo "   ⚠️  Extension non trouvée"
fi
echo ""

# 2. Vérifier le fichier de configuration Kiro
echo "2️⃣  Fichier de configuration (~/.local/share/Kiro/...)..."
if [ -f ~/.local/share/Kiro/User/globalStorage/elcamilet.ssh-connect/ssh-config.json ]; then
    echo "   ✅ ssh-config.json trouvé"
    echo "   📄 Contenu:"
    cat ~/.local/share/Kiro/User/globalStorage/elcamilet.ssh-connect/ssh-config.json | head -20
else
    echo "   ❌ Fichier non trouvé"
fi
echo ""

# 3. Vérifier la clé SSH
echo "3️⃣  Clé SSH google_compute_engine..."
if [ -f ~/.ssh/google_compute_engine ]; then
    echo "   ✅ Clé SSH trouvée"
    ls -lh ~/.ssh/google_compute_engine
else
    echo "   ❌ Clé SSH non trouvée"
fi
echo ""

# 4. Tester la connexion SSH
echo "4️⃣  Test de connexion SSH vers 169.58.67.16..."
if timeout 5 ssh -i ~/.ssh/google_compute_engine -o ConnectTimeout=5 -o BatchMode=yes ubuntu@169.58.67.16 "echo OK" 2>/dev/null; then
    echo "   ✅ Connexion SSH fonctionnelle"
else
    echo "   ⚠️  Test de connexion échoué (mais c'est normal en SSH Connect)"
fi
echo ""

# 5. Résumé
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  🎯 PROCHAINES ÉTAPES                         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "1. Redémarre Kiro complètement (ferme toutes les fenêtres)"
echo "2. Rouvre Kiro"
echo "3. Clique sur l'icône 'SSH Hosts' dans la barre latérale"
echo "4. Tu verras: VPS Servers > Ubuntu VPS - webapp"
echo "5. Clique sur 'Ubuntu VPS - webapp' pour te connecter"
echo ""
echo "Le X rouge devrait disparaître et tu verras une connexion active ✅"
echo ""
