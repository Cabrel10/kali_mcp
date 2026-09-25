#!/bin/bash
# Script pour installer l'extension Open Remote - SSH dans Kiro

echo "=== Installation de l'extension SSH pour Kiro ==="
echo ""

# Vérifier si kiro est installé
if ! command -v kiro &> /dev/null; then
    echo "❌ Kiro n'est pas installé ou pas dans le PATH"
    exit 1
fi

echo "✅ Kiro trouvé"
echo ""

# Installer l'extension Open Remote - SSH
echo "📦 Installation de l'extension Open Remote - SSH..."
kiro --install-extension jeanp413.open-remote-ssh

echo ""
echo "✅ Configuration terminée!"
echo ""
echo "📋 ÉTAPES SUIVANTES:"
echo "1. Redémarre complètement Kiro (ferme toutes les fenêtres)"
echo "2. Rouvre Kiro"
echo "3. Appuie sur Ctrl+Shift+P"
echo "4. Tape: Remote-SSH: Connect to Host..."
echo "5. Sélectionne 'root' dans la liste"
echo "6. Une fois connecté, ouvre le dossier: /home/ubuntu/webapp"
echo ""
echo "Le X rouge devrait disparaître et devenir une icône SSH verte ✅"
