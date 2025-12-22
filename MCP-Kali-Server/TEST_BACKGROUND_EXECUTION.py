#!/usr/bin/env python3
"""
Test Complet - Vérification de l'Exécution en Arrière-Plan des Tâches
Teste que les tâches démarrent réellement et progressent correctement
"""

import sys
import time
import asyncio
import json

sys.path.insert(0, '/home/morningstar/Bureau/kali_mcp/MCP-Kali-Server')

from src.core.task_manager import TaskManager, TaskStatus


async def test_background_task_execution():
    """Test que les tâches s'exécutent réellement en arrière-plan"""
    
    print("=" * 80)
    print("TEST: Exécution en Arrière-Plan des Tâches")
    print("=" * 80)
    
    # Créer un TaskManager
    tasks = TaskManager()
    
    # Test 1: Créer une tâche
    print("\n1️⃣ TEST: Création d'une tâche")
    print("-" * 80)
    
    task_id = tasks.create_task("192.168.1.1", "nmap")
    print(f"✅ Tâche créée: {task_id}")
    
    # Vérifier le statut initial
    status = tasks.get_task_status(task_id)
    print(f"   Status initial: {status['status']}")
    print(f"   Progress: {status['progress']}%")
    print(f"   Elapsed time: {status['elapsed_time']}s")
    
    assert status['status'] == TaskStatus.PENDING.value, "La tâche devrait être PENDING"
    assert status['progress'] == 0, "La progression devrait être 0%"
    print("✅ PASSÉ: Tâche créée avec le bon statut initial")
    
    # Test 2: Lancer une tâche en arrière-plan
    print("\n2️⃣ TEST: Lancement d'une tâche en arrière-plan")
    print("-" * 80)
    
    async def mock_long_operation(duration: int):
        """Opération simulée qui prend du temps"""
        await asyncio.sleep(duration)
        return f"Completed after {duration} seconds"
    
    # Lancer la tâche en arrière-plan
    future = tasks.start_background_task(task_id, mock_long_operation, 2)
    print(f"✅ Tâche lancée en arrière-plan")
    print(f"   Future: {future}")
    
    # Vérifier que la tâche est maintenant RUNNING
    await asyncio.sleep(0.5)  # Attendre un peu que la tâche démarre
    status = tasks.get_task_status(task_id)
    print(f"   Status après lancement: {status['status']}")
    print(f"   Elapsed time: {status['elapsed_time']}s")
    
    assert status['status'] in [TaskStatus.RUNNING.value, TaskStatus.COMPLETED.value], \
        f"La tâche devrait être RUNNING ou COMPLETED, pas {status['status']}"
    print("✅ PASSÉ: Tâche lancée et en cours d'exécution")
    
    # Test 3: Attendre la complétion
    print("\n3️⃣ TEST: Attendre la complétion de la tâche")
    print("-" * 80)
    
    # Attendre que la tâche se termine
    await asyncio.sleep(2.5)
    
    status = tasks.get_task_status(task_id)
    print(f"   Status final: {status['status']}")
    print(f"   Progress: {status['progress']}%")
    print(f"   Elapsed time: {status['elapsed_time']}s")
    print(f"   Result: {status['result'][:50] if status['result'] else None}...")
    
    assert status['status'] == TaskStatus.COMPLETED.value, "La tâche devrait être COMPLETED"
    assert status['progress'] == 100, "La progression devrait être 100%"
    assert status['result'] is not None, "Le résultat devrait être présent"
    print("✅ PASSÉ: Tâche complétée avec succès")
    
    # Test 4: Tâches multiples concurrentes
    print("\n4️⃣ TEST: Tâches multiples concurrentes")
    print("-" * 80)
    
    task_ids = []
    for i in range(3):
        tid = tasks.create_task(f"target_{i}", f"tool_{i}")
        tasks.start_background_task(tid, mock_long_operation, 1)
        task_ids.append(tid)
        print(f"✅ Tâche {i+1} lancée: {tid}")
    
    # Vérifier les statistiques
    stats = tasks.get_stats()
    print(f"\n   Statistiques:")
    print(f"   - Total tasks: {stats['total_tasks']}")
    print(f"   - Running: {stats['running']}")
    print(f"   - Pending: {stats['pending']}")
    
    # Attendre la complétion
    await asyncio.sleep(1.5)
    
    stats = tasks.get_stats()
    print(f"\n   Après complétion:")
    print(f"   - Total tasks: {stats['total_tasks']}")
    print(f"   - Completed: {stats['completed']}")
    print(f"   - Running: {stats['running']}")
    
    assert stats['completed'] >= 3, "Au moins 3 tâches devraient être complétées"
    print("✅ PASSÉ: Tâches multiples exécutées concurrentes")
    
    # Test 5: Annulation de tâche
    print("\n5️⃣ TEST: Annulation de tâche")
    print("-" * 80)
    
    task_id_cancel = tasks.create_task("target_cancel", "tool_cancel")
    tasks.start_background_task(task_id_cancel, mock_long_operation, 10)
    print(f"✅ Tâche créée pour annulation: {task_id_cancel}")
    
    # Annuler la tâche
    success = tasks.cancel_task(task_id_cancel)
    print(f"   Annulation: {success}")
    
    status = tasks.get_task_status(task_id_cancel)
    print(f"   Status après annulation: {status['status']}")
    
    assert status['status'] == TaskStatus.CANCELLED.value, "La tâche devrait être CANCELLED"
    print("✅ PASSÉ: Tâche annulée avec succès")
    
    # Test 6: Listing des tâches
    print("\n6️⃣ TEST: Listing des tâches")
    print("-" * 80)
    
    all_tasks = tasks.list_tasks()
    print(f"✅ Total tasks: {len(all_tasks)}")
    
    completed_tasks = tasks.list_tasks(status_filter=TaskStatus.COMPLETED)
    print(f"   Completed tasks: {len(completed_tasks)}")
    
    for task in completed_tasks[:3]:
        print(f"   - {task['task_id']}: {task['tool']} ({task['status']})")
    
    assert len(all_tasks) > 0, "Il devrait y avoir des tâches"
    print("✅ PASSÉ: Listing des tâches fonctionne")
    
    print("\n" + "=" * 80)
    print("✅ TOUS LES TESTS SONT PASSÉS!")
    print("=" * 80)
    print("\nRÉSUMÉ:")
    print("  ✅ Création de tâches")
    print("  ✅ Lancement en arrière-plan")
    print("  ✅ Progression des tâches")
    print("  ✅ Complétion des tâches")
    print("  ✅ Tâches concurrentes")
    print("  ✅ Annulation de tâches")
    print("  ✅ Listing des tâches")
    print("\n🟢 Le système de tâches en arrière-plan fonctionne correctement!")


if __name__ == "__main__":
    print("\n🚀 Démarrage des tests...\n")
    asyncio.run(test_background_task_execution())
