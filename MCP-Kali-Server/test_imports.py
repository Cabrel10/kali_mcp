#!/usr/bin/env python3
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

print("Testing imports...")

try:
    from src.core.async_executor import AsyncExecutor
    print("✅ AsyncExecutor imported successfully")
except Exception as e:
    print(f"❌ AsyncExecutor import failed: {e}")

try:
    from src.core.task_manager import TaskManager
    print("✅ TaskManager imported successfully")
except Exception as e:
    print(f"❌ TaskManager import failed: {e}")

try:
    from src.core.database import DatabaseManager
    print("✅ DatabaseManager imported successfully")
except Exception as e:
    print(f"❌ DatabaseManager import failed: {e}")

try:
    from src.modules.network_recon import NetworkRecon
    print("✅ NetworkRecon imported successfully")
except Exception as e:
    print(f"❌ NetworkRecon import failed: {e}")

try:
    from src.modules.vulnerability_scanner import VulnerabilityScanner
    print("✅ VulnerabilityScanner imported successfully")
except Exception as e:
    print(f"❌ VulnerabilityScanner import failed: {e}")

try:
    from src.tools.distributed_engine import DistributedEngine
    print("✅ DistributedEngine imported successfully")
except Exception as e:
    print(f"❌ DistributedEngine import failed: {e}")

try:
    from src.core.triage import TriageEngine
    print("✅ TriageEngine imported successfully")
except Exception as e:
    print(f"❌ TriageEngine import failed: {e}")

try:
    from src.tools.document_analyzer import DocumentAnalyzer
    print("✅ DocumentAnalyzer imported successfully")
except Exception as e:
    print(f"❌ DocumentAnalyzer import failed: {e}")

try:
    from src.tools.database_expert import DatabaseExpert
    print("✅ DatabaseExpert imported successfully")
except Exception as e:
    print(f"❌ DatabaseExpert import failed: {e}")

try:
    from src.tools.reverse_engineer import ReverseEngineer
    print("✅ ReverseEngineer imported successfully")
except Exception as e:
    print(f"❌ ReverseEngineer import failed: {e}")

try:
    from src.tools.osint_hunter import OSINTHunter
    print("✅ OSINTHunter imported successfully")
except Exception as e:
    print(f"❌ OSINTHunter import failed: {e}")

try:
    from src.tools.wireless_expert import WirelessExpert
    print("✅ WirelessExpert imported successfully")
except Exception as e:
    print(f"❌ WirelessExpert import failed: {e}")

try:
    from src.tools.post_exploit import PostExploit
    print("✅ PostExploit imported successfully")
except Exception as e:
    print(f"❌ PostExploit import failed: {e}")

try:
    from src.tools.evasion_engine import EvasionEngine
    print("✅ EvasionEngine imported successfully")
except Exception as e:
    print(f"❌ EvasionEngine import failed: {e}")

print("Import test completed.")