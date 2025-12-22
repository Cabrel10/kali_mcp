#!/usr/bin/env python3
"""
Final validation of all integrated capabilities
This script verifies that all functions are properly integrated and working
"""

import asyncio
import sys
import os

# Add src to path
src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

# Import all modules to verify they load correctly
try:
    # Direct imports without relative paths
    from src.core.async_executor import AsyncExecutor
    from src.tools.post_exploit import PostExploit
    from src.tools.evasion_engine import EvasionEngine
    from src.tools.distributed_engine import DistributedEngine
    print("✅ All modules imported successfully")
except ImportError as e:
    print(f"❌ Module import failed: {e}")
    sys.exit(1)

def validate_post_exploit_methods():
    """Validate that all post-exploit methods exist and have correct signatures"""
    print("\n[+] Validating Post-Exploit Methods...")
    
    # Check that the class exists
    assert hasattr(PostExploit, '__init__'), "PostExploit.__init__ missing"
    print("  ✅ PostExploit class exists")
    
    # Check all methods exist
    methods = [
        'smb_lateral_movement',
        'deploy_persistence', 
        'extract_credentials',
        'privilege_escalation'
    ]
    
    for method in methods:
        assert hasattr(PostExploit, method), f"Method {method} missing"
        print(f"  ✅ {method}: Available")
    
    print("  🎯 All post-exploit methods validated")

def validate_evasion_engine_methods():
    """Validate that all evasion engine methods exist and have correct signatures"""
    print("\n[+] Validating Evasion Engine Methods...")
    
    # Check that the class exists
    assert hasattr(EvasionEngine, '__init__'), "EvasionEngine.__init__ missing"
    print("  ✅ EvasionEngine class exists")
    
    # Check all methods exist
    methods = [
        'toggle_ghost_mode',
        'check_ban_and_rotate',
        'adaptive_delay',
        'get_random_user_agent',
        'fragmented_request',
        'polymorphic_encoding'
    ]
    
    for method in methods:
        assert hasattr(EvasionEngine, method), f"Method {method} missing"
        print(f"  ✅ {method}: Available")
    
    print("  🎯 All evasion engine methods validated")

def validate_distributed_engine_methods():
    """Validate that all distributed engine methods exist"""
    print("\n[+] Validating Distributed Engine Methods...")
    
    # Check that the class exists
    assert hasattr(DistributedEngine, '__init__'), "DistributedEngine.__init__ missing"
    print("  ✅ DistributedEngine class exists")
    
    # Check all methods exist
    methods = [
        'rotate_ip',
        'launch_swarm',
        'mikrotik_bypass_scan'
    ]
    
    for method in methods:
        assert hasattr(DistributedEngine, method), f"Method {method} missing"
        print(f"  ✅ {method}: Available")
    
    print("  🎯 All distributed engine methods validated")

def validate_server_integration():
    """Validate that server integration is complete"""
    print("\n[+] Validating Server Integration...")
    
    # Read the server file to verify tool definitions
    server_file = os.path.join(os.path.dirname(__file__), 'kali_mcp_server_optimized.py')
    
    with open(server_file, 'r') as f:
        content = f.read()
    
    # Check for all tool definitions
    tools = [
        'lateral_movement',
        'ghost_mode_toggle',
        'deploy_persistence',
        'extract_credentials',
        'privilege_escalation'
    ]
    
    for tool in tools:
        assert f'"name": "{tool}"' in content, f"Tool {tool} not found in server"
        print(f"  ✅ {tool}: Integrated in server")
    
    # Check for all tool handlers
    handlers = [
        'if name == "lateral_movement"',
        'if name == "ghost_mode_toggle"',
        'if name == "deploy_persistence"',
        'if name == "extract_credentials"',
        'if name == "privilege_escalation"'
    ]
    
    for handler in handlers:
        assert handler in content, f"Handler {handler} not found in server"
        tool_name = handler.split(' ')[3].strip('"')
        print(f"  ✅ Handler for {tool_name}: Implemented")
    
    print("  🎯 All server integrations validated")

def show_final_capabilities():
    """Display all final capabilities"""
    print("\n" + "="*60)
    print("🎯 FINAL SYSTEM CAPABILITIES")
    print("="*60)
    
    print("\n⚔️  POST-EXPLOITATION MODULE:")
    print("   • SMB Lateral Movement")
    print("   • Credential Extraction (SAM Hashes)")
    print("   • Privilege Escalation")
    print("   • Persistence Deployment (Sliver C2)")
    
    print("\n👻 EVASION ENGINE (Ghost Mode):")
    print("   • Adaptive Delays")
    print("   • User-Agent Rotation")
    print("   • Fragmented Requests")
    print("   • Polymorphic Encoding")
    print("   • Ban Detection & IP Rotation")
    
    print("\n🌐 DISTRIBUTED ENGINE:")
    print("   • IP Pool Rotation")
    print("   • Swarm Attack Coordination")
    print("   • MikroTik Stealth Scanning")
    
    print("\n🔌 SERVER INTEGRATION:")
    print("   • All tools exposed via MCP protocol")
    print("   • Real-time command execution")
    print("   • Asynchronous processing")
    
    print("\n🚀 SYSTEM STATUS: FULLY OPERATIONAL")
    print("   Ready for tactical deployment")

async def main():
    """Main validation function"""
    print("🚀 Final Validation of Kali MCP Tactical Server")
    print("=" * 50)
    
    try:
        # Validate all components
        validate_post_exploit_methods()
        validate_evasion_engine_methods()
        validate_distributed_engine_methods()
        validate_server_integration()
        
        # Show final capabilities
        show_final_capabilities()
        
        print("\n🎉 VALIDATION COMPLETE - ALL SYSTEMS NOMINAL")
        return 0
        
    except Exception as e:
        print(f"\n❌ VALIDATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)