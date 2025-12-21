#!/usr/bin/env python3

import json
import subprocess
import sys
import os
import time


def test_mcp_server():
    """Test the MCP server functionality using real available tools"""
    print("🚀 Testing Kali MCP Server...")

    server_path = "/home/morningstar/Bureau/kali_mcp/MCP-Kali-Server/kali_mcp_server.py"
    python_path = "/home/morningstar/miniconda3/envs/trading_env/bin/python3"

    print(f"📁 Server path: {server_path}")
    print("-" * 50)

    try:
        # Start the MCP server process
        process = subprocess.Popen(
            [python_path, server_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,
        )

        # Give the server a moment to start
        time.sleep(1)

        # Test 1: Initialize connection
        print("🔗 Test 1: Initializing connection...")
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        }

        process.stdin.write(json.dumps(init_request) + "\n")
        process.stdin.flush()

        response_line = process.stdout.readline()
        if response_line:
            try:
                response = json.loads(response_line.strip())
                if "result" in response:
                    print(
                        f"✅ Initialize response: {response['result'].get('protocolVersion', 'OK')}"
                    )
                else:
                    print(f"⚠️  Initialize response: {response}")
            except json.JSONDecodeError:
                print(f"⚠️  Non-JSON response: {response_line.strip()}")

        # Test 2: List available tools
        print("\n🛠️  Test 2: Listing available tools...")
        tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }

        process.stdin.write(json.dumps(tools_request) + "\n")
        process.stdin.flush()

        response_line = process.stdout.readline()
        if response_line:
            try:
                response = json.loads(response_line.strip())
                result = response.get("result", {})
                tools = result.get("tools", [])
                print(f"✅ Found {len(tools)} tools:")
                for i, tool in enumerate(tools[:5]):  # Show first 5 tools
                    print(f"   {i + 1}. {tool.get('name', 'Unknown')}")
                if len(tools) > 5:
                    print(f"   ... and {len(tools) - 5} more tools")
            except json.JSONDecodeError:
                print(f"⚠️  Non-JSON response: {response_line.strip()}")

        # Test 3: Test server_health tool
        print("\n🏥 Test 3: Testing server_health tool...")
        health_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "server_health", "arguments": {}},
        }

        process.stdin.write(json.dumps(health_request) + "\n")
        process.stdin.flush()

        response_line = process.stdout.readline()
        if response_line:
            try:
                response = json.loads(response_line.strip())
                result = response.get("result", {})
                if "content" in result:
                    content = result["content"]
                    if isinstance(content, list) and len(content) > 0:
                        text_content = content[0].get("text", "")
                        print(f"✅ Server health check: {text_content[:100]}...")
                    else:
                        print(f"✅ Server health check: {str(result)[:100]}...")
                elif "error" in response:
                    print(f"⚠️  Server health error: {response['error']['message']}")
                else:
                    print(f"✅ Server health response: {str(response)[:100]}...")
            except json.JSONDecodeError:
                print(f"⚠️  Non-JSON response: {response_line.strip()}")

        # Test 4: Test nmap_scan tool with localhost
        print("\n🔍 Test 4: Testing nmap_scan tool...")
        nmap_request = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "nmap_scan",
                "arguments": {
                    "target": "127.0.0.1",
                    "scan_type": "quick",
                    "timeout": 30,
                },
            },
        }

        process.stdin.write(json.dumps(nmap_request) + "\n")
        process.stdin.flush()

        response_line = process.stdout.readline()
        if response_line:
            try:
                response = json.loads(response_line.strip())
                result = response.get("result", {})
                if "content" in result:
                    content = result["content"]
                    if isinstance(content, list) and len(content) > 0:
                        text_content = content[0].get("text", "")
                        print(f"✅ Nmap scan result: {text_content[:100]}...")
                    else:
                        print(f"✅ Nmap scan result: {str(result)[:100]}...")
                elif "error" in response:
                    print(f"⚠️  Nmap scan error: {response['error']['message']}")
                else:
                    print(f"✅ Nmap scan response: {str(response)[:100]}...")
            except json.JSONDecodeError:
                print(f"⚠️  Non-JSON response: {response_line.strip()}")

        # Test 5: Test execute_command tool
        print("\n⚡ Test 5: Testing execute_command tool...")
        command_request = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "execute_command",
                "arguments": {"command": "echo 'MCP Server Test Successful'"},
            },
        }

        process.stdin.write(json.dumps(command_request) + "\n")
        process.stdin.flush()

        response_line = process.stdout.readline()
        if response_line:
            try:
                response = json.loads(response_line.strip())
                result = response.get("result", {})
                if "content" in result:
                    content = result["content"]
                    if isinstance(content, list) and len(content) > 0:
                        text_content = content[0].get("text", "")
                        print(f"✅ Command execution: {text_content[:100]}...")
                    else:
                        print(f"✅ Command execution: {str(result)[:100]}...")
                elif "error" in response:
                    print(f"⚠️  Command execution error: {response['error']['message']}")
                else:
                    print(f"✅ Command execution response: {str(response)[:100]}...")
            except json.JSONDecodeError:
                print(f"⚠️  Non-JSON response: {response_line.strip()}")

        # Cleanup
        process.terminate()
        process.wait(timeout=5)

        print("\n" + "=" * 50)
        print("🎉 MCP Server test completed!")
        print("✅ The server appears to be working correctly.")
        print("📝 You can now use it with Gemini CLI.")

        return True

    except Exception as e:
        print(f"❌ Error testing MCP server: {e}")
        if "process" in locals():
            process.terminate()
        return False


def test_gemini_config():
    """Test Gemini CLI configuration"""
    print("\n🔧 Testing Gemini CLI configuration...")

    config_paths = [
        "/home/morningstar/.gemini/settings.json",
        "/home/morningstar/.config/gemini/settings.json",
    ]

    config_found = False
    for config_path in config_paths:
        if os.path.exists(config_path):
            config_found = True
            print(f"✅ Found Gemini config at: {config_path}")

            try:
                with open(config_path, "r") as f:
                    config = json.load(f)

                mcp_servers = config.get("mcpServers", {})
                if "kali-tools" in mcp_servers:
                    server_config = mcp_servers["kali-tools"]
                    command = server_config.get("command", "")
                    args = server_config.get("args", [])

                    print(f"   Command: {command}")
                    print(f"   Args: {args}")

                    # Verify the script exists
                    if args and os.path.exists(args[0]):
                        print(f"✅ Script path exists: {args[0]}")
                        return True
                    else:
                        print(
                            f"❌ Script path not found: {args[0] if args else 'No args'}"
                        )
                        return False
                else:
                    print("❌ kali-tools server not configured")
                    return False

            except Exception as e:
                print(f"❌ Error reading config: {e}")
                return False

    if not config_found:
        print("❌ No Gemini config found")
        return False


def test_database_connection():
    """Test the database functionality"""
    print("\n💾 Test 6: Testing database connection...")

    db_path = "/home/morningstar/Bureau/kali_mcp/MCP-Kali-Server/scan_results.db"

    try:
        import sqlite3

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Test basic database operations
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        print(f"✅ Database connected successfully")
        print(f"   Found {len(tables)} tables: {[table[0] for table in tables]}")

        conn.close()
        return True

    except Exception as e:
        print(f"⚠️  Database test failed: {e}")
        print("   Database will be created when first scan is performed")
        return False


if __name__ == "__main__":
    print("🧪 Kali MCP Server - Enhanced Test Suite")
    print("=" * 50)

    # Test 1: MCP Server functionality
    server_works = test_mcp_server()

    # Test 2: Gemini CLI configuration
    config_works = test_gemini_config()

    # Test 3: Database functionality
    db_works = test_database_connection()

    print("\n" + "=" * 50)
    print("📊 FINAL RESULTS:")
    print(f"🖥️  MCP Server: {'✅ WORKING' if server_works else '❌ FAILED'}")
    print(f"⚙️  Gemini Config: {'✅ CORRECT' if config_works else '❌ FAILED'}")
    print(f"💾 Database: {'✅ READY' if db_works else '⚠️  WILL BE CREATED'}")

    if server_works and config_works:
        print("\n🎉 ALL CRITICAL TESTS PASSED!")
        print("💡 Try running: gemini 'Use kali-tools to check server health'")
        print("💡 Or: gemini 'Use kali-tools to scan localhost with nmap'")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED!")
        print("🔧 Please check the configuration and try again.")
        sys.exit(1)
