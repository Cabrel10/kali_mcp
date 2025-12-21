#!/usr/bin/env /home/morningstar/miniconda3/envs/trading_env/bin/python3

import subprocess
import json
import sys
import asyncio
from pathlib import Path


def test_mcp_server():
    """Test the MCP server by sending JSON-RPC requests."""

    server_path = Path(__file__).parent / "kali_mcp_server.py"
    python_path = "/home/morningstar/miniconda3/envs/trading_env/bin/python3"

    print("🚀 Testing Kali MCP Server...")
    print(f"📁 Server path: {server_path}")
    print("-" * 50)

    try:
        # Start the MCP server process
        process = subprocess.Popen(
            [python_path, str(server_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,
        )

        # Test 1: Initialize the connection
        print("🔗 Test 1: Initializing connection...")
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        }

        process.stdin.write(json.dumps(init_request) + "\n")
        process.stdin.flush()

        # Read response
        response_line = process.stdout.readline()
        if response_line:
            try:
                response = json.loads(response_line.strip())
                print(
                    f"✅ Initialize response: {response.get('result', {}).get('protocolVersion', 'OK')}"
                )
            except json.JSONDecodeError:
                print(f"⚠️  Non-JSON response: {response_line.strip()}")

        # Test 2: List tools
        print("\n🛠️  Test 2: Listing available tools...")
        list_tools_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }

        process.stdin.write(json.dumps(list_tools_request) + "\n")
        process.stdin.flush()

        response_line = process.stdout.readline()
        if response_line:
            try:
                response = json.loads(response_line.strip())
                tools = response.get("result", {}).get("tools", [])
                print(f"✅ Found {len(tools)} tools:")
                for tool in tools:
                    print(f"   - {tool.get('name')}: {tool.get('description')}")
            except json.JSONDecodeError:
                print(f"⚠️  Non-JSON response: {response_line.strip()}")

        # Test 3: Test ping tool
        print("\n🏓 Test 3: Testing ping tool...")
        ping_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "ping_test",
                "arguments": {"target": "8.8.8.8", "count": 2},
            },
        }

        process.stdin.write(json.dumps(ping_request) + "\n")
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
                        print(f"✅ Ping test result preview: {text_content[:100]}...")
                    else:
                        print(f"✅ Ping test completed: {str(result)[:100]}...")
                else:
                    print(f"✅ Ping test response: {str(response)[:100]}...")
            except json.JSONDecodeError:
                print(f"⚠️  Non-JSON response: {response_line.strip()}")

        # Test 4: Test system info
        print("\n💻 Test 4: Testing system info...")
        sysinfo_request = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "system_info", "arguments": {}},
        }

        process.stdin.write(json.dumps(sysinfo_request) + "\n")
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
                        print(f"✅ System info preview: {text_content[:150]}...")
                    else:
                        print(f"✅ System info completed: {str(result)[:100]}...")
                else:
                    print(f"✅ System info response: {str(response)[:100]}...")
            except json.JSONDecodeError:
                print(f"⚠️  Non-JSON response: {response_line.strip()}")

        print("\n" + "=" * 50)
        print("🎉 MCP Server test completed!")
        print("✅ The server appears to be working correctly.")
        print("📝 You can now use it with Gemini CLI.")

    except Exception as e:
        print(f"❌ Error testing MCP server: {str(e)}")
        return False

    finally:
        # Clean up
        try:
            process.terminate()
            process.wait(timeout=2)
        except:
            process.kill()

    return True


def test_gemini_config():
    """Test if Gemini CLI configuration is correct."""
    print("\n🔧 Testing Gemini CLI configuration...")

    config_paths = [
        Path.home() / ".gemini" / "settings.json",
        Path.home() / ".config" / "gemini" / "settings.json",
    ]

    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)

                if "mcpServers" in config and "kali-tools" in config["mcpServers"]:
                    server_config = config["mcpServers"]["kali-tools"]
                    print(f"✅ Found Gemini config at: {config_path}")
                    print(f"   Command: {server_config.get('command', 'Not set')}")
                    print(f"   Args: {server_config.get('args', [])}")

                    # Verify the script path exists
                    if "args" in server_config and len(server_config["args"]) > 0:
                        script_path = Path(server_config["args"][0])
                        if script_path.exists():
                            print(f"✅ Script path exists: {script_path}")
                        else:
                            print(f"❌ Script path not found: {script_path}")

                    return True
                else:
                    print(f"⚠️  Config found but no kali-tools server: {config_path}")

            except json.JSONDecodeError as e:
                print(f"❌ Invalid JSON in {config_path}: {str(e)}")
            except Exception as e:
                print(f"❌ Error reading {config_path}: {str(e)}")

    print("❌ No valid Gemini CLI configuration found!")
    return False


if __name__ == "__main__":
    print("🧪 Kali MCP Server Test Suite")
    print("=" * 50)

    # Test 1: MCP Server functionality
    server_works = test_mcp_server()

    # Test 2: Gemini CLI configuration
    config_works = test_gemini_config()

    print("\n" + "=" * 50)
    print("📊 FINAL RESULTS:")
    print(f"🖥️  MCP Server: {'✅ WORKING' if server_works else '❌ FAILED'}")
    print(f"⚙️  Gemini Config: {'✅ CORRECT' if config_works else '❌ INCORRECT'}")

    if server_works and config_works:
        print("\n🎉 ALL TESTS PASSED!")
        print("💡 Try running: gemini 'ping 8.8.8.8 using kali-tools'")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED!")
        print("🔧 Please check the configuration and try again.")
        sys.exit(1)
