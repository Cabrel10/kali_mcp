#!/usr/bin/env /home/morningstar/miniconda3/envs/trading_env/bin/python3

import subprocess
import json
import sys
from pathlib import Path


def test_tool_detection():
    """Test different methods to detect Kali tools"""

    tools_to_check = [
        "nmap",
        "gobuster",
        "dirb",
        "nikto",
        "sqlmap",
        "msfconsole",
        "hydra",
        "john",
        "wpscan",
        "enum4linux",
        "amass",
        "theharvester",
        "searchsploit",
        "hashcat",
        "reaver",
        "aircrack-ng",
        "tshark",
        "bettercap",
    ]

    print("🔧 Testing Kali Tools Detection")
    print("=" * 50)

    results = {}

    for tool in tools_to_check:
        print(f"\n📡 Testing: {tool}")

        # Method 1: which command
        try:
            result1 = subprocess.run(["which", tool], capture_output=True, text=True)
            which_success = result1.returncode == 0
            which_path = result1.stdout.strip() if which_success else "Not found"
        except:
            which_success = False
            which_path = "Error"

        # Method 2: command -v
        try:
            result2 = subprocess.run(
                ["bash", "-c", f"command -v {tool}"], capture_output=True, text=True
            )
            command_success = result2.returncode == 0
            command_path = result2.stdout.strip() if command_success else "Not found"
        except:
            command_success = False
            command_path = "Error"

        # Method 3: Direct execution test
        try:
            result3 = subprocess.run(
                [tool, "--version"], capture_output=True, text=True, timeout=5
            )
            exec_success = result3.returncode == 0
        except:
            try:
                result3 = subprocess.run(
                    [tool, "-h"], capture_output=True, text=True, timeout=5
                )
                exec_success = result3.returncode == 0
            except:
                exec_success = False

        # Store results
        results[tool] = {
            "which": {"success": which_success, "path": which_path},
            "command": {"success": command_success, "path": command_path},
            "executable": exec_success,
            "overall": which_success or command_success,
        }

        # Print status
        status = "✅" if results[tool]["overall"] else "❌"
        print(
            f"  {status} which: {which_success} | command -v: {command_success} | executable: {exec_success}"
        )
        if results[tool]["overall"]:
            print(f"     Path: {which_path if which_success else command_path}")

    return results


def generate_fixed_server_health_function(results):
    """Generate corrected server_health function code"""

    available_tools = [tool for tool, data in results.items() if data["overall"]]

    fixed_code = '''
# CORRECTED server_health function
@mcp.tool()
async def server_health() -> str:
    """
    Checks the status of the Kali server and the availability of essential tools.
    Essential for starting a pentest or CTF. Logs execution.
    """
    inputs = {}

    tools_to_check = [
        "nmap", "gobuster", "dirb", "nikto", "sqlmap",
        "msfconsole", "hydra", "john", "wpscan", "enum4linux"
    ]

    tool_status = {}
    for tool in tools_to_check:
        try:
            # Use which command for reliable detection
            result = subprocess.run(['which', tool], capture_output=True, text=True, timeout=5)
            tool_status[tool] = result.returncode == 0
        except:
            tool_status[tool] = False

    available_tools = [t for t, s in tool_status.items() if s]
    response_machine = {"status": "ok", "tools": tool_status}
    response_user = f"Server status: OK. Available tools: {', '.join(available_tools) if available_tools else 'No tools detected'}"

    outputs = {"machine_response": response_machine, "user_response": response_user}
    log_tool_execution("server_health", inputs, outputs)

    return json.dumps({"machine": response_machine, "user": response_user}, indent=2)
'''

    return fixed_code


def create_installation_script(missing_tools):
    """Create script to install missing tools"""

    if not missing_tools:
        return "# All tools are already installed!"

    script = f"""#!/bin/bash

# Install missing Kali tools
echo "🔧 Installing missing Kali tools..."

# Update package list
sudo apt update

# Install missing tools
"""

    for tool in missing_tools:
        script += f"""
echo "Installing {tool}..."
sudo apt install -y {tool}
"""

    script += """
echo "✅ Installation complete!"
echo "Run the test script again to verify installation."
"""

    return script


def main():
    print("🛠️ KALI MCP TOOLS DIAGNOSTIC AND FIX SCRIPT")
    print("=" * 60)

    # Test tool detection
    results = test_tool_detection()

    # Generate summary
    print("\n📊 SUMMARY REPORT:")
    print("=" * 30)

    available = [tool for tool, data in results.items() if data["overall"]]
    missing = [tool for tool, data in results.items() if not data["overall"]]

    print(f"✅ Available tools ({len(available)}): {', '.join(available)}")
    print(f"❌ Missing tools ({len(missing)}): {', '.join(missing)}")

    # Generate fixes
    print("\n🔧 GENERATING FIXES:")
    print("=" * 25)

    # 1. Fixed server_health function
    fixed_code = generate_fixed_server_health_function(results)

    try:
        with open("/tmp/fixed_server_health.py", "w") as f:
            f.write(fixed_code)
        print("✅ Fixed server_health function saved to: /tmp/fixed_server_health.py")
    except Exception as e:
        print(f"❌ Failed to save fixed function: {e}")

    # 2. Installation script for missing tools
    install_script = create_installation_script(missing)

    try:
        with open("/tmp/install_missing_tools.sh", "w") as f:
            f.write(install_script)
        subprocess.run(["chmod", "+x", "/tmp/install_missing_tools.sh"])
        print("✅ Installation script saved to: /tmp/install_missing_tools.sh")
    except Exception as e:
        print(f"❌ Failed to save installation script: {e}")

    # 3. Test results JSON
    try:
        with open("/tmp/tool_detection_results.json", "w") as f:
            json.dump(results, f, indent=2)
        print("✅ Detailed results saved to: /tmp/tool_detection_results.json")
    except Exception as e:
        print(f"❌ Failed to save results: {e}")

    print("\n🚀 NEXT STEPS:")
    print("=" * 15)
    print("1. Install missing tools: sudo /tmp/install_missing_tools.sh")
    print(
        "2. Replace server_health function in kali_mcp_server.py with the fixed version"
    )
    print("3. Restart MCP server: pkill -f kali_mcp_server.py && restart")
    print("4. Test with: gemini 'Use kali-tools server_health to check status'")

    # Return status code
    if missing:
        print(f"\n⚠️  {len(missing)} tools need to be installed!")
        return 1
    else:
        print(f"\n🎉 All {len(available)} tools are properly installed!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
