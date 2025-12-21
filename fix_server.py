#!/usr/bin/env python3

import os


def fix_mcp_server():
    """Fix the corrupted MCP server file by removing garbage code after main section"""

    server_file = "MCP-Kali-Server/kali_mcp_server.py"
    backup_file = "MCP-Kali-Server/kali_mcp_server_corrupted.py"

    print(f"🔧 Fixing corrupted MCP server file: {server_file}")

    # Create backup
    if os.path.exists(server_file):
        print(f"📦 Creating backup: {backup_file}")
        with open(server_file, "r") as src, open(backup_file, "w") as dst:
            dst.write(src.read())

    # Read the corrupted file
    with open(server_file, "r") as f:
        lines = f.readlines()

    print(f"📊 Original file has {len(lines)} lines")

    # Find the end of the main section - look for the last line of proper main block
    end_line = None
    for i, line in enumerate(lines):
        # Look for the end of the main exception handling
        if "raise" in line and i > 4120 and i < 4135:
            # Check if this is the raise in main exception handler
            # Look backwards to see if we're in the main block
            in_main = False
            for j in range(max(0, i - 10), i):
                if 'if __name__ == "__main__"' in lines[j]:
                    in_main = True
                    break
                if (
                    "logger.error" in lines[j]
                    and "Failed to start MCP server" in lines[j]
                ):
                    in_main = True
                    break

            if in_main:
                end_line = i + 1  # Include the raise line
                break

    if end_line is None:
        print("❌ Could not find end of main section, looking for alternative markers")
        # Alternative: find the line with just "raise" after exception handling
        for i, line in enumerate(lines):
            if line.strip() == "raise" and i > 4120:
                end_line = i + 1
                break

    if end_line is None:
        print("❌ Could not automatically determine end line, using manual approach")
        # Manual fallback - we know from the error it should be around line 4129
        end_line = 4129

    print(f"✂️  Truncating file at line {end_line}")

    # Write the clean version
    with open(server_file, "w") as f:
        for i in range(end_line):
            if i < len(lines):
                f.write(lines[i])

    print(f"✅ Fixed server file now has {end_line} lines")
    print(f"🗑️  Removed {len(lines) - end_line} corrupted lines")

    # Verify syntax
    print("🔍 Verifying syntax...")
    try:
        with open(server_file, "r") as f:
            compile(f.read(), server_file, "exec")
        print("✅ Syntax check passed!")
        return True
    except SyntaxError as e:
        print(f"❌ Syntax error still present: {e}")
        print(f"   Line {e.lineno}: {e.text}")
        return False


if __name__ == "__main__":
    success = fix_mcp_server()
    if success:
        print("🎉 MCP server file successfully fixed!")
    else:
        print("❌ Fix failed, manual intervention required")
