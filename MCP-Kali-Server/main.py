#!/usr/bin/env python3
"""
Kali MCP Tactical Server - Main Entry Point
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.server import main

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
