"""Tactical modules for Kali MCP Server"""

from .network_recon import NetworkRecon
from .vulnerability_scanner import VulnerabilityScanner
from .web_assault import WebAssault

__all__ = [
    'NetworkRecon',
    'VulnerabilityScanner',
    'WebAssault'
]
