#!/usr/bin/env python3
"""
Document Analyzer - Forensics and document manipulation
Analyzes documents for metadata, malicious content, and can modify them
"""

import os
import re
import json
import hashlib
from typing import Dict, List, Any, Optional
from pathlib import Path

from ..core.config import TacticalConfig
from ..core.async_executor import AsyncExecutor


class DocumentAnalyzer:
    """
    Advanced document analysis and manipulation
    Tools: exiftool (metadata), oletools (malware detection), python-docx (modification)
    """
    
    def __init__(self):
        """Initialize document analyzer"""
        self.config = TacticalConfig
        self.executor = AsyncExecutor()
    
    async def analyze_document(
        self,
        file_path: str,
        deep_scan: bool = False
    ) -> Dict[str, Any]:
        """
        Comprehensive document analysis
        
        Args:
            file_path: Path to document file
            deep_scan: Perform deep malware analysis
            
        Returns:
            Dictionary with analysis results
        """
        if not Path(file_path).exists():
            return {'error': 'File not found'}
        
        file_path = str(Path(file_path).resolve())
        file_ext = Path(file_path).suffix.lower()
        
        results = {
            'file_path': file_path,
            'file_name': Path(file_path).name,
            'file_size': Path(file_path).stat().st_size,
            'file_type': file_ext,
            'hash': self._calculate_hash(file_path),
            'metadata': {},
            'security_analysis': {},
            'extracted_data': {}
        }
        
        # Extract metadata with exiftool
        results['metadata'] = await self._extract_metadata(file_path)
        
        # Security analysis for Office documents
        if file_ext in ['.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx']:
            results['security_analysis'] = await self._analyze_office_security(file_path, deep_scan)
        
        # PDF analysis
        elif file_ext == '.pdf':
            results['security_analysis'] = await self._analyze_pdf_security(file_path)
        
        # Extract interesting data
        results['extracted_data'] = await self._extract_interesting_data(file_path)
        
        # Generate summary
        results['summary'] = self._generate_analysis_summary(results)
        
        return results
    
    def _calculate_hash(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                return {
                    'md5': hashlib.md5(data).hexdigest(),
                    'sha256': hashlib.sha256(data).hexdigest()
                }
        except Exception as e:
            return {'error': str(e)}
    
    async def _extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata using exiftool"""
        has_exiftool = await self.executor.check_tool_available('exiftool')
        
        if not has_exiftool:
            return {'error': 'exiftool not available'}
        
        command = f"exiftool -json '{file_path}'"
        stdout, stderr, returncode = await self.executor.run_command(command, timeout=30)
        
        if returncode != 0:
            return {'error': 'Failed to extract metadata'}
        
        try:
            data = json.loads(stdout)
            if data and isinstance(data, list):
                metadata = data[0]
                
                # Extract key fields
                return {
                    'author': metadata.get('Author') or metadata.get('Creator'),
                    'creation_date': metadata.get('CreateDate') or metadata.get('CreationDate'),
                    'modification_date': metadata.get('ModifyDate') or metadata.get('ModDate'),
                    'software': metadata.get('Software') or metadata.get('Producer') or metadata.get('Application'),
                    'title': metadata.get('Title'),
                    'subject': metadata.get('Subject'),
                    'company': metadata.get('Company'),
                    'last_modified_by': metadata.get('LastModifiedBy'),
                    'raw_metadata': metadata
                }
        except json.JSONDecodeError:
            return {'error': 'Failed to parse metadata'}
        
        return {}
    
    async def _analyze_office_security(
        self,
        file_path: str,
        deep_scan: bool
    ) -> Dict[str, Any]:
        """Analyze Office document for security threats"""
        security = {
            'threat_level': 'unknown',
            'has_macros': False,
            'suspicious_indicators': [],
            'recommendations': []
        }
        
        # Check for macros with oletools (if available)
        has_oletools = await self.executor.check_tool_available('olevba')
        
        if has_oletools:
            command = f"olevba --json '{file_path}'"
            stdout, stderr, returncode = await self.executor.run_command(command, timeout=60)
            
            if returncode == 0 and stdout.strip():
                try:
                    oledata = json.loads(stdout)
                    macros = oledata.get('macros', [])
                    
                    if macros:
                        security['has_macros'] = True
                        security['macro_count'] = len(macros)
                        
                        # Check for suspicious keywords
                        suspicious_keywords = [
                            'AutoOpen', 'AutoExec', 'Document_Open', 'Workbook_Open',
                            'Shell', 'WScript.Shell', 'CreateObject', 'GetObject',
                            'URLDownloadToFile', 'powershell', 'cmd.exe', 'eval'
                        ]
                        
                        macro_code = str(macros).lower()
                        found_suspicious = []
                        
                        for keyword in suspicious_keywords:
                            if keyword.lower() in macro_code:
                                found_suspicious.append(keyword)
                        
                        if found_suspicious:
                            security['suspicious_indicators'] = found_suspicious
                            security['threat_level'] = 'HIGH' if len(found_suspicious) > 3 else 'MEDIUM'
                        else:
                            security['threat_level'] = 'LOW'
                    else:
                        security['threat_level'] = 'CLEAN'
                
                except json.JSONDecodeError:
                    # Try text parsing
                    if 'suspicious' in stdout.lower() or 'macro' in stdout.lower():
                        security['has_macros'] = True
                        security['threat_level'] = 'MEDIUM'
        
        # Additional deep scan with oleid (if available and requested)
        if deep_scan:
            has_oleid = await self.executor.check_tool_available('oleid')
            if has_oleid:
                command = f"oleid '{file_path}'"
                stdout, stderr, returncode = await self.executor.run_command(command, timeout=30)
                
                if 'encrypted' in stdout.lower():
                    security['suspicious_indicators'].append('Document is encrypted')
                if 'external' in stdout.lower():
                    security['suspicious_indicators'].append('Contains external relationships')
        
        # Generate recommendations
        if security['threat_level'] in ['HIGH', 'MEDIUM']:
            security['recommendations'].append('⚠️  Do not enable macros unless from trusted source')
            security['recommendations'].append('🔍 Analyze in sandbox environment')
        elif security['has_macros']:
            security['recommendations'].append('⚠️  Document contains macros - verify source')
        
        return security
    
    async def _analyze_pdf_security(self, file_path: str) -> Dict[str, Any]:
        """Analyze PDF for security threats"""
        security = {
            'threat_level': 'unknown',
            'has_javascript': False,
            'has_forms': False,
            'suspicious_indicators': [],
            'recommendations': []
        }
        
        # Use pdfinfo (if available)
        has_pdfinfo = await self.executor.check_tool_available('pdfinfo')
        
        if has_pdfinfo:
            command = f"pdfinfo '{file_path}'"
            stdout, stderr, returncode = await self.executor.run_command(command, timeout=30)
            
            if 'javascript' in stdout.lower():
                security['has_javascript'] = True
                security['suspicious_indicators'].append('Contains JavaScript')
            
            if 'form' in stdout.lower():
                security['has_forms'] = True
        
        # Scan for suspicious patterns in PDF
        try:
            with open(file_path, 'rb') as f:
                content = f.read(10000)  # Read first 10KB
                content_str = str(content)
                
                suspicious_patterns = [
                    '/JavaScript', '/JS', '/Launch', '/OpenAction',
                    '/AA', '/AcroForm', '/XFA'
                ]
                
                for pattern in suspicious_patterns:
                    if pattern in content_str:
                        security['suspicious_indicators'].append(f'Contains {pattern}')
        except Exception:
            pass
        
        # Determine threat level
        if len(security['suspicious_indicators']) > 2:
            security['threat_level'] = 'HIGH'
        elif security['suspicious_indicators']:
            security['threat_level'] = 'MEDIUM'
        else:
            security['threat_level'] = 'LOW'
        
        return security
    
    async def _extract_interesting_data(self, file_path: str) -> Dict[str, Any]:
        """Extract potentially interesting data from document"""
        extracted = {
            'urls': [],
            'emails': [],
            'ip_addresses': [],
            'file_paths': []
        }
        
        # Read file content (text-based extraction)
        try:
            # For text extraction, use strings command
            command = f"strings '{file_path}' | head -10000"
            stdout, stderr, returncode = await self.executor.run_command(command, timeout=30)
            
            if returncode == 0:
                # Extract URLs
                url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
                extracted['urls'] = list(set(re.findall(url_pattern, stdout)))[:20]
                
                # Extract emails
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                extracted['emails'] = list(set(re.findall(email_pattern, stdout)))[:20]
                
                # Extract IP addresses
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ips = re.findall(ip_pattern, stdout)
                # Filter out version numbers and dates
                extracted['ip_addresses'] = [
                    ip for ip in set(ips)
                    if all(0 <= int(octet) <= 255 for octet in ip.split('.'))
                ][:20]
                
                # Extract Windows/Unix paths
                win_path_pattern = r'[A-Z]:\\[^\s:*?"<>|]+'
                unix_path_pattern = r'/[a-zA-Z0-9_\-./]+'
                
                win_paths = re.findall(win_path_pattern, stdout)
                unix_paths = [p for p in re.findall(unix_path_pattern, stdout) if len(p) > 5]
                
                extracted['file_paths'] = list(set(win_paths + unix_paths))[:20]
        
        except Exception:
            pass
        
        return extracted
    
    def _generate_analysis_summary(self, results: Dict[str, Any]) -> str:
        """Generate human-readable analysis summary"""
        lines = []
        lines.append("📄 DOCUMENT ANALYSIS SUMMARY")
        lines.append("=" * 60)
        lines.append(f"File: {results['file_name']}")
        lines.append(f"Size: {results['file_size']} bytes")
        lines.append(f"Type: {results['file_type']}")
        
        # Hash
        if results.get('hash'):
            lines.append(f"SHA256: {results['hash'].get('sha256', 'N/A')[:32]}...")
        
        lines.append("")
        
        # Metadata
        metadata = results.get('metadata', {})
        if metadata and not metadata.get('error'):
            lines.append("📊 Metadata:")
            if metadata.get('author'):
                lines.append(f"  Author: {metadata['author']}")
            if metadata.get('software'):
                lines.append(f"  Software: {metadata['software']}")
            if metadata.get('creation_date'):
                lines.append(f"  Created: {metadata['creation_date']}")
            if metadata.get('company'):
                lines.append(f"  Company: {metadata['company']}")
            lines.append("")
        
        # Security analysis
        security = results.get('security_analysis', {})
        if security:
            threat_emoji = {
                'HIGH': '🔴',
                'MEDIUM': '🟠',
                'LOW': '🟢',
                'CLEAN': '✅'
            }
            
            threat = security.get('threat_level', 'unknown')
            emoji = threat_emoji.get(threat, '⚪')
            
            lines.append(f"🛡️ Security Analysis: {emoji} {threat}")
            
            if security.get('has_macros'):
                lines.append(f"  ⚠️  Contains macros")
            
            if security.get('suspicious_indicators'):
                lines.append("  Suspicious indicators:")
                for indicator in security['suspicious_indicators'][:5]:
                    lines.append(f"    • {indicator}")
            
            lines.append("")
        
        # Extracted data
        extracted = results.get('extracted_data', {})
        if any(extracted.values()):
            lines.append("🔍 Extracted Data:")
            if extracted.get('urls'):
                lines.append(f"  URLs: {len(extracted['urls'])} found")
            if extracted.get('emails'):
                lines.append(f"  Emails: {len(extracted['emails'])} found")
            if extracted.get('ip_addresses'):
                lines.append(f"  IP addresses: {len(extracted['ip_addresses'])} found")
            if extracted.get('file_paths'):
                lines.append(f"  File paths: {len(extracted['file_paths'])} found")
        
        lines.append("=" * 60)
        
        return '\n'.join(lines)
    
    async def modify_document(
        self,
        source_path: str,
        modifications: Dict[str, str],
        output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Modify document content (Word documents only)
        
        Args:
            source_path: Source document path
            modifications: Dictionary of {old_text: new_text}
            output_path: Output path (default: source_path with _modified suffix)
            
        Returns:
            Dictionary with modification results
        """
        if not Path(source_path).exists():
            return {'error': 'Source file not found'}
        
        file_ext = Path(source_path).suffix.lower()
        
        if file_ext not in ['.docx']:
            return {
                'error': 'Only .docx files supported for modification',
                'suggestion': 'Convert .doc to .docx first'
            }
        
        # Output path
        if not output_path:
            base = Path(source_path).stem
            parent = Path(source_path).parent
            output_path = str(parent / f"{base}_modified.docx")
        
        try:
            # This would require python-docx library
            # For now, return a placeholder
            return {
                'status': 'not_implemented',
                'message': 'Document modification requires python-docx library',
                'source': source_path,
                'output': output_path,
                'modifications_requested': len(modifications)
            }
        
        except Exception as e:
            return {'error': str(e)}


if __name__ == "__main__":
    # Test the module
    import asyncio
    
    async def test():
        analyzer = DocumentAnalyzer()
        
        print("Testing DocumentAnalyzer...")
        print("=" * 60)
        
        # Create a test file
        test_file = "/tmp/test_doc.txt"
        with open(test_file, 'w') as f:
            f.write("Test document\nContains email: test@example.com\nURL: https://example.com\n")
        
        print("\n1. Analyzing test document:")
        result = await analyzer.analyze_document(test_file)
        print(result.get('summary', 'No summary'))
        
        # Cleanup
        Path(test_file).unlink(missing_ok=True)
        
        print("\n✅ Tests completed")
    
    asyncio.run(test())
