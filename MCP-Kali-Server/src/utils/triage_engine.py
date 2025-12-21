#!/usr/bin/env python3
"""
Triage Engine - Intelligence and decision-making
Analyzes scan results and generates tactical recommendations
"""

from typing import Dict, List, Any, Optional


class TriageEngine:
    """
    Intelligent triage and decision engine
    Analyzes reconnaissance results and suggests next actions
    """
    
    # Decision matrices for different scenarios
    DECISION_MATRIX = {
        'open_port_80': ['web_arsenal', 'directory_fuzzing', 'nuclei_scan'],
        'open_port_443': ['web_arsenal', 'ssl_analysis', 'nuclei_scan'],
        'open_port_22': ['ssh_audit', 'hydra_ssh', 'check_version'],
        'open_port_21': ['ftp_anonymous', 'ftp_brute'],
        'open_port_445': ['smb_enum', 'eternal_blue_check', 'smb_brute'],
        'open_port_3306': ['mysql_enum', 'default_creds', 'sql_injection'],
        'open_port_3389': ['rdp_bluekeep', 'rdp_brute'],
        'open_port_8291': ['mikrotik_cve_check', 'winbox_exploit'],
        'wordpress_detected': ['wpscan', 'nuclei_wordpress', 'plugin_enum'],
        'php_myadmin': ['default_creds', 'phpmyadmin_exploit'],
        'jenkins_detected': ['jenkins_script', 'cve_2024_23897'],
        'apache_detected': ['path_traversal', 'mod_vulnerabilities'],
        'nginx_detected': ['version_cve_check', 'misconfig_check'],
        'critical_cve_found': ['exploit_search', 'metasploit_module'],
        'sql_injection_found': ['database_extraction', 'hash_cracking'],
        'xss_found': ['session_hijacking', 'cookie_theft']
    }
    
    # Technology-specific attack patterns
    ATTACK_PATTERNS = {
        'wordpress': {
            'detection_keywords': ['wp-content', 'wp-includes', 'wordpress'],
            'tools': ['wpscan', 'nuclei-wordpress'],
            'exploits': ['CVE-2024-27956', 'plugin-vulns'],
            'priority': 'high'
        },
        'joomla': {
            'detection_keywords': ['joomla', 'components/com_'],
            'tools': ['joomscan', 'nuclei-joomla'],
            'exploits': ['CVE-2023-23752'],
            'priority': 'high'
        },
        'drupal': {
            'detection_keywords': ['drupal', '/sites/default/'],
            'tools': ['droopescan', 'nuclei-drupal'],
            'exploits': ['drupalgeddon'],
            'priority': 'high'
        },
        'jenkins': {
            'detection_keywords': ['jenkins', 'hudson'],
            'tools': ['nuclei-jenkins'],
            'exploits': ['CVE-2024-23897', 'CVE-2023-26486'],
            'priority': 'critical'
        },
        'apache': {
            'detection_keywords': ['apache', 'httpd'],
            'tools': ['nuclei-apache'],
            'exploits': ['CVE-2021-41773', 'CVE-2021-40438'],
            'priority': 'medium'
        },
        'nginx': {
            'detection_keywords': ['nginx'],
            'tools': ['nuclei-nginx'],
            'exploits': ['CVE-2021-23017'],
            'priority': 'medium'
        },
        'mikrotik': {
            'detection_keywords': ['mikrotik', 'routeros', 'winbox'],
            'tools': ['mikrotik-exploit', 'winbox-scanner'],
            'exploits': ['CVE-2024-54772', 'CVE-2018-14847'],
            'priority': 'critical'
        }
    }
    
    @classmethod
    def analyze_and_decide(
        cls,
        scan_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze scan results and generate action plan
        
        Args:
            scan_results: Dictionary with scan data
            
        Returns:
            Dictionary with recommended actions
        """
        plan = {
            'immediate_actions': [],
            'investigation_paths': [],
            'exploitation_opportunities': [],
            'priority': 'medium',
            'execution_flow': []
        }
        
        # Analyze open ports
        open_ports = scan_results.get('open_ports', [])
        for port in open_ports:
            actions = cls._get_port_actions(port)
            if actions:
                plan['immediate_actions'].extend(actions)
        
        # Analyze web services
        web_services = scan_results.get('web_services', [])
        for service in web_services:
            actions = cls._analyze_web_service(service)
            plan['immediate_actions'].extend(actions)
        
        # Analyze detected technologies
        technologies = scan_results.get('technologies', {})
        for tech, pattern in cls.ATTACK_PATTERNS.items():
            if cls._technology_detected(technologies, pattern):
                plan['exploitation_opportunities'].append({
                    'technology': tech,
                    'tools': pattern['tools'],
                    'exploits': pattern['exploits'],
                    'priority': pattern['priority']
                })
                
                if pattern['priority'] == 'critical':
                    plan['priority'] = 'critical'
        
        # Analyze vulnerabilities
        vulnerabilities = scan_results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if vuln.get('severity') in ['critical', 'high']:
                plan['exploitation_opportunities'].append({
                    'type': 'vulnerability',
                    'id': vuln.get('id'),
                    'severity': vuln.get('severity'),
                    'target': vuln.get('matched_at')
                })
                
                if vuln.get('severity') == 'critical':
                    plan['priority'] = 'critical'
        
        # Generate execution flow
        plan['execution_flow'] = cls._generate_execution_flow(plan)
        
        # Remove duplicates
        plan['immediate_actions'] = list(set(plan['immediate_actions']))
        
        return plan
    
    @classmethod
    def _get_port_actions(cls, port: int) -> List[str]:
        """Get recommended actions for a specific port"""
        port_key = f'open_port_{port}'
        return cls.DECISION_MATRIX.get(port_key, [])
    
    @classmethod
    def _analyze_web_service(cls, service: Dict[str, Any]) -> List[str]:
        """Analyze web service and recommend actions"""
        actions = []
        
        url = service.get('url', '')
        title = service.get('title', '').lower()
        server = service.get('server', '').lower()
        
        # Check for specific applications
        if 'wordpress' in title or 'wp-' in url:
            actions.extend(cls.DECISION_MATRIX.get('wordpress_detected', []))
        
        if 'phpmyadmin' in url or 'phpmyadmin' in title:
            actions.extend(cls.DECISION_MATRIX.get('php_myadmin', []))
        
        if 'jenkins' in title or 'jenkins' in url:
            actions.extend(cls.DECISION_MATRIX.get('jenkins_detected', []))
        
        # Check server type
        if 'apache' in server:
            actions.extend(cls.DECISION_MATRIX.get('apache_detected', []))
        elif 'nginx' in server:
            actions.extend(cls.DECISION_MATRIX.get('nginx_detected', []))
        
        return actions
    
    @classmethod
    def _technology_detected(
        cls,
        technologies: Dict[str, Any],
        pattern: Dict[str, Any]
    ) -> bool:
        """Check if technology is detected"""
        tech_str = str(technologies).lower()
        
        return any(
            keyword in tech_str
            for keyword in pattern.get('detection_keywords', [])
        )
    
    @classmethod
    def _generate_execution_flow(cls, plan: Dict[str, Any]) -> List[str]:
        """Generate ordered execution flow"""
        flow = []
        
        # Priority 1: Critical exploitation opportunities
        critical_exploits = [
            e for e in plan.get('exploitation_opportunities', [])
            if e.get('priority') == 'critical'
        ]
        
        for exploit in critical_exploits:
            flow.append(f"🔴 CRITICAL: Exploit {exploit.get('technology')} - {exploit.get('exploits', [None])[0]}")
        
        # Priority 2: Immediate actions (top 3)
        for action in plan.get('immediate_actions', [])[:3]:
            flow.append(f"🟠 Execute: {action}")
        
        # Priority 3: Investigation paths
        for path in plan.get('investigation_paths', [])[:2]:
            flow.append(f"🟡 Investigate: {path}")
        
        # Default if no actions
        if not flow:
            flow.append("⚪ No critical actions identified - continue reconnaissance")
        
        return flow
    
    @classmethod
    def format_action_plan(cls, plan: Dict[str, Any]) -> str:
        """Format action plan for display"""
        lines = []
        lines.append("=" * 60)
        lines.append("🧠 TACTICAL TRIAGE & ACTION PLAN")
        lines.append("=" * 60)
        
        # Priority
        priority_emoji = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        
        emoji = priority_emoji.get(plan.get('priority', 'medium'), '⚪')
        lines.append(f"Priority Level: {emoji} {plan.get('priority', 'medium').upper()}")
        lines.append("")
        
        # Execution flow
        if plan.get('execution_flow'):
            lines.append("📋 Recommended Execution Flow:")
            for i, step in enumerate(plan['execution_flow'], 1):
                lines.append(f"  {i}. {step}")
            lines.append("")
        
        # Immediate actions
        if plan.get('immediate_actions'):
            lines.append(f"⚡ Immediate Actions ({len(plan['immediate_actions'])}):")
            for action in plan['immediate_actions'][:5]:
                lines.append(f"  • {action}")
            lines.append("")
        
        # Exploitation opportunities
        if plan.get('exploitation_opportunities'):
            lines.append(f"💣 Exploitation Opportunities ({len(plan['exploitation_opportunities'])}):")
            for opp in plan['exploitation_opportunities'][:3]:
                if isinstance(opp, dict):
                    lines.append(f"  • {opp.get('technology', 'Unknown')}: {opp.get('exploits', ['N/A'])[0]}")
            lines.append("")
        
        lines.append("=" * 60)
        
        return '\n'.join(lines)


if __name__ == "__main__":
    # Test the engine
    print("Testing TriageEngine...")
    print("=" * 60)
    
    # Mock scan results
    mock_results = {
        'target': '192.168.1.1',
        'open_ports': [22, 80, 443, 8291],
        'web_services': [
            {'url': 'http://192.168.1.1', 'title': 'Jenkins Dashboard', 'server': 'Apache'},
            {'url': 'http://192.168.1.1/wordpress', 'title': 'WordPress Site', 'server': 'nginx'}
        ],
        'technologies': {
            'cms': ['WordPress'],
            'server': 'nginx'
        },
        'vulnerabilities': [
            {'id': 'CVE-2024-12345', 'severity': 'critical', 'matched_at': 'http://192.168.1.1'}
        ]
    }
    
    # Analyze
    plan = TriageEngine.analyze_and_decide(mock_results)
    
    # Display
    print("\n" + TriageEngine.format_action_plan(plan))
    
    print("\n✅ Test completed")
