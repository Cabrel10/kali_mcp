"""
Capability Graph - Tool Intelligence Mapping
=============================================
Maps entity types and situations to appropriate tools.
This is the "brain" that knows which tool to use when.

Example:
  - WordPress detected -> WPScan, Nuclei WP templates
  - Jenkins found -> Jenkins CLI, Searchsploit, Hydra
  - GraphQL endpoint -> Introspection, GraphQL Cop, Batching
  - JWT token -> jwt_tool, jku injection, alg:none
"""

from typing import Dict, List, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum


class ToolCategory(Enum):
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploitation"
    ENUMERATION = "enumeration"
    BRUTE_FORCE = "brute_force"
    FUZZING = "fuzzing"
    CRAWLING = "crawling"
    BROWSER = "browser"
    ANALYSIS = "analysis"


@dataclass
class ToolCapability:
    """Describes what a tool can do"""
    name: str
    category: ToolCategory
    input_types: List[str]           # What entity types it needs
    output_types: List[str]          # What entity types it produces
    triggers: List[str]              # Conditions that suggest using this tool
    priority: int = 5                # 1-10, higher = more important
    requires: List[str] = field(default_factory=list)  # Required tools/binaries
    timeout: int = 300               # Default timeout in seconds
    stealth_level: int = 5           # 1=noisy, 10=very stealthy
    reliability: float = 0.8         # How often it produces useful results
    description: str = ""


# ============================================================================
# COMPLETE TOOL CAPABILITY DATABASE
# ============================================================================

CAPABILITY_DATABASE: Dict[str, ToolCapability] = {
    
    # ========================================================================
    # RECONNAISSANCE
    # ========================================================================
    
    "subfinder": ToolCapability(
        name="subfinder",
        category=ToolCategory.RECON,
        input_types=["host", "domain"],
        output_types=["subdomain", "host"],
        triggers=["new_domain", "scope_expansion"],
        priority=9,
        requires=["subfinder"],
        stealth_level=9,
        reliability=0.9,
        description="Passive subdomain enumeration"
    ),
    
    "amass": ToolCapability(
        name="amass",
        category=ToolCategory.RECON,
        input_types=["host", "domain"],
        output_types=["subdomain", "host", "dns_record"],
        triggers=["new_domain", "deep_recon"],
        priority=8,
        requires=["amass"],
        timeout=600,
        stealth_level=7,
        reliability=0.85,
        description="Active/passive subdomain enumeration"
    ),
    
    "httpx": ToolCapability(
        name="httpx",
        category=ToolCategory.RECON,
        input_types=["subdomain", "host"],
        output_types=["endpoint", "technology", "header"],
        triggers=["subdomains_found", "probe_hosts"],
        priority=9,
        requires=["httpx"],
        stealth_level=8,
        reliability=0.95,
        description="HTTP probe and technology detection"
    ),
    
    "nmap": ToolCapability(
        name="nmap",
        category=ToolCategory.SCANNING,
        input_types=["host"],
        output_types=["port", "service", "technology"],
        triggers=["new_host", "port_scan_needed"],
        priority=10,
        requires=["nmap"],
        timeout=600,
        stealth_level=4,
        reliability=0.95,
        description="Port scanning and service detection"
    ),
    
    "masscan": ToolCapability(
        name="masscan",
        category=ToolCategory.SCANNING,
        input_types=["host", "network"],
        output_types=["port", "host"],
        triggers=["large_scope", "quick_port_scan"],
        priority=7,
        requires=["masscan"],
        stealth_level=2,
        reliability=0.85,
        description="Fast port scanning for large ranges"
    ),
    
    # ========================================================================
    # WEB SCANNING
    # ========================================================================
    
    "nuclei": ToolCapability(
        name="nuclei",
        category=ToolCategory.SCANNING,
        input_types=["endpoint", "host", "technology"],
        output_types=["vulnerability"],
        triggers=["endpoints_found", "tech_detected", "generic_scan"],
        priority=9,
        requires=["nuclei"],
        timeout=900,
        stealth_level=5,
        reliability=0.8,
        description="Template-based vulnerability scanner"
    ),
    
    "nikto": ToolCapability(
        name="nikto",
        category=ToolCategory.SCANNING,
        input_types=["endpoint", "host"],
        output_types=["vulnerability", "endpoint"],
        triggers=["web_server_found"],
        priority=6,
        requires=["nikto"],
        stealth_level=3,
        reliability=0.6,
        description="Web server vulnerability scanner"
    ),
    
    "wpscan": ToolCapability(
        name="wpscan",
        category=ToolCategory.SCANNING,
        input_types=["endpoint"],
        output_types=["vulnerability", "credential", "technology"],
        triggers=["wordpress_detected"],
        priority=9,
        requires=["wpscan"],
        stealth_level=5,
        reliability=0.85,
        description="WordPress vulnerability scanner"
    ),
    
    "joomscan": ToolCapability(
        name="joomscan",
        category=ToolCategory.SCANNING,
        input_types=["endpoint"],
        output_types=["vulnerability", "technology"],
        triggers=["joomla_detected"],
        priority=8,
        requires=["joomscan"],
        stealth_level=5,
        reliability=0.7,
        description="Joomla vulnerability scanner"
    ),
    
    # ========================================================================
    # DIRECTORY/CONTENT DISCOVERY
    # ========================================================================
    
    "ffuf": ToolCapability(
        name="ffuf",
        category=ToolCategory.FUZZING,
        input_types=["endpoint", "host"],
        output_types=["endpoint", "file"],
        triggers=["web_server_found", "directory_bruteforce"],
        priority=8,
        requires=["ffuf"],
        stealth_level=4,
        reliability=0.85,
        description="Fast web fuzzer for directories and parameters"
    ),
    
    "katana": ToolCapability(
        name="katana",
        category=ToolCategory.CRAWLING,
        input_types=["endpoint"],
        output_types=["endpoint", "parameter", "file"],
        triggers=["web_app_found", "crawl_needed"],
        priority=8,
        requires=["katana"],
        stealth_level=6,
        reliability=0.9,
        description="Web crawler for endpoint discovery"
    ),
    
    "feroxbuster": ToolCapability(
        name="feroxbuster",
        category=ToolCategory.FUZZING,
        input_types=["endpoint"],
        output_types=["endpoint", "file"],
        triggers=["deep_directory_scan"],
        priority=7,
        requires=["feroxbuster"],
        stealth_level=3,
        reliability=0.85,
        description="Recursive content discovery"
    ),
    
    # ========================================================================
    # EXPLOITATION
    # ========================================================================
    
    "sqlmap": ToolCapability(
        name="sqlmap",
        category=ToolCategory.EXPLOITATION,
        input_types=["parameter", "endpoint"],
        output_types=["vulnerability", "credential", "proof"],
        triggers=["sql_injection_suspected", "parameter_with_db"],
        priority=9,
        requires=["sqlmap"],
        timeout=600,
        stealth_level=3,
        reliability=0.85,
        description="Automatic SQL injection exploitation"
    ),
    
    "xsstrike": ToolCapability(
        name="xsstrike",
        category=ToolCategory.EXPLOITATION,
        input_types=["parameter", "endpoint"],
        output_types=["vulnerability", "proof"],
        triggers=["xss_suspected", "reflected_input"],
        priority=7,
        requires=["xsstrike"],
        stealth_level=5,
        reliability=0.7,
        description="Advanced XSS detection and exploitation"
    ),
    
    "commix": ToolCapability(
        name="commix",
        category=ToolCategory.EXPLOITATION,
        input_types=["parameter", "endpoint"],
        output_types=["vulnerability", "proof"],
        triggers=["command_injection_suspected"],
        priority=8,
        requires=["commix"],
        stealth_level=4,
        reliability=0.75,
        description="Command injection exploitation"
    ),
    
    # ========================================================================
    # AUTHENTICATION
    # ========================================================================
    
    "hydra": ToolCapability(
        name="hydra",
        category=ToolCategory.BRUTE_FORCE,
        input_types=["service", "credential"],
        output_types=["credential"],
        triggers=["login_found", "weak_auth_suspected", "service_with_auth"],
        priority=7,
        requires=["hydra"],
        timeout=900,
        stealth_level=2,
        reliability=0.6,
        description="Network login brute forcer"
    ),
    
    "jwt_tool": ToolCapability(
        name="jwt_tool",
        category=ToolCategory.EXPLOITATION,
        input_types=["jwt"],
        output_types=["vulnerability", "credential"],
        triggers=["jwt_detected", "auth_token_found"],
        priority=8,
        requires=["python3"],
        stealth_level=8,
        reliability=0.75,
        description="JWT vulnerability testing"
    ),
    
    # ========================================================================
    # API TESTING
    # ========================================================================
    
    "graphql_introspection": ToolCapability(
        name="graphql_introspection",
        category=ToolCategory.ENUMERATION,
        input_types=["endpoint"],
        output_types=["endpoint", "vulnerability"],
        triggers=["graphql_detected"],
        priority=9,
        requires=["python3"],
        stealth_level=7,
        reliability=0.9,
        description="GraphQL schema introspection"
    ),
    
    "graphql_cop": ToolCapability(
        name="graphql_cop",
        category=ToolCategory.SCANNING,
        input_types=["endpoint"],
        output_types=["vulnerability"],
        triggers=["graphql_detected"],
        priority=8,
        requires=["python3"],
        stealth_level=6,
        reliability=0.8,
        description="GraphQL security auditor"
    ),
    
    "grpcurl": ToolCapability(
        name="grpcurl",
        category=ToolCategory.ENUMERATION,
        input_types=["service", "endpoint"],
        output_types=["endpoint", "vulnerability"],
        triggers=["grpc_detected"],
        priority=8,
        requires=["grpcurl"],
        stealth_level=7,
        reliability=0.8,
        description="gRPC service enumeration"
    ),
    
    # ========================================================================
    # CLOUD SECURITY
    # ========================================================================
    
    "cloud_enum": ToolCapability(
        name="cloud_enum",
        category=ToolCategory.RECON,
        input_types=["host", "domain"],
        output_types=["s3_bucket", "cloud_resource"],
        triggers=["cloud_domain", "s3_reference"],
        priority=7,
        requires=["python3"],
        stealth_level=8,
        reliability=0.7,
        description="Cloud resource enumeration"
    ),
    
    "pacu": ToolCapability(
        name="pacu",
        category=ToolCategory.EXPLOITATION,
        input_types=["api_key", "credential"],
        output_types=["cloud_resource", "vulnerability"],
        triggers=["aws_key_found"],
        priority=9,
        requires=["pacu"],
        stealth_level=5,
        reliability=0.8,
        description="AWS exploitation framework"
    ),
    
    "scout_suite": ToolCapability(
        name="scout_suite",
        category=ToolCategory.SCANNING,
        input_types=["credential", "api_key"],
        output_types=["vulnerability", "cloud_resource"],
        triggers=["cloud_creds_found"],
        priority=8,
        requires=["scout"],
        stealth_level=6,
        reliability=0.85,
        description="Multi-cloud security auditing"
    ),
    
    # ========================================================================
    # ACTIVE DIRECTORY
    # ========================================================================
    
    "bloodhound": ToolCapability(
        name="bloodhound",
        category=ToolCategory.ENUMERATION,
        input_types=["ad_object", "credential"],
        output_types=["ad_object", "vulnerability"],
        triggers=["ad_environment", "domain_joined"],
        priority=9,
        requires=["bloodhound-python"],
        stealth_level=5,
        reliability=0.9,
        description="Active Directory attack path mapping"
    ),
    
    "certipy": ToolCapability(
        name="certipy",
        category=ToolCategory.EXPLOITATION,
        input_types=["ad_object"],
        output_types=["vulnerability", "credential"],
        triggers=["adcs_found", "certificate_service"],
        priority=9,
        requires=["certipy"],
        stealth_level=5,
        reliability=0.85,
        description="Active Directory Certificate Services exploitation"
    ),
    
    "netexec": ToolCapability(
        name="netexec",
        category=ToolCategory.ENUMERATION,
        input_types=["host", "credential"],
        output_types=["ad_object", "credential", "vulnerability"],
        triggers=["smb_found", "ad_environment"],
        priority=8,
        requires=["netexec"],
        stealth_level=4,
        reliability=0.85,
        description="Network service exploitation (CrackMapExec successor)"
    ),
    
    # ========================================================================
    # MOBILE
    # ========================================================================
    
    "mobsf": ToolCapability(
        name="mobsf",
        category=ToolCategory.ANALYSIS,
        input_types=["file"],
        output_types=["vulnerability", "endpoint", "api_key"],
        triggers=["apk_found", "mobile_target"],
        priority=8,
        requires=["mobsf"],
        stealth_level=10,
        reliability=0.8,
        description="Mobile Security Framework - static analysis"
    ),
    
    "frida": ToolCapability(
        name="frida",
        category=ToolCategory.EXPLOITATION,
        input_types=["file"],
        output_types=["vulnerability", "credential"],
        triggers=["mobile_dynamic_test", "ssl_pinning"],
        priority=8,
        requires=["frida"],
        stealth_level=5,
        reliability=0.7,
        description="Dynamic instrumentation toolkit"
    ),
    
    # ========================================================================
    # CONTAINER SECURITY
    # ========================================================================
    
    "trivy": ToolCapability(
        name="trivy",
        category=ToolCategory.SCANNING,
        input_types=["container", "file"],
        output_types=["vulnerability"],
        triggers=["container_found", "docker_image"],
        priority=8,
        requires=["trivy"],
        stealth_level=10,
        reliability=0.9,
        description="Container vulnerability scanner"
    ),
    
    "kube_hunter": ToolCapability(
        name="kube_hunter",
        category=ToolCategory.SCANNING,
        input_types=["host", "service"],
        output_types=["vulnerability"],
        triggers=["kubernetes_found", "k8s_api"],
        priority=8,
        requires=["kube-hunter"],
        stealth_level=5,
        reliability=0.75,
        description="Kubernetes penetration testing"
    ),
    
    # ========================================================================
    # BROWSER AUTOMATION
    # ========================================================================
    
    "browser_login": ToolCapability(
        name="browser_login",
        category=ToolCategory.BROWSER,
        input_types=["endpoint", "credential"],
        output_types=["session", "cookie", "jwt"],
        triggers=["login_page_found", "auth_needed"],
        priority=8,
        requires=["playwright"],
        stealth_level=7,
        reliability=0.8,
        description="Automated browser login with human-like behavior"
    ),
    
    "browser_exploit": ToolCapability(
        name="browser_exploit",
        category=ToolCategory.BROWSER,
        input_types=["endpoint", "vulnerability"],
        output_types=["proof"],
        triggers=["dom_xss_suspected", "csrf_test", "clickjacking"],
        priority=7,
        requires=["playwright"],
        stealth_level=6,
        reliability=0.7,
        description="Browser-based exploit verification"
    ),
    
    # ========================================================================
    # POST-EXPLOITATION
    # ========================================================================
    
    "linpeas": ToolCapability(
        name="linpeas",
        category=ToolCategory.POST_EXPLOIT,
        input_types=["session"],
        output_types=["vulnerability", "credential", "file"],
        triggers=["shell_obtained", "linux_host"],
        priority=9,
        requires=["shell_access"],
        stealth_level=4,
        reliability=0.9,
        description="Linux privilege escalation enumeration"
    ),
    
    "winpeas": ToolCapability(
        name="winpeas",
        category=ToolCategory.POST_EXPLOIT,
        input_types=["session"],
        output_types=["vulnerability", "credential", "file"],
        triggers=["shell_obtained", "windows_host"],
        priority=9,
        requires=["shell_access"],
        stealth_level=4,
        reliability=0.9,
        description="Windows privilege escalation enumeration"
    ),
}


# ============================================================================
# TECHNOLOGY -> TOOL MAPPING
# ============================================================================

TECH_TOOL_MAP: Dict[str, List[str]] = {
    # CMS
    "wordpress": ["wpscan", "nuclei", "ffuf", "sqlmap"],
    "joomla": ["joomscan", "nuclei"],
    "drupal": ["droopescan", "nuclei"],
    "magento": ["magescan", "nuclei"],
    
    # Languages/Frameworks
    "php": ["nuclei", "sqlmap", "commix", "ffuf"],
    "java": ["nuclei", "log4j_scan", "deserialization"],
    "python": ["nuclei", "ssti_test"],
    "node": ["nuclei", "prototype_pollution"],
    "ruby": ["nuclei", "deserialization"],
    "asp.net": ["nuclei", "viewstate_deserialize"],
    
    # Servers
    "apache": ["nuclei", "nikto", "searchsploit"],
    "nginx": ["nuclei", "nikto"],
    "iis": ["nuclei", "nikto", "shortname_scan"],
    "tomcat": ["nuclei", "tomcat_exploit", "hydra"],
    "jenkins": ["jenkins_enum", "hydra", "searchsploit"],
    "weblogic": ["nuclei", "deserialization", "searchsploit"],
    "jboss": ["nuclei", "deserialization", "searchsploit"],
    
    # Databases
    "mysql": ["hydra", "sqlmap"],
    "postgresql": ["hydra", "sqlmap"],
    "mssql": ["hydra", "sqlmap", "xp_cmdshell"],
    "mongodb": ["nuclei", "nosql_injection"],
    "redis": ["redis_exploit", "nuclei"],
    "elasticsearch": ["nuclei", "elastic_enum"],
    
    # Services
    "ssh": ["hydra", "ssh_audit"],
    "ftp": ["hydra", "anonymous_check"],
    "smb": ["netexec", "enum4linux", "smbclient"],
    "rdp": ["hydra", "rdp_check"],
    "ldap": ["ldapsearch", "bloodhound"],
    "kerberos": ["kerbrute", "kerberoast"],
    
    # API
    "graphql": ["graphql_introspection", "graphql_cop"],
    "grpc": ["grpcurl", "grpc_scan"],
    "soap": ["wsdl_scan"],
    "rest": ["nuclei", "ffuf", "param_miner"],
    
    # Cloud
    "aws": ["pacu", "cloud_enum", "scout_suite"],
    "azure": ["azurehound", "scout_suite"],
    "gcp": ["gcp_enum", "scout_suite"],
    "kubernetes": ["kube_hunter", "kubeaudit"],
    "docker": ["trivy", "docker_escape"],
    
    # Auth
    "jwt": ["jwt_tool", "jwt_crack"],
    "oauth": ["oauth_test"],
    "saml": ["saml_raider"],
}


# ============================================================================
# SITUATION -> ACTION MAPPING
# ============================================================================

SITUATION_ACTIONS: Dict[str, List[Dict[str, Any]]] = {
    "new_target": [
        {"tool": "subfinder", "priority": 9},
        {"tool": "nmap", "priority": 10},
        {"tool": "httpx", "priority": 9},
    ],
    "subdomains_found": [
        {"tool": "httpx", "priority": 9},
        {"tool": "nmap", "priority": 7},
    ],
    "web_server_found": [
        {"tool": "nuclei", "priority": 9},
        {"tool": "katana", "priority": 8},
        {"tool": "ffuf", "priority": 7},
        {"tool": "nikto", "priority": 6},
    ],
    "login_found": [
        {"tool": "browser_login", "priority": 8},
        {"tool": "hydra", "priority": 6},
        {"tool": "sqlmap", "priority": 7},
    ],
    "api_found": [
        {"tool": "ffuf", "priority": 8},
        {"tool": "nuclei", "priority": 8},
    ],
    "graphql_detected": [
        {"tool": "graphql_introspection", "priority": 9},
        {"tool": "graphql_cop", "priority": 8},
    ],
    "jwt_detected": [
        {"tool": "jwt_tool", "priority": 9},
    ],
    "sql_injection_suspected": [
        {"tool": "sqlmap", "priority": 9},
    ],
    "shell_obtained": [
        {"tool": "linpeas", "priority": 9},
        {"tool": "winpeas", "priority": 9},
    ],
    "ad_environment": [
        {"tool": "bloodhound", "priority": 9},
        {"tool": "netexec", "priority": 8},
        {"tool": "certipy", "priority": 8},
    ],
    "cloud_creds_found": [
        {"tool": "pacu", "priority": 9},
        {"tool": "scout_suite", "priority": 8},
    ],
}


# ============================================================================
# CAPABILITY GRAPH CLASS
# ============================================================================

class CapabilityGraph:
    """
    Manages the mapping between entities, technologies, situations and tools.
    Used by the Planner to decide which tool to use next.
    """
    
    def __init__(self):
        self.capabilities = CAPABILITY_DATABASE
        self.tech_map = TECH_TOOL_MAP
        self.situation_map = SITUATION_ACTIONS
    
    def get_tools_for_entity(self, entity_type: str, entity_data: Dict = None) -> List[ToolCapability]:
        """Get applicable tools for an entity type"""
        matching = []
        for tool_name, cap in self.capabilities.items():
            if entity_type in cap.input_types:
                matching.append(cap)
        return sorted(matching, key=lambda x: x.priority, reverse=True)
    
    def get_tools_for_technology(self, tech_name: str) -> List[str]:
        """Get tools relevant for a specific technology"""
        tech_lower = tech_name.lower()
        for tech, tools in self.tech_map.items():
            if tech in tech_lower or tech_lower in tech:
                return tools
        return []
    
    def get_tools_for_situation(self, situation: str) -> List[Dict[str, Any]]:
        """Get recommended tools for a given situation"""
        return self.situation_map.get(situation, [])
    
    def suggest_next_tools(self, entities: List[Dict], 
                          already_used: Set[str] = None,
                          max_suggestions: int = 5) -> List[Dict[str, Any]]:
        """
        Given current entities and already-used tools,
        suggest the best next tools to use.
        """
        already_used = already_used or set()
        suggestions = []
        seen_tools = set()
        
        for entity in entities:
            entity_type = entity.get("type", "")
            entity_data = entity.get("data", {})
            entity_name = entity.get("name", "").lower()
            
            # Get tools based on entity type
            type_tools = self.get_tools_for_entity(entity_type, entity_data)
            for tool in type_tools:
                if tool.name not in already_used and tool.name not in seen_tools:
                    suggestions.append({
                        "tool": tool.name,
                        "reason": f"Applicable to {entity_type}: {entity.get('name', '')}",
                        "priority": tool.priority,
                        "category": tool.category.value,
                        "stealth": tool.stealth_level
                    })
                    seen_tools.add(tool.name)
            
            # Get tools based on technology name
            tech_tools = self.get_tools_for_technology(entity_name)
            for tool_name in tech_tools:
                if tool_name not in already_used and tool_name not in seen_tools:
                    cap = self.capabilities.get(tool_name)
                    if cap:
                        suggestions.append({
                            "tool": tool_name,
                            "reason": f"Specialized for technology: {entity_name}",
                            "priority": cap.priority,
                            "category": cap.category.value,
                            "stealth": cap.stealth_level
                        })
                        seen_tools.add(tool_name)
        
        # Sort by priority
        suggestions.sort(key=lambda x: x["priority"], reverse=True)
        return suggestions[:max_suggestions]
