"""
Knowledge Graph - Entity-Relationship Engine for Pentest Intelligence
=====================================================================
Implements a graph-based data structure that connects:
Host -> Ports -> Services -> Technologies -> Endpoints -> Vulnerabilities -> Credentials -> Proofs

Every tool output is parsed into normalized entities and linked in the graph,
enabling the Planner to make intelligent decisions about next steps.
"""

import uuid
import time
import json
import re
from typing import Dict, Any, Optional, List, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from pathlib import Path


# ============================================================================
# ENTITY TYPES
# ============================================================================

class EntityType(Enum):
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    HEADER = "header"
    COOKIE = "cookie"
    JWT = "jwt"
    CREDENTIAL = "credential"
    VULNERABILITY = "vulnerability"
    EXPLOIT = "exploit"
    PROOF = "proof"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    SUBDOMAIN = "subdomain"
    EMAIL = "email"
    API_KEY = "api_key"
    S3_BUCKET = "s3_bucket"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    AD_OBJECT = "ad_object"
    FILE = "file"
    SESSION = "session"
    NETWORK = "network"


class RelationType(Enum):
    HOSTS = "hosts"                  # Host -> Port
    RUNS = "runs"                    # Port -> Service
    USES = "uses"                    # Service -> Technology
    EXPOSES = "exposes"              # Technology -> Endpoint
    ACCEPTS = "accepts"              # Endpoint -> Parameter
    RETURNS = "returns"              # Endpoint -> Header
    SETS = "sets"                    # Service -> Cookie
    AUTHENTICATES = "authenticates"  # Cookie/JWT -> Session
    HAS_VULN = "has_vuln"            # Entity -> Vulnerability
    EXPLOITED_BY = "exploited_by"    # Vulnerability -> Exploit
    PROVED_BY = "proved_by"          # Vulnerability -> Proof
    RESOLVES_TO = "resolves_to"      # Subdomain -> Host
    BELONGS_TO = "belongs_to"        # Entity -> Parent
    CONTAINS = "contains"            # Container -> File
    CONNECTS_TO = "connects_to"     # Service -> Service
    TRUSTS = "trusts"                # AD_Object -> AD_Object
    LEAKS = "leaks"                  # Endpoint -> Credential/APIKey
    CHAINS_TO = "chains_to"          # Vulnerability -> Vulnerability


class VulnState(Enum):
    HYPOTHESIS = "hypothesis"        # Initial suspicion
    SUSPECTED = "suspected"          # Some evidence
    VERIFIED = "verified"            # Reproduced once
    REPRODUCED = "reproduced"        # Multiple reproductions
    CONFIRMED = "confirmed"          # Fully validated with proof
    FALSE_POSITIVE = "false_positive" # Dismissed after testing


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class Entity:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    type: EntityType = EntityType.HOST
    name: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    source_tool: str = ""
    discovered_at: float = field(default_factory=time.time)
    tags: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "type": self.type.value,
            "name": self.name,
            "data": self.data,
            "confidence": self.confidence,
            "source_tool": self.source_tool,
            "discovered_at": self.discovered_at,
            "tags": list(self.tags)
        }


@dataclass
class Relation:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    source_id: str = ""
    target_id: str = ""
    type: RelationType = RelationType.CONNECTS_TO
    data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    created_at: float = field(default_factory=time.time)


@dataclass
class VulnEvidence:
    """A single piece of evidence for/against a vulnerability"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    vuln_id: str = ""
    evidence_type: str = ""  # "error_message", "time_diff", "boolean_response", etc.
    description: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    points: int = 0  # Positive = supports, Negative = refutes
    tool_used: str = ""
    timestamp: float = field(default_factory=time.time)
    reproducible: bool = False


# ============================================================================
# EVIDENCE SCORING SYSTEM
# ============================================================================

EVIDENCE_SCORES = {
    # SQL Injection
    "sql_error_visible": 25,
    "sql_boolean_diff": 20,
    "sql_time_diff": 20,
    "sql_data_extracted": 30,
    "sql_reproduced": 40,
    
    # XSS
    "xss_reflected": 20,
    "xss_dom_executed": 25,
    "xss_stored_confirmed": 35,
    "xss_cookie_stolen": 40,
    
    # IDOR
    "idor_different_response": 15,
    "idor_other_user_data": 30,
    "idor_uuid_bypassed": 25,
    "idor_reproduced_multi_user": 40,
    
    # SSRF
    "ssrf_dns_callback": 20,
    "ssrf_internal_response": 30,
    "ssrf_cloud_metadata": 35,
    "ssrf_file_read": 40,
    
    # RCE
    "rce_command_output": 40,
    "rce_reverse_shell": 50,
    "rce_file_write": 35,
    "rce_dns_exfil": 30,
    
    # Auth Bypass
    "auth_bypass_access": 30,
    "auth_bypass_admin": 40,
    "auth_jwt_forged": 35,
    "auth_session_hijack": 35,
    
    # Generic
    "error_disclosure": 10,
    "version_vulnerable": 15,
    "config_exposed": 20,
    "default_creds": 25,
    "sensitive_data_leak": 30,
    
    # Negative evidence
    "not_reproducible": -20,
    "waf_blocked": -10,
    "false_alarm": -30,
    "patched": -40,
}

CONFIDENCE_THRESHOLDS = {
    VulnState.HYPOTHESIS: 0,
    VulnState.SUSPECTED: 20,
    VulnState.VERIFIED: 40,
    VulnState.REPRODUCED: 60,
    VulnState.CONFIRMED: 80,
}


# ============================================================================
# KNOWLEDGE GRAPH
# ============================================================================

class KnowledgeGraph:
    """
    A graph-based knowledge store that maintains relationships between
    all discovered entities during a pentest engagement.
    """
    
    def __init__(self):
        self.entities: Dict[str, Entity] = {}
        self.relations: List[Relation] = []
        self.vulnerabilities: Dict[str, Dict] = {}  # vuln_id -> {state, evidence, score}
        self._index_by_type: Dict[EntityType, List[str]] = defaultdict(list)
        self._index_by_name: Dict[str, List[str]] = defaultdict(list)
        self._adjacency: Dict[str, List[str]] = defaultdict(list)  # entity_id -> [relation_ids]
        
    def add_entity(self, entity: Entity) -> str:
        """Add an entity to the graph, deduplicating by type+name"""
        # Check for existing entity with same type and name
        existing = self.find_entity(entity.type, entity.name)
        if existing:
            # Merge data
            existing.data.update(entity.data)
            existing.tags.update(entity.tags)
            existing.confidence = max(existing.confidence, entity.confidence)
            return existing.id
        
        self.entities[entity.id] = entity
        self._index_by_type[entity.type].append(entity.id)
        self._index_by_name[entity.name.lower()].append(entity.id)
        return entity.id
    
    def add_relation(self, source_id: str, target_id: str, 
                     rel_type: RelationType, data: Dict = None) -> Optional[str]:
        """Add a relationship between two entities"""
        if source_id not in self.entities or target_id not in self.entities:
            return None
        
        # Check for duplicate relation
        for rel in self.relations:
            if (rel.source_id == source_id and rel.target_id == target_id 
                and rel.type == rel_type):
                return rel.id
        
        relation = Relation(
            source_id=source_id,
            target_id=target_id,
            type=rel_type,
            data=data or {}
        )
        self.relations.append(relation)
        self._adjacency[source_id].append(relation.id)
        self._adjacency[target_id].append(relation.id)
        return relation.id
    
    def find_entity(self, entity_type: EntityType, name: str) -> Optional[Entity]:
        """Find an entity by type and name"""
        for eid in self._index_by_type.get(entity_type, []):
            entity = self.entities[eid]
            if entity.name.lower() == name.lower():
                return entity
        return None
    
    def get_neighbors(self, entity_id: str, rel_type: RelationType = None) -> List[Entity]:
        """Get all entities connected to a given entity"""
        neighbors = []
        for rel in self.relations:
            if rel.source_id == entity_id:
                if rel_type is None or rel.type == rel_type:
                    if rel.target_id in self.entities:
                        neighbors.append(self.entities[rel.target_id])
            elif rel.target_id == entity_id:
                if rel_type is None or rel.type == rel_type:
                    if rel.source_id in self.entities:
                        neighbors.append(self.entities[rel.source_id])
        return neighbors
    
    def get_entities_by_type(self, entity_type: EntityType) -> List[Entity]:
        """Get all entities of a given type"""
        return [self.entities[eid] for eid in self._index_by_type.get(entity_type, [])
                if eid in self.entities]
    
    def get_attack_path(self, start_id: str, target_type: EntityType) -> List[Entity]:
        """Find path from start entity to a target entity type (BFS)"""
        visited = set()
        queue = [(start_id, [start_id])]
        
        while queue:
            current_id, path = queue.pop(0)
            if current_id in visited:
                continue
            visited.add(current_id)
            
            entity = self.entities.get(current_id)
            if entity and entity.type == target_type and current_id != start_id:
                return [self.entities[eid] for eid in path if eid in self.entities]
            
            for neighbor in self.get_neighbors(current_id):
                if neighbor.id not in visited:
                    queue.append((neighbor.id, path + [neighbor.id]))
        
        return []
    
    # ========================================================================
    # VULNERABILITY EVIDENCE MANAGEMENT
    # ========================================================================
    
    def register_vulnerability(self, vuln_entity_id: str) -> None:
        """Register a vulnerability entity for evidence tracking"""
        if vuln_entity_id not in self.vulnerabilities:
            self.vulnerabilities[vuln_entity_id] = {
                "state": VulnState.HYPOTHESIS,
                "evidence": [],
                "score": 0,
                "attempts": 0,
                "last_tested": time.time()
            }
    
    def add_evidence(self, vuln_id: str, evidence: VulnEvidence) -> Dict:
        """Add evidence to a vulnerability and recalculate state"""
        if vuln_id not in self.vulnerabilities:
            self.register_vulnerability(vuln_id)
        
        vuln = self.vulnerabilities[vuln_id]
        vuln["evidence"].append(evidence)
        vuln["score"] += evidence.points
        vuln["attempts"] += 1
        vuln["last_tested"] = time.time()
        
        # Determine state based on score
        new_state = VulnState.HYPOTHESIS
        for state, threshold in sorted(CONFIDENCE_THRESHOLDS.items(), 
                                       key=lambda x: x[1], reverse=True):
            if vuln["score"] >= threshold:
                new_state = state
                break
        
        # Check for negative override
        if vuln["score"] < -10:
            new_state = VulnState.FALSE_POSITIVE
        
        vuln["state"] = new_state
        
        return {
            "vuln_id": vuln_id,
            "new_state": new_state.value,
            "score": vuln["score"],
            "evidence_count": len(vuln["evidence"]),
            "needs_more_evidence": new_state in [VulnState.HYPOTHESIS, VulnState.SUSPECTED]
        }
    
    def get_actionable_vulns(self) -> List[Dict]:
        """Get vulnerabilities that need more testing"""
        actionable = []
        for vuln_id, vuln_data in self.vulnerabilities.items():
            if vuln_data["state"] in [VulnState.HYPOTHESIS, VulnState.SUSPECTED]:
                entity = self.entities.get(vuln_id)
                actionable.append({
                    "id": vuln_id,
                    "name": entity.name if entity else "unknown",
                    "state": vuln_data["state"].value,
                    "score": vuln_data["score"],
                    "evidence_count": len(vuln_data["evidence"]),
                    "suggested_tests": self._suggest_tests(vuln_id)
                })
        return sorted(actionable, key=lambda x: x["score"], reverse=True)
    
    def _suggest_tests(self, vuln_id: str) -> List[str]:
        """Suggest next tests for a vulnerability based on existing evidence"""
        entity = self.entities.get(vuln_id)
        if not entity:
            return []
        
        vuln_data = self.vulnerabilities.get(vuln_id, {})
        existing_types = {e.evidence_type for e in vuln_data.get("evidence", [])}
        
        suggestions = []
        vuln_name = entity.name.lower()
        
        if "sql" in vuln_name:
            needed = {"sql_boolean_diff", "sql_time_diff", "sql_data_extracted", "sql_reproduced"}
            missing = needed - existing_types
            if "sql_boolean_diff" in missing:
                suggestions.append("Try boolean-based blind SQLi with AND 1=1 vs AND 1=2")
            if "sql_time_diff" in missing:
                suggestions.append("Try time-based blind with SLEEP(5)")
            if "sql_data_extracted" in missing:
                suggestions.append("Try UNION SELECT to extract data")
            if "sql_reproduced" in missing:
                suggestions.append("Reproduce with different payloads")
        
        elif "xss" in vuln_name:
            needed = {"xss_reflected", "xss_dom_executed", "xss_stored_confirmed"}
            missing = needed - existing_types
            if "xss_dom_executed" in missing:
                suggestions.append("Verify XSS executes in browser context")
            if "xss_stored_confirmed" in missing:
                suggestions.append("Check if payload persists across sessions")
        
        elif "idor" in vuln_name:
            needed = {"idor_different_response", "idor_other_user_data", "idor_reproduced_multi_user"}
            missing = needed - existing_types
            if "idor_other_user_data" in missing:
                suggestions.append("Access resource with different user's ID")
            if "idor_reproduced_multi_user" in missing:
                suggestions.append("Verify with multiple user roles")
        
        elif "ssrf" in vuln_name:
            needed = {"ssrf_dns_callback", "ssrf_internal_response", "ssrf_cloud_metadata"}
            missing = needed - existing_types
            if "ssrf_dns_callback" in missing:
                suggestions.append("Use Burp Collaborator/webhook for DNS callback")
            if "ssrf_cloud_metadata" in missing:
                suggestions.append("Try accessing 169.254.169.254")
        
        elif "rce" in vuln_name:
            needed = {"rce_command_output", "rce_dns_exfil", "rce_file_write"}
            missing = needed - existing_types
            if "rce_command_output" in missing:
                suggestions.append("Execute id/whoami and capture output")
            if "rce_dns_exfil" in missing:
                suggestions.append("Exfiltrate via DNS to confirm blind RCE")
        
        if not suggestions:
            suggestions.append("Try reproducing with different parameters")
            suggestions.append("Test from different authentication context")
        
        return suggestions[:5]
    
    # ========================================================================
    # GRAPH TRAVERSAL AND QUERIES
    # ========================================================================
    
    def get_full_attack_surface(self, host_name: str) -> Dict:
        """Get complete attack surface for a host"""
        host = self.find_entity(EntityType.HOST, host_name)
        if not host:
            return {"error": f"Host {host_name} not found"}
        
        surface = {
            "host": host.to_dict(),
            "ports": [],
            "services": [],
            "technologies": [],
            "endpoints": [],
            "vulnerabilities": [],
            "credentials": [],
            "attack_paths": []
        }
        
        # Traverse graph from host
        ports = self.get_neighbors(host.id, RelationType.HOSTS)
        surface["ports"] = [p.to_dict() for p in ports]
        
        for port in ports:
            services = self.get_neighbors(port.id, RelationType.RUNS)
            surface["services"].extend([s.to_dict() for s in services])
            
            for svc in services:
                techs = self.get_neighbors(svc.id, RelationType.USES)
                surface["technologies"].extend([t.to_dict() for t in techs])
                
                endpoints = self.get_neighbors(svc.id, RelationType.EXPOSES)
                surface["endpoints"].extend([e.to_dict() for e in endpoints])
        
        # Get all vulns related to this host's entities
        all_entity_ids = {host.id}
        for p in ports:
            all_entity_ids.add(p.id)
        for s in surface["services"]:
            all_entity_ids.add(s["id"])
        
        for vuln in self.get_entities_by_type(EntityType.VULNERABILITY):
            for rel in self.relations:
                if rel.type == RelationType.HAS_VULN and rel.source_id in all_entity_ids:
                    vuln_info = vuln.to_dict()
                    if vuln.id in self.vulnerabilities:
                        vuln_info["state"] = self.vulnerabilities[vuln.id]["state"].value
                        vuln_info["score"] = self.vulnerabilities[vuln.id]["score"]
                    surface["vulnerabilities"].append(vuln_info)
        
        return surface
    
    def export_graph(self) -> Dict:
        """Export the entire graph for visualization or persistence"""
        return {
            "entities": {eid: e.to_dict() for eid, e in self.entities.items()},
            "relations": [{
                "id": r.id,
                "source": r.source_id,
                "target": r.target_id,
                "type": r.type.value,
                "data": r.data
            } for r in self.relations],
            "vulnerabilities": {
                vid: {
                    "state": v["state"].value,
                    "score": v["score"],
                    "evidence_count": len(v["evidence"]),
                    "attempts": v["attempts"]
                } for vid, v in self.vulnerabilities.items()
            },
            "stats": {
                "total_entities": len(self.entities),
                "total_relations": len(self.relations),
                "total_vulns": len(self.vulnerabilities),
                "confirmed_vulns": sum(1 for v in self.vulnerabilities.values() 
                                       if v["state"] == VulnState.CONFIRMED)
            }
        }
    
    def import_graph(self, data: Dict) -> None:
        """Import a previously exported graph"""
        for eid, edata in data.get("entities", {}).items():
            entity = Entity(
                id=edata["id"],
                type=EntityType(edata["type"]),
                name=edata["name"],
                data=edata.get("data", {}),
                confidence=edata.get("confidence", 1.0),
                source_tool=edata.get("source_tool", ""),
                tags=set(edata.get("tags", []))
            )
            self.entities[entity.id] = entity
            self._index_by_type[entity.type].append(entity.id)
            self._index_by_name[entity.name.lower()].append(entity.id)


# ============================================================================
# ENTITY EXTRACTOR
# ============================================================================

class EntityExtractor:
    """
    Parses raw tool output into normalized entities.
    Each tool's output format is handled by a specific parser.
    """
    
    def __init__(self, graph: KnowledgeGraph):
        self.graph = graph
        self.parsers = {
            "nmap": self._parse_nmap,
            "httpx": self._parse_httpx,
            "subfinder": self._parse_subfinder,
            "nuclei": self._parse_nuclei,
            "wpscan": self._parse_wpscan,
            "sqlmap": self._parse_sqlmap,
            "nikto": self._parse_nikto,
            "ffuf": self._parse_ffuf,
            "katana": self._parse_katana,
            "jwt_scan": self._parse_jwt,
            "burp_scan": self._parse_burp,
            "graphql": self._parse_graphql,
            "cloud_enum": self._parse_cloud,
            "bloodhound": self._parse_bloodhound,
        }
    
    def extract(self, tool_name: str, raw_output: str, 
                context: Dict = None) -> List[Entity]:
        """Extract entities from tool output"""
        parser = self.parsers.get(tool_name, self._parse_generic)
        entities = parser(raw_output, context or {})
        
        # Add all entities to graph
        for entity in entities:
            entity.source_tool = tool_name
            self.graph.add_entity(entity)
        
        return entities
    
    def _parse_nmap(self, output: str, context: Dict) -> List[Entity]:
        """Parse nmap output into entities"""
        entities = []
        
        # Extract host
        host_match = re.search(r'Nmap scan report for (\S+)', output)
        if host_match:
            host_name = host_match.group(1)
            host_entity = Entity(
                type=EntityType.HOST,
                name=host_name,
                data={"raw_scan": output[:500]}
            )
            entities.append(host_entity)
        
        # Extract ports and services
        port_pattern = r'(\d+)/(\w+)\s+(open|filtered)\s+(\S+)\s*(.*)'
        for match in re.finditer(port_pattern, output):
            port_num, protocol, state, service, version = match.groups()
            
            port_entity = Entity(
                type=EntityType.PORT,
                name=f"{port_num}/{protocol}",
                data={
                    "number": int(port_num),
                    "protocol": protocol,
                    "state": state
                }
            )
            entities.append(port_entity)
            
            svc_entity = Entity(
                type=EntityType.SERVICE,
                name=service,
                data={
                    "port": int(port_num),
                    "version": version.strip(),
                    "protocol": protocol
                }
            )
            entities.append(svc_entity)
            
            # Extract technology from version
            if version.strip():
                tech_entity = Entity(
                    type=EntityType.TECHNOLOGY,
                    name=version.strip().split()[0] if version.strip() else service,
                    data={"version_string": version.strip(), "port": int(port_num)}
                )
                entities.append(tech_entity)
        
        # Link entities
        if entities:
            host_id = entities[0].id if entities[0].type == EntityType.HOST else None
            if host_id:
                for e in entities[1:]:
                    if e.type == EntityType.PORT:
                        self.graph.add_relation(host_id, e.id, RelationType.HOSTS)
                    elif e.type == EntityType.SERVICE:
                        # Find corresponding port
                        port_num = e.data.get("port")
                        for pe in entities:
                            if pe.type == EntityType.PORT and pe.data.get("number") == port_num:
                                self.graph.add_relation(pe.id, e.id, RelationType.RUNS)
                                break
        
        return entities
    
    def _parse_httpx(self, output: str, context: Dict) -> List[Entity]:
        """Parse httpx output"""
        entities = []
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            url = parts[0] if parts else ""
            
            if url.startswith(('http://', 'https://')):
                endpoint_entity = Entity(
                    type=EntityType.ENDPOINT,
                    name=url,
                    data={
                        "status_code": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                        "title": " ".join(parts[2:]) if len(parts) > 2 else "",
                        "raw_line": line
                    }
                )
                entities.append(endpoint_entity)
                
                # Extract technology from headers if available
                tech_patterns = [
                    (r'\[(.+?)\]', "technology"),
                ]
                for pattern, _ in tech_patterns:
                    for tech_match in re.finditer(pattern, line):
                        tech = Entity(
                            type=EntityType.TECHNOLOGY,
                            name=tech_match.group(1),
                            data={"source": "httpx_probe"}
                        )
                        entities.append(tech)
        
        return entities
    
    def _parse_subfinder(self, output: str, context: Dict) -> List[Entity]:
        """Parse subfinder output"""
        entities = []
        for line in output.strip().split('\n'):
            subdomain = line.strip()
            if subdomain and '.' in subdomain:
                entity = Entity(
                    type=EntityType.SUBDOMAIN,
                    name=subdomain,
                    data={"discovered_via": "subfinder"}
                )
                entities.append(entity)
        return entities
    
    def _parse_nuclei(self, output: str, context: Dict) -> List[Entity]:
        """Parse nuclei output into vulnerability entities"""
        entities = []
        # Nuclei format: [template-id] [severity] [protocol] url [info]
        pattern = r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)\s*(.*)'
        
        for match in re.finditer(pattern, output):
            template_id, severity, protocol, url, info = match.groups()
            
            vuln_entity = Entity(
                type=EntityType.VULNERABILITY,
                name=f"{template_id}@{url}",
                data={
                    "template": template_id,
                    "severity": severity,
                    "protocol": protocol,
                    "url": url,
                    "info": info.strip(),
                    "scanner": "nuclei"
                },
                confidence=0.6 if severity in ["info", "low"] else 0.8
            )
            entities.append(vuln_entity)
        
        return entities
    
    def _parse_wpscan(self, output: str, context: Dict) -> List[Entity]:
        """Parse WPScan output"""
        entities = []
        
        # WordPress version
        ver_match = re.search(r'WordPress version (\S+)', output)
        if ver_match:
            entities.append(Entity(
                type=EntityType.TECHNOLOGY,
                name="WordPress",
                data={"version": ver_match.group(1)}
            ))
        
        # Plugins
        plugin_pattern = r'\[!\]\s*Title:\s*(.+?)[\n\r]'
        for match in re.finditer(plugin_pattern, output):
            entities.append(Entity(
                type=EntityType.VULNERABILITY,
                name=match.group(1),
                data={"source": "wpscan", "type": "plugin_vuln"}
            ))
        
        # Users
        user_pattern = r'\|\s*(\w+)\s*\|'
        for match in re.finditer(user_pattern, output):
            username = match.group(1)
            if username not in ['Id', 'Login', 'Name']:
                entities.append(Entity(
                    type=EntityType.CREDENTIAL,
                    name=username,
                    data={"type": "wordpress_user", "password": None}
                ))
        
        return entities
    
    def _parse_sqlmap(self, output: str, context: Dict) -> List[Entity]:
        """Parse sqlmap output"""
        entities = []
        
        # Injection point found
        if "is vulnerable" in output.lower() or "injectable" in output.lower():
            param_match = re.search(r"Parameter:\s*(\S+)", output)
            param_name = param_match.group(1) if param_match else "unknown"
            
            entities.append(Entity(
                type=EntityType.VULNERABILITY,
                name=f"SQLi_{param_name}",
                data={
                    "type": "sql_injection",
                    "parameter": param_name,
                    "confirmed": True,
                    "scanner": "sqlmap"
                },
                confidence=0.95
            ))
        
        # Extracted data
        db_match = re.search(r'available databases.*?:\s*\[.*?\]', output, re.DOTALL)
        if db_match:
            entities.append(Entity(
                type=EntityType.PROOF,
                name="sql_data_extraction",
                data={"extracted": db_match.group(0)[:500]}
            ))
        
        return entities
    
    def _parse_nikto(self, output: str, context: Dict) -> List[Entity]:
        """Parse nikto output"""
        entities = []
        for line in output.split('\n'):
            if '+ ' in line and 'OSVDB' in line:
                entities.append(Entity(
                    type=EntityType.VULNERABILITY,
                    name=line.strip(),
                    data={"source": "nikto", "type": "web_vuln"}
                ))
        return entities
    
    def _parse_ffuf(self, output: str, context: Dict) -> List[Entity]:
        """Parse ffuf/directory fuzzing output"""
        entities = []
        for line in output.strip().split('\n'):
            # Pattern: URL [Status] [Size] [Words]
            match = re.search(r'(\S+)\s+\[Status:\s*(\d+)', line)
            if match:
                url, status = match.groups()
                entities.append(Entity(
                    type=EntityType.ENDPOINT,
                    name=url,
                    data={"status_code": int(status), "source": "ffuf"}
                ))
        return entities
    
    def _parse_katana(self, output: str, context: Dict) -> List[Entity]:
        """Parse katana crawler output"""
        entities = []
        for line in output.strip().split('\n'):
            url = line.strip()
            if url.startswith(('http://', 'https://')):
                entities.append(Entity(
                    type=EntityType.ENDPOINT,
                    name=url,
                    data={"source": "katana", "type": "crawled"}
                ))
        return entities
    
    def _parse_jwt(self, output: str, context: Dict) -> List[Entity]:
        """Parse JWT analysis output"""
        entities = []
        # JWT token pattern
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        for match in re.finditer(jwt_pattern, output):
            entities.append(Entity(
                type=EntityType.JWT,
                name=match.group(0)[:50] + "...",
                data={"full_token": match.group(0), "source": "jwt_scan"}
            ))
        return entities
    
    def _parse_burp(self, output: str, context: Dict) -> List[Entity]:
        """Parse Burp-like scanner output"""
        entities = []
        # Generic issue pattern
        issue_pattern = r'Issue:\s*(.+?)(?:\n|Severity:\s*(\w+))'
        for match in re.finditer(issue_pattern, output):
            entities.append(Entity(
                type=EntityType.VULNERABILITY,
                name=match.group(1).strip(),
                data={"severity": match.group(2) if match.group(2) else "info"}
            ))
        return entities
    
    def _parse_graphql(self, output: str, context: Dict) -> List[Entity]:
        """Parse GraphQL introspection/scan output"""
        entities = []
        if "__schema" in output or "introspection" in output.lower():
            entities.append(Entity(
                type=EntityType.VULNERABILITY,
                name="GraphQL Introspection Enabled",
                data={"type": "graphql", "severity": "low"}
            ))
        
        # Extract types and fields
        type_pattern = r'"name":\s*"(\w+)"'
        for match in re.finditer(type_pattern, output):
            name = match.group(1)
            if name not in ['String', 'Int', 'Boolean', 'Float', 'ID']:
                entities.append(Entity(
                    type=EntityType.ENDPOINT,
                    name=f"GraphQL:{name}",
                    data={"type": "graphql_type"}
                ))
        
        return entities
    
    def _parse_cloud(self, output: str, context: Dict) -> List[Entity]:
        """Parse cloud enumeration output"""
        entities = []
        
        # S3 buckets
        s3_pattern = r'([\w.-]+\.s3[\w.-]*\.amazonaws\.com|s3://[\w.-]+)'
        for match in re.finditer(s3_pattern, output):
            entities.append(Entity(
                type=EntityType.S3_BUCKET,
                name=match.group(1),
                data={"cloud": "aws"}
            ))
        
        # Azure blobs
        azure_pattern = r'([\w.-]+\.blob\.core\.windows\.net)'
        for match in re.finditer(azure_pattern, output):
            entities.append(Entity(
                type=EntityType.CLOUD_RESOURCE,
                name=match.group(1),
                data={"cloud": "azure", "type": "blob"}
            ))
        
        return entities
    
    def _parse_bloodhound(self, output: str, context: Dict) -> List[Entity]:
        """Parse BloodHound/AD enumeration output"""
        entities = []
        
        # Users
        user_pattern = r'(\w+@[\w.]+)'
        for match in re.finditer(user_pattern, output):
            entities.append(Entity(
                type=EntityType.AD_OBJECT,
                name=match.group(1),
                data={"type": "user"}
            ))
        
        return entities
    
    def _parse_generic(self, output: str, context: Dict) -> List[Entity]:
        """Generic parser for unknown tools"""
        entities = []
        
        # Extract IPs
        ip_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        for match in re.finditer(ip_pattern, output):
            entities.append(Entity(
                type=EntityType.HOST,
                name=match.group(1),
                data={"source": "generic_parser"}
            ))
        
        # Extract URLs
        url_pattern = r'(https?://[^\s<>"]+)'
        for match in re.finditer(url_pattern, output):
            entities.append(Entity(
                type=EntityType.ENDPOINT,
                name=match.group(1),
                data={"source": "generic_parser"}
            ))
        
        # Extract emails
        email_pattern = r'[\w.-]+@[\w.-]+\.\w+'
        for match in re.finditer(email_pattern, output):
            entities.append(Entity(
                type=EntityType.EMAIL,
                name=match.group(0),
                data={"source": "generic_parser"}
            ))
        
        return entities
