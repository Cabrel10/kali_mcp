#!/usr/bin/env python3
"""
Bounty Pro - MCP Server Integration
=====================================
Main entry point that registers all Bounty Pro capabilities as MCP tools.
Integrates:
- Autonomous Planner with Knowledge Graph
- Burp Suite Pro native capabilities
- Advanced browser automation
- API testing (GraphQL, gRPC, WebSocket, JWT, OAuth)
- Cloud/AD/Mobile/Container security
- Evidence-based vulnerability validation

This file adds new tools to the existing kali_mcp_server.py
"""

import asyncio
import json
import time
import os
import sys
from typing import Dict, Any, Optional, List
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastmcp import FastMCP

# Import Bounty Pro modules
from bounty_pro.core.knowledge_graph import (
    KnowledgeGraph, EntityExtractor, Entity, EntityType,
    RelationType, VulnState, VulnEvidence, EVIDENCE_SCORES
)
from bounty_pro.core.capability_graph import CapabilityGraph
from bounty_pro.core.planner import (
    AutonomousPlanner, ReasoningEngine, ExecutionPlan,
    ObjectiveType, KillChainPhase
)
from bounty_pro.engines.burp_engine import (
    ProxyInterceptor, ActiveScanner, IntruderEngine,
    Repeater, Sequencer, Collaborator, ParamMiner,
    Comparer, Decoder, HTTPRequest, HTTPResponse,
    AttackType, InsertionPoint
)
from bounty_pro.engines.browser_engine import HumanBrowserEngine
from bounty_pro.engines.api_engine import (
    GraphQLEngine, WebSocketEngine, JWTEngine, OAuthEngine, GRPCEngine,
    AuthTestEngine
)
from bounty_pro.modules.security_modules import (
    CloudSecurityEngine, ADSecurityEngine,
    MobileSecurityEngine, ContainerSecurityEngine
)


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

# Core intelligence
knowledge_graph = KnowledgeGraph()
entity_extractor = EntityExtractor(knowledge_graph)
capability_graph = CapabilityGraph()
reasoning_engine = ReasoningEngine(knowledge_graph)

# Engines
burp_proxy = ProxyInterceptor()
burp_scanner = ActiveScanner()
burp_intruder = IntruderEngine()
burp_repeater = Repeater()
burp_sequencer = Sequencer()
burp_collaborator = Collaborator()
burp_param_miner = ParamMiner()
burp_decoder = Decoder()
burp_comparer = Comparer()

browser_engine = HumanBrowserEngine()

graphql_engine = GraphQLEngine()
websocket_engine = WebSocketEngine()
jwt_engine = JWTEngine()
oauth_engine = OAuthEngine()
grpc_engine = GRPCEngine()
auth_engine = AuthTestEngine()

cloud_engine = CloudSecurityEngine()
ad_engine = ADSecurityEngine()
mobile_engine = MobileSecurityEngine()
container_engine = ContainerSecurityEngine()

# Planner (initialized without execute_fn - will be set after tool registration)
planner = AutonomousPlanner(knowledge_graph, capability_graph)


# ============================================================================
# MCP SERVER SETUP
# ============================================================================

mcp = FastMCP("BountyPro")


# ============================================================================
# TOOL: AUTONOMOUS PLANNER
# ============================================================================

@mcp.tool()
async def bounty_planner(
    action: str,
    target: str = "",
    objective: str = "full_pentest",
    scope: str = "",
    stealth: bool = False
) -> str:
    """
    Autonomous Pentest Planner - Creates and executes intelligent attack plans.
    
    Actions:
    - create_plan: Create a new attack plan for a target
    - get_status: Get current plan status and progress
    - get_recommendations: Get AI-driven next-step recommendations
    - adapt: Manually trigger plan adaptation with new info
    - get_attack_surface: Get full attack surface for a host
    - export_graph: Export the knowledge graph
    
    Objectives: full_pentest, find_rce, find_sqli, find_xss, find_idor, 
                find_ssrf, find_auth_bypass, api_audit, cloud_audit, ad_audit
    """
    try:
        if action == "create_plan":
            obj_type = ObjectiveType(objective) if objective in [e.value for e in ObjectiveType] else ObjectiveType.FULL_PENTEST
            planner.stealth_mode = stealth
            plan = planner.create_plan(obj_type, target)
            return json.dumps({
                "plan_id": plan.id,
                "objective": objective,
                "target": target,
                "tasks": [t.to_dict() for t in plan.tasks],
                "total_tasks": len(plan.tasks)
            }, indent=2)
        
        elif action == "get_status":
            status = planner.get_status()
            return json.dumps(status, indent=2)
        
        elif action == "get_recommendations":
            recs = planner.get_recommendations()
            return json.dumps({"recommendations": recs}, indent=2)
        
        elif action == "get_attack_surface":
            surface = knowledge_graph.get_full_attack_surface(target)
            return json.dumps(surface, indent=2, default=str)
        
        elif action == "export_graph":
            graph = knowledge_graph.export_graph()
            return json.dumps(graph, indent=2, default=str)
        
        elif action == "get_vulns":
            actionable = knowledge_graph.get_actionable_vulns()
            confirmed = [
                {"id": vid, "state": v["state"].value, "score": v["score"]}
                for vid, v in knowledge_graph.vulnerabilities.items()
                if v["state"] == VulnState.CONFIRMED
            ]
            return json.dumps({
                "actionable": actionable,
                "confirmed": confirmed,
                "total_tracked": len(knowledge_graph.vulnerabilities)
            }, indent=2)
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: KNOWLEDGE GRAPH
# ============================================================================

@mcp.tool()
async def bounty_knowledge(
    action: str,
    tool_name: str = "",
    raw_output: str = "",
    entity_type: str = "",
    entity_name: str = "",
    entity_data: str = "{}",
    vuln_id: str = "",
    evidence_type: str = "",
    evidence_points: int = 0,
    evidence_desc: str = ""
) -> str:
    """
    Knowledge Graph - Entity relationship management for pentest intelligence.
    
    Actions:
    - extract: Parse tool output into entities (provide tool_name + raw_output)
    - add_entity: Manually add an entity
    - add_evidence: Add evidence to a vulnerability  
    - get_entities: Get entities by type
    - get_vulns: Get vulnerability states and suggested tests
    - query: Query the graph for relationships
    """
    try:
        if action == "extract":
            entities = entity_extractor.extract(tool_name, raw_output)
            return json.dumps({
                "entities_extracted": len(entities),
                "entities": [e.to_dict() for e in entities[:20]],
                "graph_total": len(knowledge_graph.entities)
            }, indent=2, default=str)
        
        elif action == "add_entity":
            etype = EntityType(entity_type) if entity_type else EntityType.HOST
            data = json.loads(entity_data) if entity_data else {}
            entity = Entity(type=etype, name=entity_name, data=data)
            eid = knowledge_graph.add_entity(entity)
            return json.dumps({"entity_id": eid, "name": entity_name, "type": entity_type})
        
        elif action == "add_evidence":
            evidence = VulnEvidence(
                vuln_id=vuln_id,
                evidence_type=evidence_type,
                points=evidence_points or EVIDENCE_SCORES.get(evidence_type, 10),
                description=evidence_desc
            )
            result = knowledge_graph.add_evidence(vuln_id, evidence)
            return json.dumps(result, indent=2, default=str)
        
        elif action == "get_entities":
            etype = EntityType(entity_type) if entity_type else None
            if etype:
                entities = knowledge_graph.get_entities_by_type(etype)
            else:
                entities = list(knowledge_graph.entities.values())[:50]
            return json.dumps({
                "count": len(entities),
                "entities": [e.to_dict() for e in entities[:30]]
            }, indent=2, default=str)
        
        elif action == "get_vulns":
            actionable = knowledge_graph.get_actionable_vulns()
            return json.dumps({"vulnerabilities": actionable}, indent=2)
        
        elif action == "query":
            entity = knowledge_graph.find_entity(
                EntityType(entity_type) if entity_type else EntityType.HOST,
                entity_name
            )
            if entity:
                neighbors = knowledge_graph.get_neighbors(entity.id)
                return json.dumps({
                    "entity": entity.to_dict(),
                    "neighbors": [n.to_dict() for n in neighbors]
                }, indent=2, default=str)
            return json.dumps({"error": "Entity not found"})
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: BURP SCANNER (Active Scanner)
# ============================================================================

@mcp.tool()
async def bounty_scanner(
    action: str,
    url: str = "",
    method: str = "GET",
    headers: str = "{}",
    body: str = "",
    scan_types: str = "sqli,xss,ssrf,path_traversal,rce",
    raw_request: str = ""
) -> str:
    """
    Active Vulnerability Scanner (Burp Scanner equivalent).
    
    Actions:
    - scan: Scan a request for vulnerabilities
    - scan_url: Quick scan of a URL
    - get_findings: Get all scanner findings
    - configure: Configure scan settings
    """
    try:
        if action == "scan" or action == "scan_url":
            if raw_request:
                request = HTTPRequest.from_raw(raw_request)
            else:
                request = HTTPRequest(
                    method=method,
                    url=url,
                    headers=json.loads(headers) if headers != "{}" else {},
                    body=body
                )
            
            burp_scanner.config["scan_types"] = scan_types.split(",")
            findings = await burp_scanner.scan_request(request)
            
            # Extract entities from findings
            for finding in findings:
                entity = Entity(
                    type=EntityType.VULNERABILITY,
                    name=f"{finding['category']}_{finding['parameter']}",
                    data=finding,
                    confidence=finding.get("confidence", 0.7),
                    source_tool="bounty_scanner"
                )
                knowledge_graph.add_entity(entity)
                knowledge_graph.register_vulnerability(entity.id)
            
            return json.dumps({
                "findings": findings,
                "count": len(findings),
                "url": url
            }, indent=2)
        
        elif action == "get_findings":
            return json.dumps({
                "findings": burp_scanner.findings,
                "total": len(burp_scanner.findings)
            }, indent=2)
        
        elif action == "configure":
            burp_scanner.config["scan_types"] = scan_types.split(",")
            return json.dumps({"configured": burp_scanner.config})
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: INTRUDER
# ============================================================================

@mcp.tool()
async def bounty_intruder(
    url: str,
    method: str = "GET",
    headers: str = "{}",
    body: str = "",
    positions: str = "[]",
    payloads: str = "[]",
    attack_type: str = "sniper",
    grep_match: str = "",
    grep_extract: str = ""
) -> str:
    """
    Intruder Attack Engine (Burp Intruder equivalent).
    
    Supports: sniper, battering_ram, pitchfork, cluster_bomb
    
    positions: JSON array of {name, type, original_value}
    payloads: JSON array of payload lists
    """
    try:
        request = HTTPRequest(
            method=method,
            url=url,
            headers=json.loads(headers) if headers != "{}" else {},
            body=body
        )
        
        pos_list = json.loads(positions)
        pay_list = json.loads(payloads)
        atype = AttackType(attack_type)
        
        if grep_match:
            burp_intruder.config["grep_match"] = grep_match.split("|")
        if grep_extract:
            burp_intruder.config["grep_extract"] = grep_extract.split("|")
        
        results = await burp_intruder.attack(request, pos_list, pay_list, atype)
        interesting = burp_intruder.get_interesting_results()
        
        return json.dumps({
            "total_requests": len(results),
            "interesting": interesting,
            "interesting_count": len(interesting),
            "attack_type": attack_type
        }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: SEQUENCER
# ============================================================================

@mcp.tool()
async def bounty_sequencer(
    action: str,
    tokens: str = "[]"
) -> str:
    """
    Token Randomness Analyzer (Burp Sequencer equivalent).
    
    Actions:
    - analyze: Analyze token randomness (provide tokens as JSON array)
    - add: Add samples for later analysis
    """
    try:
        token_list = json.loads(tokens) if tokens != "[]" else []
        
        if action == "add":
            burp_sequencer.add_samples(token_list)
            return json.dumps({"added": len(token_list), "total": len(burp_sequencer.samples)})
        
        elif action == "analyze":
            if token_list:
                burp_sequencer.add_samples(token_list)
            results = burp_sequencer.analyze()
            return json.dumps(results, indent=2)
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: COLLABORATOR (OOB Detection)
# ============================================================================

@mcp.tool()
async def bounty_collaborator(
    action: str,
    payload_type: str = "dns",
    context: str = "",
    callback_server: str = ""
) -> str:
    """
    Out-of-Band Interaction Detection (Burp Collaborator equivalent).
    
    Actions:
    - generate: Generate a unique collaborator payload
    - generate_ssrf: Generate SSRF-specific payloads
    - generate_xxe: Generate XXE payload with callback
    - check: Check for interactions/callbacks
    """
    try:
        if callback_server:
            burp_collaborator.callback_server = callback_server
        
        if action == "generate":
            payload = burp_collaborator.generate_payload(payload_type, context)
            return json.dumps(payload)
        
        elif action == "generate_ssrf":
            payloads = burp_collaborator.generate_ssrf_payloads(context)
            return json.dumps({"payloads": payloads})
        
        elif action == "generate_xxe":
            payload = burp_collaborator.generate_xxe_payload(context)
            return json.dumps({"xxe_payload": payload})
        
        elif action == "check":
            interactions = burp_collaborator.check_interactions()
            return json.dumps({"interactions": interactions, "count": len(interactions)})
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: DECODER
# ============================================================================

@mcp.tool()
async def bounty_decoder(
    action: str,
    data: str,
    encoding: str = "base64",
    algorithm: str = "sha256"
) -> str:
    """
    Universal Decoder/Encoder/Hasher (Burp Decoder equivalent).
    
    Actions:
    - decode: Decode data (encodings: base64, base64url, url, double_url, hex, html, unicode, jwt)
    - encode: Encode data
    - hash: Hash data (algorithms: md5, sha1, sha256, sha512)
    - smart_decode: Try all decodings automatically
    """
    try:
        if action == "decode":
            result = Decoder.decode(data, encoding)
            return json.dumps({"decoded": result, "encoding": encoding})
        
        elif action == "encode":
            result = Decoder.encode(data, encoding)
            return json.dumps({"encoded": result, "encoding": encoding})
        
        elif action == "hash":
            result = Decoder.hash(data, algorithm)
            return json.dumps({"hash": result, "algorithm": algorithm})
        
        elif action == "smart_decode":
            results = Decoder.smart_decode(data)
            return json.dumps({"decodings": results})
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: PARAM MINER
# ============================================================================

@mcp.tool()
async def bounty_param_miner(
    url: str,
    method: str = "GET",
    headers: str = "{}",
    body: str = "",
    wordlist: str = ""
) -> str:
    """
    Hidden Parameter Discovery (Burp Param Miner equivalent).
    Discovers unlinked/hidden parameters by observing response differences.
    """
    try:
        request = HTTPRequest(
            method=method,
            url=url,
            headers=json.loads(headers) if headers != "{}" else {},
            body=body
        )
        
        custom_wordlist = wordlist.split(",") if wordlist else None
        discovered = await burp_param_miner.mine(request, wordlist=custom_wordlist)
        
        return json.dumps({
            "discovered_parameters": discovered,
            "count": len(discovered),
            "url": url
        }, indent=2)
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: HUMAN BROWSER
# ============================================================================

@mcp.tool()
async def bounty_browser(
    action: str,
    url: str = "",
    tab_id: str = "",
    selector: str = "",
    text: str = "",
    proxy: str = "",
    headless: bool = True
) -> str:
    """
    Human-like Browser Automation Engine.
    
    Actions:
    - launch: Start browser
    - navigate: Navigate to URL with human behavior
    - click: Click element with natural mouse movement
    - type: Type text character by character
    - scroll: Scroll with natural patterns
    - extract_data: Extract all page data (forms, links, storage)
    - get_storage: Get localStorage/sessionStorage/cookies
    - check_webrtc: Check for WebRTC IP leaks
    - shadow_dom: Access Shadow DOM content
    - close: Close browser
    """
    try:
        if action == "launch":
            result = await browser_engine.launch(headless=headless, proxy=proxy or None)
            if "error" not in result:
                tid = await browser_engine.new_tab(url, tab_id or None)
                result["tab_id"] = tid
            return json.dumps(result)
        
        elif action == "navigate":
            result = await browser_engine.human_navigate(tab_id, url)
            return json.dumps(result)
        
        elif action == "click":
            result = await browser_engine.human_click(tab_id, selector)
            return json.dumps(result, default=str)
        
        elif action == "type":
            result = await browser_engine.human_type(tab_id, selector, text)
            return json.dumps(result)
        
        elif action == "scroll":
            result = await browser_engine.human_scroll(tab_id, int(text) if text else 1000)
            return json.dumps(result)
        
        elif action == "extract_data":
            result = await browser_engine.extract_page_data(tab_id)
            return json.dumps(result, indent=2, default=str)
        
        elif action == "get_storage":
            storage_type = text or "localStorage"
            result = await browser_engine.get_storage(tab_id, storage_type)
            return json.dumps(result, indent=2, default=str)
        
        elif action == "check_webrtc":
            result = await browser_engine.check_webrtc_leaks(tab_id)
            return json.dumps(result)
        
        elif action == "shadow_dom":
            result = await browser_engine.get_shadow_dom(tab_id, selector)
            return json.dumps(result, default=str)
        
        elif action == "close":
            await browser_engine.close()
            return json.dumps({"closed": True})
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: GRAPHQL TESTING
# ============================================================================

@mcp.tool()
async def bounty_graphql(
    action: str,
    url: str,
    headers: str = "{}",
    query_template: str = "",
    variable_name: str = ""
) -> str:
    """
    GraphQL Security Testing Engine.
    
    Actions:
    - introspect: Full schema introspection
    - test_depth: Test query depth limits (DoS)
    - test_batch: Test batch query support
    - test_injection: Test injection in variables
    """
    try:
        hdrs = json.loads(headers) if headers != "{}" else None
        
        if action == "introspect":
            result = await graphql_engine.introspect(url, hdrs)
            return json.dumps(result, indent=2)
        
        elif action == "test_depth":
            result = await graphql_engine.test_depth_limit(url, hdrs)
            return json.dumps(result, indent=2)
        
        elif action == "test_batch":
            result = await graphql_engine.test_batch_queries(url, hdrs)
            return json.dumps(result, indent=2)
        
        elif action == "test_injection":
            result = await graphql_engine.test_injection(url, query_template, variable_name, hdrs)
            return json.dumps(result, indent=2, default=str)
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: JWT TESTING
# ============================================================================

@mcp.tool()
async def bounty_jwt(
    action: str,
    token: str = "",
    public_key: str = "",
    modifications: str = "{}",
    wordlist: str = "",
    evil_url: str = ""
) -> str:
    """
    JWT Advanced Security Testing.
    
    Actions:
    - decode: Decode JWT without verification
    - alg_none: Generate alg:none attack tokens
    - key_confusion: RS256->HS256 key confusion attack
    - kid_injection: KID parameter injection
    - jku_injection: JKU header injection
    - manipulate: Modify JWT claims
    - brute_force: Brute force HMAC secret
    """
    try:
        if action == "decode":
            result = jwt_engine.decode_jwt(token)
            return json.dumps(result, indent=2, default=str)
        
        elif action == "alg_none":
            tokens = jwt_engine.test_alg_none(token)
            return json.dumps({"forged_tokens": tokens, "count": len(tokens)})
        
        elif action == "key_confusion":
            forged = jwt_engine.test_key_confusion(token, public_key)
            return json.dumps({"forged_token": forged})
        
        elif action == "kid_injection":
            tokens = jwt_engine.test_kid_injection(token)
            return json.dumps({"tokens": tokens, "count": len(tokens)})
        
        elif action == "jku_injection":
            forged = jwt_engine.test_jku_injection(token, evil_url)
            return json.dumps({"forged_token": forged})
        
        elif action == "manipulate":
            mods = json.loads(modifications)
            forged = jwt_engine.manipulate_claims(token, mods)
            return json.dumps({"forged_token": forged, "modifications": mods})
        
        elif action == "brute_force":
            wl = wordlist.split(",") if wordlist else ["secret", "password", "123456", "admin"]
            result = jwt_engine.brute_force_secret(token, wl)
            return json.dumps({"secret_found": result})
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: CLOUD SECURITY
# ============================================================================

@mcp.tool()
async def bounty_cloud(
    action: str,
    target: str = "",
    access_key: str = "",
    secret_key: str = "",
    token: str = "",
    region: str = "us-east-1"
) -> str:
    """
    Cloud Security Testing (AWS, Azure, GCP, Kubernetes).
    
    Actions:
    - test_s3: Test S3 bucket misconfigurations
    - aws_metadata: Enumerate AWS metadata service
    - test_aws_keys: Test AWS key permissions
    - k8s_audit: Audit Kubernetes API
    - azure_metadata: Test Azure IMDS
    - gcp_metadata: Test GCP metadata service
    """
    try:
        if action == "test_s3":
            result = await cloud_engine.test_s3_bucket(target)
            return json.dumps(result, indent=2)
        
        elif action == "aws_metadata":
            result = await cloud_engine.enumerate_aws_metadata(target or None)
            return json.dumps(result, indent=2)
        
        elif action == "test_aws_keys":
            result = await cloud_engine.test_aws_keys(access_key, secret_key)
            return json.dumps(result, indent=2)
        
        elif action == "k8s_audit":
            result = await cloud_engine.test_kubernetes_api(target, token or None)
            return json.dumps(result, indent=2)
        
        elif action == "azure_metadata":
            result = await cloud_engine.test_azure_metadata(target or None)
            return json.dumps(result, indent=2)
        
        elif action == "gcp_metadata":
            result = await cloud_engine.test_gcp_metadata(target or None)
            return json.dumps(result, indent=2)
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: ACTIVE DIRECTORY
# ============================================================================

@mcp.tool()
async def bounty_ad(
    action: str,
    domain: str = "",
    username: str = "",
    password: str = "",
    dc_ip: str = "",
    userlist: str = "",
    target_password: str = ""
) -> str:
    """
    Active Directory Security Testing.
    
    Actions:
    - kerberoast: Kerberoasting attack
    - asrep_roast: AS-REP Roasting
    - enumerate_adcs: Find ADCS vulnerabilities (ESC1-ESC16)
    - ldap_enum: LDAP enumeration
    - password_spray: Password spraying
    """
    try:
        users = userlist.split(",") if userlist else []
        
        if action == "kerberoast":
            result = await ad_engine.kerberoast(domain, username, password, dc_ip)
            return json.dumps(result, indent=2)
        
        elif action == "asrep_roast":
            result = await ad_engine.asrep_roast(domain, users, dc_ip)
            return json.dumps(result, indent=2)
        
        elif action == "enumerate_adcs":
            result = await ad_engine.enumerate_adcs(domain, username, password, dc_ip)
            return json.dumps(result, indent=2)
        
        elif action == "ldap_enum":
            result = await ad_engine.ldap_enum(dc_ip, domain, username, password)
            return json.dumps(result, indent=2)
        
        elif action == "password_spray":
            result = await ad_engine.password_spray(domain, users, target_password or password, dc_ip)
            return json.dumps(result, indent=2)
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: MOBILE SECURITY
# ============================================================================

@mcp.tool()
async def bounty_mobile(
    action: str,
    apk_path: str = "",
    purpose: str = "ssl_pinning_bypass"
) -> str:
    """
    Mobile Application Security Testing.
    
    Actions:
    - analyze_apk: Static analysis of APK (secrets, permissions, components)
    - frida_script: Generate Frida scripts (ssl_pinning_bypass, root_detection_bypass, 
                    intercept_crypto, intercept_http)
    """
    try:
        if action == "analyze_apk":
            result = await mobile_engine.analyze_apk(apk_path)
            return json.dumps(result, indent=2, default=str)
        
        elif action == "frida_script":
            script = mobile_engine.generate_frida_scripts(purpose)
            return json.dumps({"purpose": purpose, "script": script})
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: CONTAINER SECURITY
# ============================================================================

@mcp.tool()
async def bounty_container(
    action: str,
    target: str = "",
    image: str = ""
) -> str:
    """
    Container Security Testing (Docker, Kubernetes).
    
    Actions:
    - check_docker_socket: Check for exposed Docker socket
    - container_escape: Check for container escape possibilities
    - scan_image: Scan container image for vulnerabilities
    """
    try:
        if action == "check_docker_socket":
            result = await container_engine.check_docker_socket(target or "localhost")
            return json.dumps(result, indent=2)
        
        elif action == "container_escape":
            result = await container_engine.check_container_escape()
            return json.dumps(result, indent=2)
        
        elif action == "scan_image":
            result = await container_engine.scan_image(image)
            return json.dumps(result, indent=2)
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: EVIDENCE VALIDATOR
# ============================================================================

@mcp.tool()
async def bounty_validate(
    action: str,
    vuln_id: str = "",
    test_result: str = "{}"
) -> str:
    """
    Vulnerability Evidence Validator - Implements refutation-first approach.
    
    Actions:
    - should_verify: Check if a vulnerability needs more verification
    - plan_verification: Get verification test plan for a vulnerability
    - evaluate: Evaluate test result and update vulnerability state
    - get_state: Get current state and evidence for a vulnerability
    """
    try:
        if action == "should_verify":
            should = reasoning_engine.should_verify(vuln_id)
            return json.dumps({"should_verify": should, "vuln_id": vuln_id})
        
        elif action == "plan_verification":
            tests = reasoning_engine.plan_verification(vuln_id)
            return json.dumps({"verification_plan": tests, "vuln_id": vuln_id}, indent=2)
        
        elif action == "evaluate":
            result_data = json.loads(test_result)
            result = reasoning_engine.evaluate_evidence(vuln_id, result_data)
            return json.dumps(result, indent=2, default=str)
        
        elif action == "get_state":
            vuln_data = knowledge_graph.vulnerabilities.get(vuln_id, {})
            entity = knowledge_graph.entities.get(vuln_id)
            return json.dumps({
                "vuln_id": vuln_id,
                "name": entity.name if entity else "unknown",
                "state": vuln_data.get("state", VulnState.HYPOTHESIS).value if vuln_data else "unknown",
                "score": vuln_data.get("score", 0),
                "evidence_count": len(vuln_data.get("evidence", [])),
                "attempts": vuln_data.get("attempts", 0),
                "suggested_tests": knowledge_graph._suggest_tests(vuln_id) if vuln_data else []
            }, indent=2)
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# TOOL: OAUTH/OIDC
# ============================================================================

@mcp.tool()
async def bounty_oauth(
    action: str,
    auth_url: str = "",
    token_url: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    token_response: str = "{}"
) -> str:
    """
    OAuth2/OIDC Security Testing.
    
    Actions:
    - test_redirect: Test redirect_uri manipulation
    - test_state: Generate state bypass test cases
    - test_pkce: Test PKCE downgrade possibilities
    - analyze_token: Analyze token response for security issues
    """
    try:
        if action == "test_redirect":
            tests = oauth_engine.test_redirect_uri_manipulation(auth_url, client_id, redirect_uri)
            return json.dumps({"tests": tests, "count": len(tests)}, indent=2)
        
        elif action == "test_state":
            tests = oauth_engine.test_state_bypass(auth_url)
            return json.dumps({"tests": tests}, indent=2)
        
        elif action == "test_pkce":
            tests = oauth_engine.test_pkce_downgrade(token_url)
            return json.dumps({"tests": tests}, indent=2)
        
        elif action == "analyze_token":
            response = json.loads(token_response)
            result = oauth_engine.analyze_token_response(response)
            return json.dumps(result, indent=2)
        
        else:
            return json.dumps({"error": f"Unknown action: {action}"})
    
    except Exception as e:
        return json.dumps({"error": str(e)})


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    mcp.run(transport="stdio")
