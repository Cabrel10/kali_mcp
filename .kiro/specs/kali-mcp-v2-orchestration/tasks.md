# Implementation Plan: Kali MCP V2 Orchestration

## Overview

This implementation plan breaks down the Kali MCP V2 Orchestration architecture (6 layers + evidence policy + integration) into 33 concrete coding tasks organized across 8 categories. Tasks are sequenced to respect dependencies, enable parallel work, and ensure early validation through end-to-end checkpoints.

The implementation follows a critical path through Tool Registry → Capability Engine → Orchestrator → Baseline Engine → Evidence Graph → Standardized Output → Evidence Policy enforcement → Integration & Testing.

---

## Layer 1: Tool Registry (Foundation)

### 1.1 Define Tool, Capability, and Parameter Data Structures

- [ ] 1.1 Implement Tool, Capability, Parameter, and HealthStatus data classes
  - Define @dataclass Tool with fields: id, name, category, capabilities, required_params, optional_params, timeout_seconds, rate_limit_delay_ms, max_concurrent_instances, health_status, last_health_check, failure_count, version, requires_root, supported_platforms
  - Define @dataclass Capability with fields: id, type (CapabilityType enum), technology_stack, vulnerability_types, max_evidence_level, estimated_duration_seconds, estimated_requests, requires_capabilities, requires_authenticated_context, finding_format
  - Define @dataclass Parameter with fields: name, type (ParameterType enum), description, default_value, valid_values, validation_regex
  - Define @enum HealthStatus: HEALTHY, DEGRADED, OFFLINE
  - Verify all structures compile and are instantiable with test data
  - _Requirements: REQ-TR-01_

### 1.2 Implement ToolRegistry Class and Core Methods

- [ ] 1.2 Implement ToolRegistry with registration and querying
  - Create ToolRegistry class with internal registry dict (UUID → Tool)
  - Implement register(tool: Tool) → success|error with duplicate ID check
  - Implement get_tool_by_id(tool_id: UUID) → Tool|error
  - Implement query_tools_by_capability_type(capability_type: CapabilityType) → List[Tool]
  - Implement query_tools_by_tech_stack(tech_stack: List[str]) → List[Tool]
  - Implement query_tools_with_evidence_level(min_level: FindingStatus) → List[Tool]
  - Verify registration works without duplicates; queries return correct subsets
  - Test: Register 10 tools, query by capability, verify filtering works
  - _Requirements: REQ-TR-01, REQ-TR-02_

### 1.3 Implement Tool Health Check Mechanism

- [ ] 1.3 Implement ToolRegistry health_check() method
  - Implement health_check(tool_id: UUID) → (HealthStatus, message: str)
  - Check tool binary exists at expected path
  - Run tool-specific diagnostic command (nuclei --version, nmap --version, etc.)
  - Parse exit code: 0 = HEALTHY, non-zero = DEGRADED/OFFLINE
  - Increment failure_count on failure; reset to 0 on success
  - Implement periodic health check scheduler (every 60 seconds)
  - Verify health status reflects actual tool availability
  - Test: Mock offline tool, verify status = OFFLINE; restore, verify HEALTHY
  - _Requirements: REQ-TR-03, REQ-ORCH-06_

### 1.4 Implement Parameter Validation

- [ ] 1.4 Implement Parameter validation and tool invocation
  - Implement Parameter.validate(value: Any) → bool|error
  - Type checking: STRING, INTEGER, BOOLEAN, ENUM, FILE_PATH
  - For ENUM: check value in valid_values list
  - For STRING: regex validation if validation_regex defined
  - For FILE_PATH: check file exists
  - For INTEGER: range validation (min/max bounds)
  - Implement build_tool_invocation(tool_id: UUID, parameters: Dict) → List[str] (command array)
  - Prevent command injection via proper parameter escaping
  - Test: ENUM validation (depth=invalid → error), FILE_PATH validation, command building
  - _Requirements: REQ-TR-04_

---

## Layer 2: Capability Engine

### 2.1 Define Capability Query and Matching Data Structures

- [ ] 2.1 Implement CapabilityQuery, CapabilityMatch, and supporting enums
  - Define @dataclass CapabilityQuery with fields: target_type (TargetType), detected_tech_stack, objective (ObjectiveType), constraints (QueryConstraints)
  - Define @dataclass CapabilityMatch with fields: tool_id, matching_capabilities, relevance_score, evidence_potential, required_dependencies, estimated_cost (ExecutionCost)
  - Define @enum TargetType: WEB_APP, API, NETWORK, CLOUD_INFRASTRUCTURE, CONTAINER, SAAS_PLATFORM, HARDWARE
  - Define @enum ObjectiveType: RECON, VULNERABILITY_ASSESSMENT, EXPLOIT_VERIFICATION, COMPLIANCE_AUDIT, PROOF_OF_CONCEPT, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, PERSISTENCE
  - Define @dataclass QueryConstraints with fields: max_tools, preferred_evidence_level, max_requests_per_host, require_authenticated, require_stealth
  - Define @dataclass ExecutionCost with fields: estimated_time_seconds, estimated_requests, estimated_network_bytes, resource_intensity (enum)
  - Verify all data structures instantiable and valid
  - _Requirements: REQ-CE-01_

### 2.2 Implement Capability Engine Scoring and Tool Selection

- [ ] 2.2 Implement CapabilityEngine.get_applicable_tools() with relevance scoring
  - Create CapabilityEngine class with reference to ToolRegistry
  - Implement get_applicable_tools(query: CapabilityQuery) → sorted List[CapabilityMatch]
  - Scoring formula: (tech_stack_match * 0.3) + (objective_match * 0.4) + (evidence_level_match * 0.3)
  - tech_stack_match = count(detected_tech ∩ tool_tech) / count(detected_tech)
  - objective_match = 1.0 if capability.type matches query.objective, else 0.0
  - evidence_level_match = 1.0 if capability.max_evidence_level >= query.preferred_evidence_level, else 0.0
  - Filter by health_status != OFFLINE
  - Filter by relevance_score > 0.2
  - Sort by relevance_score descending
  - Apply query.constraints.max_tools limit
  - Test: Query NETWORK_RECON on WEB_APP (Java, Spring) → recon tools ranked higher than exploit tools
  - _Requirements: REQ-CE-02, REQ-CE-04_

### 2.3 Implement Capability Dependency Resolution

- [ ] 2.3 Implement resolve_capability_dependencies() with cycle detection
  - Implement resolve_capability_dependencies(capability: Capability) → List[UUID]
  - Recursive DFS to find transitive dependencies
  - Detect circular dependencies; return error with cycle path if found
  - Return topologically sorted list (prerequisites first)
  - Validate no capability referenced that doesn't exist
  - Test: Tool A requires B requires C → resolve [C, B, A]; Tool A requires B, Tool B requires A → cycle error
  - _Requirements: REQ-CE-03_

### 2.4 Implement Target Technology Stack Detection

- [ ] 2.4 Implement detect_target_type() for tech stack discovery
  - Implement detect_target_type(target: str) → TargetType
  - Parse target URL scheme (HTTP/HTTPS → WEB_APP or API)
  - Make HTTP HEAD request; parse headers: X-Powered-By, Server, X-AspNet-Version
  - Identify tech stack: Java (Tomcat, Spring), Node.js (Express), PHP (Laravel), Python (Django, Flask), ASP.NET, Go, Rust
  - Return CapabilityQuery with detected_tech_stack populated
  - Handle connection failures gracefully (timeout → WEB_APP, log warning)
  - Test: URL with Express header → detect Node.js; URL with Spring error → detect Java
  - _Requirements: REQ-CE-01, REQ-CE-04_

---

## Layer 3: Orchestrator (Plan Generation & Execution)

### 3.1 Define ExecutionPhase and ExecutionPlan Data Structures

- [ ] 3.1 Implement ExecutionPhase, ExecutionPlan, and supporting enums
  - Define @dataclass ExecutionPhase with fields: phase_id, phase_type (PhaseType), sequence_index, tools_to_execute, parallel, stop_on_failure, depends_on_phases, inputs_from_phases, estimated_duration_seconds, estimated_total_requests
  - Define @enum PhaseType: RECON, BASELINE_ESTABLISHMENT, FINGERPRINTING, SHALLOW_SCAN, DEEP_SCAN, EXPLOIT_VERIFICATION, PRIVILEGE_ESCALATION, VERIFICATION, CLEANUP
  - Define @dataclass ExecutionPlan with fields: plan_id, target, target_type, depth (ScanDepth), phases, phase_graph, total_estimated_duration, total_estimated_requests, metadata
  - Define @dataclass ToolExecution with fields: tool_id, parameters, timeout_seconds, priority
  - Verify data structures compile and are instantiable with test data
  - _Requirements: REQ-ORCH-01_

### 3.2 Implement Orchestrator.plan_scan() to Generate Execution Plans

- [ ] 3.2 Implement plan_scan() with phase sequencing
  - Create Orchestrator class with references to CapabilityEngine and ToolRegistry
  - Implement plan_scan(target: str, depth: ScanDepth, objective: ObjectiveType) → ExecutionPlan
  - Phase 0: DETECT_TARGET_TYPE (call detect_target_type())
  - Phase 1: RECON (if depth >= LIGHT; use CapabilityEngine for RECON objective tools)
  - Phase 2: BASELINE_ESTABLISHMENT (mandatory; before all payload testing)
  - Phase 3: FINGERPRINTING (if depth >= DEEP)
  - Phase 4+: SHALLOW_SCAN or DEEP_SCAN (based on depth)
  - Phase 5+ (optional): EXPLOIT_VERIFICATION (if objective = EXPLOIT_VERIFICATION or PROOF_OF_CONCEPT)
  - Build phase_graph with dependency edges
  - Calculate total_estimated_duration and total_estimated_requests
  - Test: plan_scan("http://example.com", "deep", VULN_ASSESS) → 6-8 phases in correct order
  - _Requirements: REQ-ORCH-01, REQ-ORCH-02, REQ-ORCH-03_

### 3.3 Enforce Baseline Phase Precedence

- [ ] 3.3 Implement baseline precedence validation
  - In plan_scan(), verify: baseline_phase.sequence_index < first_payload_phase.sequence_index
  - Ensure all payload phases (SCAN, EXPLOIT) list baseline_phase in depends_on_phases
  - Return error if constraint violated
  - Document invariant in code comments
  - Test: Generate plan; verify baseline before scanning; attempt invalid plan → error
  - _Requirements: REQ-ORCH-02, REQ-POLICY-02_

### 3.4 Implement Phase Dependency Graph and Topological Sorting

- [ ] 3.4 Implement phase_graph and topological_sort()
  - Build phase_graph as DirectedGraph (using networkx or custom implementation)
  - For each phase: add edges from depends_on_phases to phase
  - Implement topological_sort(phase_graph) → List[Phase]
  - Detect cycles in graph; return error with cycle path if found
  - Validate topological order: for each phase, all dependencies execute first
  - Test: 3-phase plan (RECON → BASELINE → SCAN) → sort returns [RECON, BASELINE, SCAN]; circular deps → error
  - _Requirements: REQ-ORCH-03, REQ-ORCH-04_

### 3.5 Implement Orchestrator.execute_plan() with Phase Execution

- [ ] 3.5 Implement execute_plan() with phase orchestration
  - Implement execute_plan(plan: ExecutionPlan) → ExecutionResults
  - Topologically sort phases via topological_sort()
  - FOR each phase in sorted order: execute_phase(phase, executed_phases_map)
  - execute_phase(): FOR each tool in tools_to_execute, invoke tool (respecting parallel flag)
  - Capture tool output (stdout, stderr, exit_code)
  - Store output in executed_phases_map[phase.phase_id]
  - Pass output to dependent phases via inputs_from_phases
  - Check stop_on_failure flag; abort if needed
  - Return ExecutionResults with all phase outputs
  - Test: Execute 3-phase plan; verify RECON → BASELINE → SCAN in order; BASELINE output available to SCAN
  - _Requirements: REQ-ORCH-05, REQ-ORCH-03, REQ-ORCH-06_

### 3.6 Implement Phase Parallelization and Concurrency Control

- [ ] 3.6 Implement parallel phase execution with concurrency limits
  - In execute_phase(): check phase.parallel flag
  - IF parallel=true: use ThreadPoolExecutor or asyncio.gather() for concurrent execution
  - Respect tool.max_concurrent_instances limit (e.g., max 3 simultaneous Nuclei)
  - Implement global concurrency limit (e.g., max 8 concurrent tools across all tools)
  - Queue remaining tools; start when slots free
  - IF parallel=false: execute tools sequentially
  - Test: RECON phase with 4 tools, max_concurrent=2 → 2 run, then 2 more; BASELINE phase sequential
  - _Requirements: REQ-ORCH-04, REQ-INT-05_

---

## Layer 4: Baseline Engine (Semantic Response Comparison)

### 4.1 Define Baseline Data Structures

- [ ] 4.1 Implement Baseline, BaselineSet, and SemanticComparisonResult classes
  - Define @dataclass Baseline with fields: baseline_type (BaselineType), request_method, request_url, request_headers, request_body, response_status_code, response_headers, response_body, response_size_bytes, dom_hash, text_hash, semantic_tokens, jaccard_signature, response_time_ms, request_timestamp
  - Define @enum BaselineType: HOMEPAGE, NOT_FOUND_404, INVALID_PARAM, NULL_BODY, EMPTY_QUERY, AUTHENTICATED_HOME, AUTHENTICATED_404
  - Define @dataclass BaselineSet with fields: baselines (dict), target, established_timestamp, http_version, response_times_ms, average_response_time_ms
  - Define @dataclass SemanticComparisonResult with fields: test_response, baseline_response, similarity_score, jaccard_similarity, dom_similarity, semantic_difference, is_semantic_match
  - Verify data structures instantiable and valid
  - _Requirements: REQ-BE-01_

### 4.2 Implement BaselineEngine.establish_baseline()

- [ ] 4.2 Implement establish_baseline() to create three reference responses
  - Create BaselineEngine class
  - Implement establish_baseline(target: str) → BaselineSet
  - Baseline 1 (HOMEPAGE): GET / with standard headers, timeout 10s, store response
  - Baseline 2 (NOT_FOUND_404): GET /{random_uuid}, expect 404, store response
  - Baseline 3 (INVALID_PARAM): GET {target}?{random_param}={random_value}, store response
  - For each baseline: store response_body, status_code, headers, response_time_ms
  - Return BaselineSet with 3 baselines or error if any fails
  - Handle connection failures gracefully (timeout → error, don't mask)
  - Test: Establish baselines for http://example.com; verify 3 distinct responses
  - _Requirements: REQ-BE-01, REQ-BE-02_

### 4.3 Implement Semantic Token Extraction and Hashing

- [ ] 4.3 Implement extract_semantic_tokens() and hash functions
  - Implement extract_semantic_tokens(response_body: str) → Set[str]
  - Tokenize: split on whitespace/punctuation, extract words/numbers/patterns
  - Remove common stopwords; normalize case
  - Implement compute_dom_hash(html: str) → str (SHA256 of parsed DOM tree)
  - Parse HTML (BeautifulSoup), traverse tree, ignore whitespace/comments
  - Implement compute_text_hash(html: str) → str (SHA256 of extracted text only)
  - Extract all text nodes from HTML, concatenate, hash
  - For each Baseline: populate semantic_tokens, dom_hash, text_hash
  - Ensure determinism: same input always produces same hash
  - Test: Extract tokens from "<div>Hello 123</div>" → {hello, 123}; verify hash determinism
  - _Requirements: REQ-BE-02, REQ-BE-03_

### 4.4 Implement Jaccard Similarity Computation

- [ ] 4.4 Implement jaccard_similarity() and combined scoring
  - Implement jaccard_similarity(tokens1: Set, tokens2: Set) → float [0.0, 1.0]
  - Formula: |intersection| / |union|
  - Handle edge cases: empty sets → 0.0 if both empty, else 0.0
  - Implement size_ratio(size1: int, size2: int) → float [0.0, 1.0]
  - Formula: min(size1, size2) / max(size1, size2)
  - Implement combined_score = (jaccard * 0.6) + (size_ratio * 0.4)
  - Test: Reflexivity (tokens vs. itself = 1.0); known token sets (e.g., {a,b,c} vs {a,b} = 0.67)
  - _Requirements: REQ-BE-03, REQ-BE-04, REQ-BE-05_

### 4.5 Implement BaselineEngine.compare_semantic()

- [ ] 4.5 Implement compare_semantic() with threshold-based classification
  - Implement compare_semantic(test_response: str, baseline: Baseline) → SemanticComparisonResult
  - Extract tokens from test_response
  - Compute jaccard_similarity against baseline.semantic_tokens
  - Compute size_ratio
  - Compute combined_score
  - Threshold check: combined_score >= 0.75 → is_semantic_match = true
  - Generate semantic_difference description (new/missing tokens)
  - Return SemanticComparisonResult
  - Test: Identical response → similarity=1.0; significantly different → similarity < 0.75
  - _Requirements: REQ-BE-04, REQ-BE-05, REQ-INT-02_

---

## Layer 5: Evidence Graph (Proof Chains)

### 5.1 Define Evidence Graph Data Structures

- [ ] 5.1 Implement EvidenceNode, EvidenceEdge, and EvidenceGraph classes
  - Define @dataclass EvidenceNode with fields: node_id, node_type (EvidenceNodeType), hypothesis, hypothesis_class, signal_type, signal_source, signal_value, signal_confidence, proof_type, proof_data, proof_timestamp, context_type, context_data, parent_hypotheses, supporting_signals, required_proofs, created_timestamp, tool_id
  - Define @enum EvidenceNodeType: HYPOTHESIS, SIGNAL, PROOF, CONTEXT
  - Define @dataclass EvidenceEdge with fields: from_node_id, to_node_id, relationship_type (supports|proves|requires|context_for), weight [0.0, 1.0]
  - Define @dataclass EvidenceGraph with fields: graph_id, finding_type, root_hypothesis, nodes (dict), edges (list), confirmed_proofs, unconfirmed_signals, evidence_status, confidence_score, created_timestamp, last_updated
  - Verify data structures compile and instantiate correctly
  - _Requirements: REQ-EG-01_

### 5.2 Implement EvidenceGraph.build()

- [ ] 5.2 Implement EvidenceGraph.build() to construct proof chains
  - Create EvidenceGraph class
  - Implement build(finding: StandardFinding, signals: List[Signal]) → EvidenceGraph
  - Create root_hypothesis node with finding_type as hypothesis_class
  - FOR each signal: create signal_node, add to graph.nodes, create edge to root_hypothesis with weight=signal.confidence
  - FOR each evidence_item in finding.evidence: create proof_node with proof_type/proof_data, add to confirmed_proofs, create edge to root_hypothesis with weight=1.0
  - Identify unconfirmed_signals (signals without matching proofs)
  - Compute evidence_status and confidence_score
  - Test: Build graph from SSRF finding with 2 proofs, 3 signals → 6 nodes (1 hyp + 2 proofs + 3 signals)
  - _Requirements: REQ-EG-02, REQ-EG-03_

### 5.3 Implement Evidence Status Derivation

- [ ] 5.3 Implement evidence_status_from_graph() with confidence scoring
  - Implement evidence_status_from_graph(graph: EvidenceGraph) → FindingStatus
  - IF confirmed_proofs.length > 0: status = CONFIRMED
  - ELSE IF unconfirmed_signals.length > 0: status = OBSERVED
  - ELSE: status = NOT_TESTED
  - Implement confidence_score = proofs_count / (proofs_count + signals_count) IF denominator > 0, else 0.0
  - Ensure proofs get 100% weight, signals 0% (proofs alone determine confirmation)
  - Test: 1 proof, 2 signals → CONFIRMED, confidence=0.33; 0 proofs, 2 signals → OBSERVED, confidence=0.0
  - _Requirements: REQ-EG-04, REQ-POLICY-03_

### 5.4 Implement EvidenceGraph Immutability

- [ ] 5.4 Implement immutability enforcement
  - Add immutable flag to EvidenceGraph (set to true after build() completes)
  - In add_signal/add_proof methods: check immutable flag; return error if true
  - Document: new findings create new graphs (don't modify existing)
  - Track created_timestamp (never changes), last_updated_timestamp (read-only, updated on query)
  - Test: Create graph, attempt add_signal() → error; create new graph → success
  - _Requirements: REQ-EG-05, REQ-POLICY-04_

### 5.5 Implement Evidence Graph Justification String

- [ ] 5.5 Implement build_justification_string() for human-readable proofs
  - Implement build_justification_string(graph: EvidenceGraph) → str
  - Include: status line, proof summary, signal summary, discovery path, confidence
  - For proofs: "Evidence: N proofs" + list proof_type for each
  - For signals: "Signals: N signals" + list signal_type/source for each
  - Output 100–500 character string, human-readable
  - Test: SSRF finding with metadata marker proof → "Status: CONFIRMED. Evidence: 1 proof. Proof: aws_metadata_retrieved. Confidence: 100%"
  - _Requirements: REQ-EG-06_

### 5.6 Implement StandardFinding.enrich_with_orchestration()

- [ ] 5.6 Implement finding enrichment with orchestration metadata
  - Implement method in StandardFinding class
  - Add fields: evidence_graph_id, execution_ledger_id, negative_evidence, affected_endpoints, proof_of_concept, chain_of_discovery
  - Re-assess status based on evidence_graph (may promote OBSERVED → CONFIRMED)
  - Populate justification_string from evidence_graph
  - Return EnrichedStandardFinding with all metadata
  - Test: SSRF finding with evidence_graph → enriched finding has evidence_graph_id, justification, status updated if proofs present
  - _Requirements: REQ-EG-06, REQ-INT-04_

---

## Layer 6: Standardized Output Schema (Unified Tool Output)

### 6.1 Define Standardized Output JSON Schema

- [ ] 6.1 Implement JSON schema with execution, assessment, findings, negative_evidence sections
  - Document JSON schema with all fields: execution, assessment, findings, negative_evidence, execution_ledger, limitations, next_action
  - Implement JSON schema validator using jsonschema library
  - Define Finding object schema: finding_id, finding_type, title, description, severity (critical|high|medium|low|info), evidence_status, confidence, affected_endpoints, proof_of_concept, remediation, cve_references, cwe_references, owasp_references, limitations
  - Define NegativeEvidence schema: tests_performed, tests_with_no_findings, coverage_percentage, rate_limited_tests, waf_blocked_tests, timeout_tests, authentication_failures
  - Define ExecutionLedger entry schema: timestamp, action, phase_id, tool_id, details, related_finding_id
  - Create @dataclass for each schema component
  - Test: Generate sample output; validate with jsonschema → pass
  - _Requirements: REQ-OS-01_

### 6.2 Implement Tool Output Wrapper

- [ ] 6.2 Implement ToolOutputWrapper to normalize tool outputs
  - Create ToolOutputWrapper class
  - Implement wrap(raw_output: dict, tool_id: str, execution_id: UUID) → StandardizedToolOutput
  - Extract execution metadata: start_time, end_time, duration_seconds, status (completed|failed|timeout|interrupted), exit_code
  - Extract assessment: target_type, detected_tech_stack, scan_depth
  - Transform findings to standard Finding schema
  - Populate negative_evidence (tests_performed, tests_with_no_findings, coverage_percentage)
  - Generate execution_ledger from timestamps
  - Validate output against schema; return error if invalid
  - Test: Wrap nuclei, hydra, sqlmap outputs → all produce valid StandardizedToolOutput
  - _Requirements: REQ-OS-01, REQ-OS-02_

### 6.3 Implement Proof of Concept Generation

- [ ] 6.3 Implement generate_proof_of_concept() with evidence markers
  - Implement generate_proof_of_concept(finding: Finding, evidence_graph: EvidenceGraph) → ProofOfConcept
  - IF evidence_status = EXPLOITED: include full request-response pair
  - Extract proof_markers from evidence (specific strings confirming vulnerability)
  - IF evidence_status < EXPLOITED: proof_of_concept may be partial (request only, no response)
  - Ensure proof_markers present and exact (no truncation, no generalization)
  - Validate PoC is reproducible (all required headers, body, parameters present)
  - Test: EXPLOITED XSS finding includes alert(1) in response; CONFIRMED SQLi includes error message
  - _Requirements: REQ-OS-03, REQ-OS-02_

### 6.4 Implement Negative Evidence Tracking

- [ ] 6.4 Implement NegativeEvidence quantification
  - Create @dataclass NegativeEvidence
  - Implement compute_negative_evidence(tool_execution: ExecutionResult) → NegativeEvidence
  - Count total_planned_tests (from tool parameters)
  - Count tests_completed (from execution log)
  - Count findings_found (from results)
  - Compute coverage_percentage = tests_completed / total_planned * 100
  - Track blocking reasons: rate limit, WAF, timeout, auth failure
  - Test: Nuclei runs 100 tests, finds 2 → tests_performed=100, tests_with_no_findings=98, coverage=100%
  - _Requirements: REQ-OS-04, REQ-POLICY-02_

### 6.5 Implement Execution Ledger Recording

- [ ] 6.5 Implement ExecutionLedger for audit trail
  - Create @dataclass ExecutionLedgerEntry
  - Implement ExecutionLedger class with entries list
  - Implement record_action(action: str, **details) → void (timestamps automatically added)
  - FROM execute_plan(): call record_action("phase_started"), record_action("tool_started"), record_action("finding_discovered"), etc.
  - Ensure chronological order (timestamps sortable)
  - Implement queryable methods: events_for_phase(), events_for_tool(), events_in_time_range()
  - Test: Execute 3-phase plan; ledger has 9+ entries in order
  - _Requirements: REQ-OS-05_

### 6.6 Implement Limitations and Constraints Tracking

- [ ] 6.6 Implement Limitation recording with remediation suggestions
  - Create @dataclass Limitation with fields: category (RATE_LIMITING|WAF_PROTECTION|AUTHENTICATION|TIMEOUT|MISSING_PERMISSION|UNKNOWN), description, impact, recommendation
  - Implement add_limitation() to tool output wrapper
  - FROM execute_phase(): detect conditions:
    - 429/403 responses → RATE_LIMITING
    - WAF headers detected (X-WAF, etc.) → WAF_PROTECTION
    - 401/403 without credentials → AUTHENTICATION
    - Timeout exceeded → TIMEOUT
  - Generate description, impact, and remediation strings
  - Test: Get 429 response → limitation category=RATE_LIMITING with description and recommendation
  - _Requirements: REQ-OS-06_

### 6.7 Implement Next Action Guidance

- [ ] 6.7 Implement next_action computation for orchestrator guidance
  - Create @dataclass NextAction with fields: type (MANUAL_TESTING|EXPLOIT_VERIFICATION|CREDENTIAL_ACQUISITION|RETRY_WITH_EVASION|COMPLETED), reason, suggested_tool
  - Implement compute_next_action(findings: List[Finding], limitations: List[Limitation]) → NextAction
  - IF findings_count > 0 AND max_evidence_status < EXPLOITED: type=EXPLOIT_VERIFICATION
  - IF findings_count = 0 AND WAF_detected: type=RETRY_WITH_EVASION
  - IF findings_count = 0 AND auth_required: type=CREDENTIAL_ACQUISITION
  - IF all_findings_exploited: type=COMPLETED
  - Suggest appropriate tool: SSRF → ssrf_hunter, SQL → sqlmap, etc.
  - Test: SSRF with SUSPECTED status → suggest EXPLOIT_VERIFICATION with ssrf_hunter
  - _Requirements: REQ-OS-07_

---

## Layer 7: Evidence Policy Integration (Enforcement)

### 7.1 Enforce No Status Promotion Without Proof

- [ ] 7.1 Implement status validation with proof requirement
  - In StandardFinding.validate(), check evidence_graph.confirmed_proofs.length
  - IF status claims CONFIRMED but proofs.length = 0: cap status to OBSERVED
  - IF status claims EXPLOITED but proof_of_concept is empty: cap to CONFIRMED or lower
  - Add validation before any finding is reported
  - Log warning if status reduced
  - Test: Signal-only finding → status capped at OBSERVED; add proof → allow CONFIRMED
  - _Requirements: REQ-POLICY-01_

### 7.2 Enforce Baseline Mandatory Before Payload Testing

- [ ] 7.2 Implement baseline requirement enforcement
  - In Orchestrator.execute_plan(), verify baseline_establishment phase exists and completes first
  - IF baseline fails: stop scan, abort all downstream phases, log error
  - ALL payload phases must depend_on baseline; validate this constraint
  - Add assertion: no payload-based tool executes before baseline_output available
  - Test: Execute plan → baseline runs first; if baseline times out, SCAN skipped
  - _Requirements: REQ-POLICY-02_

### 7.3 Enforce Evidence Status Consistency

- [ ] 7.3 Implement consistency validation
  - Implement validate_evidence_consistency(finding: Finding) → bool|error
  - INVARIANT: (status=CONFIRMED) ⟹ (proofs.length > 0)
  - INVARIANT: (status=OBSERVED) ⟹ (proofs.length=0 AND signals.length > 0)
  - Call validation before finding included in report
  - Raise error if invariant violated
  - Test: Finding claims CONFIRMED with 0 proofs → validation error
  - _Requirements: REQ-POLICY-03_

### 7.4 Prevent Evidence Status Regression

- [ ] 7.4 Implement status history tracking with monotonic enforcement
  - Implement track_status_history(finding_id: UUID) → List[FindingStatus]
  - On status update: check new_status >= previous_status
  - IF new_status < previous_status: log warning, keep previous status
  - Allowed transitions: NOT_TESTED → TESTED → OBSERVED → SUSPECTED → CONFIRMED → EXPLOITED (monotonic)
  - Test: CONFIRMED finding cannot be downgraded to OBSERVED
  - _Requirements: REQ-POLICY-04_

### 7.5 Enforce Signal Validation Before Confirmation

- [ ] 7.5 Implement signal-proof correlation checking
  - In EvidenceGraph.build(), signals added to unconfirmed_signals initially
  - When proof_node added: check if signal correlates (same vulnerability class)
  - Only signals with matching proofs removed from unconfirmed
  - Signals alone never cause CONFIRMED status
  - Document signal-only → OBSERVED, proof-based → CONFIRMED
  - Test: 10 signals, 1 proof → status=CONFIRMED (proof drives it)
  - _Requirements: REQ-POLICY-05, REQ-EG-02_

---

## Layer 8: Cross-Layer Integration & Testing

### 8.1 Implement End-to-End Integration Test

- [ ] 8.1 Create end-to-end test of full pipeline
  - Create test that runs complete pipeline: plan → baseline → scan → findings
  - Test scenario: plan_scan("http://example.com", "deep", VULN_ASSESS)
  - execute_plan() with mocked tool outputs (nuclei finds SSRF, hydra finds weak creds)
  - Verify: phases execute in order, baselines established, findings wrapped, evidence graphs created
  - Verify: output conforms to standardized schema
  - Check all 6 layers work together correctly
  - Test: Mock 3-phase plan (RECON → BASELINE → SCAN) executes completely with findings
  - _Requirements: REQ-INT-01, REQ-INT-02, REQ-INT-03_

### 8.2 Implement Correctness Property Tests

- [ ] 8.2 Create property-based tests for invariants
  - test_dag_acyclicity() — verify all generated plans form valid DAG (no cycles)
  - test_evidence_status_consistency() — verify status matches proof presence
  - test_baseline_before_payload() — verify phase ordering constraint
  - test_semantic_reflexivity() — verify similarity(x, x) = 1.0 for all responses
  - test_tool_health_before_execution() — verify only HEALTHY tools run
  - test_no_status_regression() — verify status transitions monotonic
  - test_negative_evidence_coverage() — verify negative_evidence.coverage_percentage >= 0
  - Run all tests; all pass
  - _Requirements: REQ-INT-02, REQ-POLICY-03_

### 8.3 Implement Performance Benchmarks

- [ ] 8.3 Create performance benchmarks for critical paths
  - Benchmark plan_scan() latency (target < 100ms)
  - Benchmark baseline_establishment latency (target < 5s for 3 requests)
  - Benchmark semantic_comparison for 10MB response (target < 50ms)
  - Benchmark evidence_graph construction per finding (target < 50ms)
  - Benchmark topological_sort for 20-phase plan (target < 10ms)
  - Document results; identify bottlenecks
  - Run benchmarks on realistic data; confirm < target latencies
  - _Requirements: REQ-INT-03_

### 8.4 Implement Tool Wrappers for Key Tools

- [ ] 8.4 Create wrappers for Nuclei, Hydra, Sqlmap
  - Create wrapper for Nuclei → standardized output
  - Extract findings from nuclei JSON output
  - Map nuclei severity to standard severity enum
  - Map nuclei metadata to affected_endpoints
  - Create wrapper for Hydra → standardized output
  - Create wrapper for Sqlmap → standardized output
  - Test each wrapper with real tool output
  - Verify standardized schema validation passes for each
  - _Requirements: REQ-INT-04, REQ-OS-01_

### 8.5 Create Documentation and User Guide

- [ ] 8.5 Document API and usage patterns
  - Document Tool Registry usage (register tools, query capabilities)
  - Document Orchestrator usage (plan_scan, execute_plan)
  - Document Evidence Graph interpretation (proof chains, status justification)
  - Create example: "From RECON to CONFIRMED finding" (full walkthrough)
  - Create API documentation (all public methods, parameters, return values)
  - Create troubleshooting guide (common issues, debugging)
  - Verify: new user can register a tool, run a scan, interpret findings
  - _Requirements: REQ-INT-05_

---

## Checkpoint Tasks

- [ ] Checkpoint 1 (After Layer 1-2): Tool Registry and Capability Engine working; tools queryable by capability
- [ ] Checkpoint 2 (After Layer 3): Orchestrator generating valid plans; phases in correct order
- [ ] Checkpoint 3 (After Layer 4): Baseline Engine establishing 3 baselines; semantic comparison working
- [ ] Checkpoint 4 (After Layer 5): Evidence Graph constructing proof chains; status derived correctly
- [ ] Checkpoint 5 (After Layer 6): Standardized output schema complete; tool outputs wrappable
- [ ] Checkpoint 6 (After Layer 7): Evidence Policy enforced; no status promotion without proof
- [ ] Checkpoint 7 (Final): End-to-end test passing; all 33 tasks complete; benchmarks meet targets

---

## Notes

- **Parallel Execution**: Tasks within same layer can run in parallel (e.g., 2.1 and 2.2 can start after 1.2 completes)
- **Critical Path**: TASK-TR-01 → TR-02 → CE-02 → ORCH-02 → BE-02 → BE-04 → BE-05 → EG-02 → OS-01 → INT-01
- **Testing Strategy**:
  - Unit tests for each task (verify individual methods work)
  - Integration tests at each checkpoint (verify layer communication)
  - Property tests for correctness invariants
  - End-to-end test with mocked tools
- **Implementation Language**: Python 3.9+
- **Key Libraries**: 
  - dataclasses (built-in), enum (built-in), uuid (built-in), datetime (built-in)
  - requests (HTTP baseline), networkx (DAG operations), BeautifulSoup4 (HTML parsing)
  - jsonschema (output validation)

---

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "2.1"] },
    { "id": 1, "tasks": ["1.2", "2.2"] },
    { "id": 2, "tasks": ["1.3", "1.4", "2.3", "2.4"] },
    { "id": 3, "tasks": ["3.1", "4.1", "5.1", "6.1"] },
    { "id": 4, "tasks": ["3.2", "4.2"] },
    { "id": 5, "tasks": ["3.3", "3.4", "4.3", "4.4"] },
    { "id": 6, "tasks": ["3.5", "4.5", "5.2"] },
    { "id": 7, "tasks": ["3.6", "5.3", "5.4"] },
    { "id": 8, "tasks": ["5.5", "5.6", "6.2"] },
    { "id": 9, "tasks": ["6.3", "6.4", "6.5"] },
    { "id": 10, "tasks": ["6.6", "6.7"] },
    { "id": 11, "tasks": ["7.1", "7.2", "7.3"] },
    { "id": 12, "tasks": ["7.4", "7.5"] },
    { "id": 13, "tasks": ["8.1", "8.2"] },
    { "id": 14, "tasks": ["8.3", "8.4", "8.5"] }
  ]
}
```

---

**End of Implementation Plan**

This tasks.md file provides a complete roadmap for implementing Kali MCP V2 Orchestration. Each task includes clear acceptance criteria, verification steps, specific requirements, and dependency information. The task dependency graph shows execution waves for parallel scheduling.

