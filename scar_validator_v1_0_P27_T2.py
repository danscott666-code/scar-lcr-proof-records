#!/usr/bin/env python3
"""
SCAR Compliance Validator v1.0 FINAL
Structural Coherence Audit & Repair — Execution Enforcement Layer
© Danny Scott 2026

Authority layers (all frozen — do not modify):
  VALIDATION_AUTHORITY_VERSION = "v1.3"
  EXECUTION_STANDARD_VERSION   = "v1.4"
  VALIDATOR_VERSION            = "1.0"
  MANIFEST_SCHEMA_VERSION      = "1.0"
  CANONICAL_AUTHORITY_DOCNAME  = "SCAR_Validation_Pack_v1.3_MASTER.docx"

Patches applied over RC2 (ChatGPT final patch list, items 1–15):
  P01  Preflight gate blocks post_run on Class A outcome, not just call order
  P02  Canonical authority checked by name AND hash
  P03  Version fields fully separated: validator / manifest_schema / system
  P04  required_artefacts in manifest is fully operative (Option A)
  P05  optional_artefacts constrained by profile and scope
  P06  Inline JSON Schema validation for all 8 artefact files
  P07  Validator immutability across full cycle: init / preflight / post_run / emit
  P08  Input availability semantics: missing local file = Class A for requiring profiles
  P09  Contradiction checks broadened across all 8 manifest/runtime/artefact pairs
  P10  Full rule trace: RULE_TRACE section in COMPLIANCE_REPORT.json
  P11  Alpha type: isinstance(alpha, (int, float)) — aligns with schema
  P12  Dead code removed; no duplicate emission
  P13  Explicit profile-governed sign-off logic in summary
  P14  Profile-aware artefact and rule requirements (demo → hostile_audit)
  P15  Boundary lock self-consistency: all required entries enforced

Patches applied per Clean Rewrite audit (Danny Scott directive, 2026-04-05):
  P16  ERROR status defined and special-cased before generic invalid-status check
  P17  DEFERRED — adversarial execution check pending artefact contract freeze
  P18  Runner hash enforced in execution boundary (Class B)
  P19  Null model invariants declaration enforced in preflight (R-PF-20)
  P20  Determinism enforcement broadened across all profiles (Class A always)
  P21  Runtime completion gate added as independent check (R-RT-01)
  P22  Runtime completion proof strengthened: manifest profile authoritative,
       stages_completed semantic validation, profile mismatch fails,
       file-size check scoped as preliminary evidence only (R-RT-01 replacement)
  P23  Independent determinism verification: RERUN_BOUNDARY.lock.json hash comparison
       replaces self-reported determinism_check_passed; two-tier model (Tier A independent
       proof / Tier B partial evidence); manifest_hash match enforced Class A; artefact-set
       mismatch explicit Class A; environment presence checked (Class B / Class A hostile);
       final+hostile_audit rerun absence=Class A; comparison scoped to stable artefact
       hashes only — transient metadata (run_id, sealed_at) excluded from equality testing
  P23-fix-2  Two remaining logic gaps closed: (1) primary boundary schema validity now
       tracked and gates determinism comparison — lock present but schema-invalid is
       treated as inadmissible; (2) missing/empty validator hashes in boundary now
       produce explicit violation rather than silently falling through to PASS
  P24a Scope wording tightened before Item 3: (A) Tier B determinism explicitly
       scoped as single-run non-contradiction only — NOT determinism verification;
       (B) R-RT-01 pass note explicitly scoped as declared-stage/artefact consistency
       only — not proof that stages actually executed
  P25-fix  Four hostile-auditor corrections to R-PR-12 only:
       (1) Rerun-side independent hash recomputation added — both primary and rerun
           boundary hashes now verified from disk before any comparison;
       (2) Input integrity wording corrected — scoped to disk-to-manifest verification
           only; cross-run comparison not claimed (no per-run input evidence artefacts);
       (3) Environment equality Class A reverted to locked policy — presence check
           only, Class B standard / Class A hostile_audit, equality not enforced;
       (4) Stable comparison set reverted to boundary-defined keys minus DETERMINISM_EXCLUDED;
           _required_artefacts() no longer substituted for boundary stable set
  P25-fix-2  Four wording/comment fixes to R-PR-12 only (no logic changes):
       (1) Stale contradictory P25 bullets removed from header — P25-fix is now sole
           authoritative description;
       (2) R-PR-12 block comment rewritten to match actual implementation exactly —
           stale claims about required-set coverage, cross-run inputs, env equality removed;
       (3) Final determinism pass note narrowed — no longer claims "independent
           determinism verified"; now states only what is actually proven under current
           boundary architecture with shared run_dir;
       (4) Explicit note added that both boundary declarations are checked against
           the same shared run_dir materialisation, not separate retained directories
  P26-fix  Three blocker fixes: (1) Schema presence flags for p_value, fdr_corrected,
       theta_observed, pass_condition changed to required=False so P26 profile-sensitive
       severity governs absence — schema layer now enforces type only if present;
       (2) --phase CLI argument honoured in __main__ — preflight/post_run/all now route
       correctly instead of always running run_all; (3) Option B wording: clarifying
       comment added that audit_grade_ready is profile-agnostic by design; P26 R-PR-08
       comment tightened to "completeness and internal consistency"
       R-PR-07 extended: E1 verdict validity + ERROR gate; E2 pass_condition non-empty
           non-whitespace profile-sensitive; E3 theta_observed consistency with tolerance;
           E4 fdr_method consistency — mismatch/invalid=Class A all profiles, absent=Class A
           final+hostile_audit, Class B lower; E8 kappa_L threshold consistency with
           tolerance, PARTIAL skipped, kappa_L from manifest authoritative;
       R-PR-08 extended: E5 fdr_corrected in [0,1]; E6 plausibility fdr_corrected>=p_value
           for BH/bonferroni only, guarded on presence, Class B only; E7 z_score+effect_size
           profile-sensitive Class A hostile_audit+final, Class B lower; E9 p_value presence
           enforced — missing=Class A final+hostile_audit else Class B;
       Source authority hierarchy declared in comments: manifest=config, COMPARISON=verdict,
           STATISTICS=computed, OBSERVED_METRICS=raw; cross-source conflict=Class A;
       Non-goals explicitly stated: no method re-execution, no BH/FDR correctness proof,
           no permutation test validation, no sample independence verification
  P27  Item 4 — Schema contract self-binding and drift detection (R-PF-21):
       SCHEMA_AUTHORITY_HASH constant added — frozen from accepted canonical schema state
           for this validator version; not external authority binding;
       _compute_schema_hash() helper — deterministic SHA-256 of ARTEFACT_SCHEMAS using
           canonical serialisation: artefacts sorted by name, fields sorted by name,
           each field as {"name":..,"required":<bool>,"type":<canonical_token>};
       Type normalisation: singleton type -> string token; tuple type -> sorted list of
           string tokens; hard failure on unsupported type (no silent coercion);
       Drift = Class A on all profiles; assurance boundary: local drift detection only,
           not external provenance proof; external integrity via validator immutability
"""

import json, hashlib, sys, pathlib, datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple

# ── FROZEN AUTHORITY CONSTANTS ───────────────────────────────────────────────
VALIDATOR_VERSION            = "1.0"
MANIFEST_SCHEMA_VERSION      = "1.0"
VALIDATION_AUTHORITY_VERSION = "v1.3"
EXECUTION_STANDARD_VERSION   = "v1.4"
CANONICAL_AUTHORITY_DOCNAME  = "SCAR_Validation_Pack_v1.3_MASTER.docx"

# ── PROFILE DEFINITIONS (P14) ─────────────────────────────────────────────────
# Each profile defines: null_floor, max_class_b_allowed, requires_comparison,
# requires_repair_report, requires_determinism_check, allows_missing_local_inputs
PROFILE_RULES: Dict[str, Dict[str, Any]] = {
    "demo": {
        "null_floor":                  100,
        "max_class_b_allowed":         None,   # unlimited
        "requires_comparison":         False,
        "requires_repair_report":      False,
        "requires_determinism_check":  False,
        "requires_rerun_boundary":     False,  # P23-fix: explicit policy
        "allows_missing_local_inputs": True,
        "optional_artefacts_blocked":  set(),
    },
    "reduced": {
        "null_floor":                  1000,
        "max_class_b_allowed":         None,
        "requires_comparison":         False,
        "requires_repair_report":      False,
        "requires_determinism_check":  False,
        "requires_rerun_boundary":     False,  # P23-fix: explicit policy
        "allows_missing_local_inputs": True,
        "optional_artefacts_blocked":  set(),
    },
    "standard": {
        "null_floor":                  5000,
        "max_class_b_allowed":         None,
        "requires_comparison":         True,
        "requires_repair_report":      False,
        "requires_determinism_check":  False,
        "requires_rerun_boundary":     False,  # P23-fix: explicit policy
        "allows_missing_local_inputs": False,
        "optional_artefacts_blocked":  {"COMPARISON.json"},
    },
    "final": {
        "null_floor":                  10000,
        "max_class_b_allowed":         None,
        "requires_comparison":         True,
        "requires_repair_report":      True,
        "requires_determinism_check":  True,
        "requires_rerun_boundary":     True,   # P23: independent determinism proof mandatory
        "allows_missing_local_inputs": False,
        "optional_artefacts_blocked":  {"COMPARISON.json", "REPAIR_REPORT.json"},
    },
    "hostile_audit": {
        "null_floor":                  50000,
        "max_class_b_allowed":         0,      # zero B tolerated
        "requires_comparison":         True,
        "requires_repair_report":      True,
        "requires_determinism_check":  True,
        "requires_rerun_boundary":     True,   # P23: independent determinism proof mandatory
        "allows_missing_local_inputs": False,
        "optional_artefacts_blocked":  {"COMPARISON.json", "REPAIR_REPORT.json"},
    },
}

REQUIRED_ARTEFACTS_ALWAYS = [
    "RUN_REPORT.json",
    "OBSERVED_METRICS.json",
    "NULL_METRICS.json",
    "STATISTICS.json",
    "FAILURE_SUMMARY.json",
    "EXECUTION_BOUNDARY.lock.json",
]

VALID_STATUSES        = {"PASS", "PARTIAL", "FAIL"}
EXECUTION_ERROR_STATE = "ERROR"   # P16: distinct execution failure — not a valid classification
ALLOWED_OP_TYPES = {"substitution", "deletion", "insertion", "reorder", "normalise"}
ALLOWED_DOMAINS  = {"AI_hallucination", "scripture", "finance", "pharmacy",
                    "defence", "biological", "custom"}
ALLOWED_FDR      = {"BH", "BY", "bonferroni", "none_single_test"}

# P27: Schema contract self-binding and drift detection
# SCHEMA_AUTHORITY_HASH is the SHA-256 of the canonical serialisation of ARTEFACT_SCHEMAS
# for this validator version. It is initialised from the accepted canonical schema state
# and then frozen as part of this validator version. It is NOT external authority binding.
# Assurance: detects accidental or partial schema drift. Does not detect coordinated
# whole-file replacement (covered by validator immutability, R-PF-07).
# Canonical serialisation: artefacts sorted by name; fields sorted by name;
# each field as {"name":str, "required":bool, "type":token_or_sorted_list};
# type normalisation: singleton->string token, tuple->sorted list of string tokens.
SCHEMA_AUTHORITY_HASH = "7ede1e7927bd31df971290a583e259f50b4d85513216aa80dc87f6123575d86f"

# P27: frozen type normalisation map for _compute_schema_hash()
# Hard failure on unsupported type — no silent coercion permitted.
_SCHEMA_TYPE_MAP: dict = {
    str:    "str",
    int:    "int",
    float:  "float",
    bool:   "bool",
    list:   "list",
    dict:   "dict",
    object: "object",
}

# P22: mandatory stage artefacts per profile — used for runtime completion proof
MANDATORY_STAGE_ARTEFACTS: Dict[str, List[str]] = {
    "demo":          ["RUN_REPORT.json", "OBSERVED_METRICS.json",
                      "NULL_METRICS.json", "STATISTICS.json",
                      "FAILURE_SUMMARY.json", "EXECUTION_BOUNDARY.lock.json"],
    "reduced":       ["RUN_REPORT.json", "OBSERVED_METRICS.json",
                      "NULL_METRICS.json", "STATISTICS.json",
                      "FAILURE_SUMMARY.json", "EXECUTION_BOUNDARY.lock.json"],
    "standard":      ["RUN_REPORT.json", "OBSERVED_METRICS.json",
                      "NULL_METRICS.json", "STATISTICS.json",
                      "COMPARISON.json", "FAILURE_SUMMARY.json",
                      "EXECUTION_BOUNDARY.lock.json"],
    "final":         ["RUN_REPORT.json", "OBSERVED_METRICS.json",
                      "NULL_METRICS.json", "STATISTICS.json",
                      "COMPARISON.json", "REPAIR_REPORT.json",
                      "FAILURE_SUMMARY.json", "EXECUTION_BOUNDARY.lock.json"],
    "hostile_audit": ["RUN_REPORT.json", "OBSERVED_METRICS.json",
                      "NULL_METRICS.json", "STATISTICS.json",
                      "COMPARISON.json", "REPAIR_REPORT.json",
                      "FAILURE_SUMMARY.json", "EXECUTION_BOUNDARY.lock.json"],
}

# ── INLINE ARTEFACT SCHEMAS (P06) ─────────────────────────────────────────────
# Format: field → (required:bool, type_or_types)
ARTEFACT_SCHEMAS: Dict[str, List[Tuple[str, bool, Any]]] = {
    "RUN_REPORT.json": [
        ("status",                       True,  str),
        ("run_id",                        True,  str),
        ("start_time",                    True,  str),
        ("end_time",                      True,  str),
        ("validation_authority_version",  True,  str),
        ("execution_standard_version",    True,  str),
        ("stages_completed",              True,  list),   # P22: required for completion proof
        ("operators_used",                False, list),
        ("repair_performed",              False, bool),
    ],
    "OBSERVED_METRICS.json": [
        ("theta",            True,  (int, float)),
        ("structural_score", True,  (int, float)),
        ("n_units",          True,  int),
        ("seed_used",        False, int),
        ("alpha_used",       False, (int, float)),
    ],
    "NULL_METRICS.json": [
        ("n_samples", True, int),
        ("null_mean", True, (int, float)),
        ("null_std",  True, (int, float)),
        ("null_min",  True, (int, float)),
        ("null_max",  True, (int, float)),
    ],
    "STATISTICS.json": [
        # p_value and fdr_corrected presence governed by P26 (E9, E5) with profile-sensitive
        # severity. Schema layer enforces type only if present; P26 handles missing-field severity.
        ("p_value",       False, float),        # P26-E9: presence governed by profile
        ("fdr_corrected", False, float),        # P26-E5: presence governed by profile
        ("z_score",       False, (int, float)),
        ("effect_size",   False, (int, float)),
    ],
    "COMPARISON.json": [
        ("verdict",        True,  str),         # Always required — E1 gates on this
        ("kappa_L",        True,  (int, float)),# Always required — manifest consistency
        # theta_observed and pass_condition presence governed by P26 (E2, E3) with
        # profile-sensitive severity. Schema layer enforces type only if present.
        ("theta_observed", False, (int, float)),# P26-E3/E8: presence governed by P26
        ("pass_condition", False, str),         # P26-E2: presence governed by profile
    ],
    "REPAIR_REPORT.json": [
        ("repair_attempted",    True, bool),
        ("candidates_evaluated", True, int),
        ("c_star",               True, object),
    ],
    "FAILURE_SUMMARY.json": [
        ("class_a_failures", True, list),
        ("class_b_failures", True, list),
        ("total_failures",   True, int),
    ],
    "EXECUTION_BOUNDARY.lock.json": [
        ("run_id",          True, str),
        ("sealed_at",       True, str),
        ("artefact_hashes", True, dict),
        ("environment",     True, dict),
        ("validator_hash",  True, str),
        ("manifest_hash",   True, str),
    ],
    # P23: rerun boundary — same schema as primary boundary
    "RERUN_BOUNDARY.lock.json": [
        ("run_id",          True, str),
        ("sealed_at",       True, str),
        ("artefact_hashes", True, dict),
        ("environment",     True, dict),
        ("validator_hash",  True, str),
        ("manifest_hash",   True, str),
    ],
}


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────
@dataclass
class Violation:
    rule_id:  str
    cls:      str
    message:  str
    evidence: str = ""

@dataclass
class RuleTrace:
    rule_id:        str
    phase:          str
    cls:            str
    result:         str     # PASS / FAIL / SKIP
    blocking:       bool
    failure_effect: str     # "FAIL" / "RECORD" / "WARN" / "N/A"
    artefacts:      List[str] = field(default_factory=list)
    note:           str = ""

@dataclass
class ValidationResult:
    phase:      str
    status:     str = "PASS"
    violations: List[Violation]  = field(default_factory=list)
    traces:     List[RuleTrace]  = field(default_factory=list)
    timestamp:  str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def add(self, v: Violation, artefacts: List[str] = None, note: str = ""):
        self.violations.append(v)
        blocking      = v.cls == "A"
        failure_effect = "FAIL" if blocking else ("RECORD" if v.cls == "B" else "WARN")
        self.traces.append(RuleTrace(
            rule_id=v.rule_id, phase=self.phase, cls=v.cls,
            result="FAIL", blocking=blocking, failure_effect=failure_effect,
            artefacts=artefacts or [], note=note or v.message
        ))
        if v.cls == "A":
            self.status = "FAIL"

    def pass_rule(self, rule_id: str, cls: str = "A",
                  artefacts: List[str] = None, note: str = ""):
        self.traces.append(RuleTrace(
            rule_id=rule_id, phase=self.phase, cls=cls,
            result="PASS", blocking=False, failure_effect="N/A",
            artefacts=artefacts or [], note=note
        ))


# ── VALIDATOR ─────────────────────────────────────────────────────────────────
class SCARValidator:

    def __init__(self, manifest_path: str, run_dir: str,
                 authority_path: Optional[str] = None):
        self.manifest_path  = pathlib.Path(manifest_path)
        self.run_dir        = pathlib.Path(run_dir)
        self.authority_path = pathlib.Path(authority_path) if authority_path else None
        self.manifest: Dict  = {}
        self._preflight_done:   bool = False
        self._preflight_passed: bool = False
        self._preflight_result: Optional[ValidationResult] = None
        self._postrun_result:   Optional[ValidationResult] = None
        # P07: hash self at init — stored for full-cycle comparison
        self._validator_hash_at_init = self._sha256(pathlib.Path(__file__))
        self._validator_hash_at_preflight: Optional[str] = None
        self._validator_hash_at_postrun:   Optional[str] = None

    # ── UTILITIES ─────────────────────────────────────────────────────────────
    def _sha256(self, path: pathlib.Path) -> str:
        if not path or not path.exists():
            return "FILE_MISSING"
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _load_json(self, path: pathlib.Path) -> Tuple[Optional[dict], Optional[str]]:
        if not path.exists():
            return None, f"File not found: {path}"
        try:
            return json.loads(path.read_text(encoding="utf-8")), None
        except json.JSONDecodeError as e:
            return None, f"JSON parse error in {path.name}: {e}"

    def _art(self, name: str) -> pathlib.Path:
        return self.run_dir / name

    def _profile(self) -> Dict[str, Any]:
        return PROFILE_RULES.get(self.manifest.get("profile_mode", "standard"),
                                  PROFILE_RULES["standard"])

    # P27: deterministic schema hash for drift detection
    def _compute_schema_hash(self) -> str:
        """
        Produce a deterministic SHA-256 of the current ARTEFACT_SCHEMAS semantic contract.
        Canonical form: artefacts sorted by name; fields sorted by field name;
        each field serialised as {"name":str, "required":bool, "type":<token>};
        singleton type -> string token; tuple type -> sorted list of string tokens.
        Raises ValueError (surfaced as Class A) on any unsupported type — no silent coercion.
        """
        import json as _json

        def _type_token(t: Any) -> Any:
            if isinstance(t, tuple):
                tokens = []
                for elem in t:
                    if elem not in _SCHEMA_TYPE_MAP:
                        raise ValueError(
                            f"_compute_schema_hash: unsupported type in tuple: {elem!r}. "
                            "Add to _SCHEMA_TYPE_MAP or update SCHEMA_AUTHORITY_HASH.")
                    tokens.append(_SCHEMA_TYPE_MAP[elem])
                return sorted(tokens)   # sorted list of string tokens
            else:
                if t not in _SCHEMA_TYPE_MAP:
                    raise ValueError(
                        f"_compute_schema_hash: unsupported singleton type: {t!r}. "
                        "Add to _SCHEMA_TYPE_MAP or update SCHEMA_AUTHORITY_HASH.")
                return _SCHEMA_TYPE_MAP[t]  # string token

        canonical: Dict[str, Any] = {}
        for art_name in sorted(ARTEFACT_SCHEMAS.keys()):
            fields = ARTEFACT_SCHEMAS[art_name]
            field_records = []
            for fname, required, ftype in sorted(fields, key=lambda x: x[0]):
                field_records.append({
                    "name":     fname,
                    "required": required,           # JSON boolean
                    "type":     _type_token(ftype),
                })
            canonical[art_name] = field_records

        serialised = _json.dumps(
            canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(serialised.encode("utf-8")).hexdigest()

    # P04: required_artefacts fully operative
    def _required_artefacts(self) -> List[str]:
        pr = self._profile()
        # Start from manifest declaration if present, else REQUIRED_ARTEFACTS_ALWAYS
        manifest_required = self.manifest.get("required_artefacts")
        if manifest_required:
            # Merge: mandatory baseline must always be included
            base = set(REQUIRED_ARTEFACTS_ALWAYS) | set(manifest_required)
        else:
            base = set(REQUIRED_ARTEFACTS_ALWAYS)
        # P05: add conditionally required artefacts per profile
        if pr["requires_comparison"]:
            base.add("COMPARISON.json")
        if pr["requires_repair_report"]:
            base.add("REPAIR_REPORT.json")
        # P05: remove optional only if profile allows it
        optional_out   = set(self.manifest.get("optional_artefacts", []))
        blocked_opt    = pr["optional_artefacts_blocked"]
        effective_opt  = optional_out - blocked_opt
        return sorted(base - effective_opt)

    # P06: schema validation
    def _validate_artefact_schema(self, name: str, data: dict,
                                   result: ValidationResult) -> bool:
        schema = ARTEFACT_SCHEMAS.get(name)
        if not schema or data is None:
            return True
        all_ok = True
        for fname, required, ftype in schema:
            if fname not in data:
                if required:
                    result.add(Violation(f"R-SCHEMA","A",
                        f"{name}: missing required field '{fname}'"),
                        artefacts=[name])
                    all_ok = False
            elif ftype is not object:
                val = data[fname]
                if not isinstance(val, ftype):
                    result.add(Violation(f"R-SCHEMA","B",
                        f"{name}: field '{fname}' wrong type "
                        f"(expected {ftype.__name__ if hasattr(ftype,'__name__') else ftype}, "
                        f"got {type(val).__name__})"),
                        artefacts=[name])
        return all_ok

    # ── PHASE 1: PREFLIGHT ────────────────────────────────────────────────────
    def preflight(self) -> ValidationResult:
        r = ValidationResult(phase="PREFLIGHT")

        # P07: record validator hash at preflight
        self._validator_hash_at_preflight = self._sha256(pathlib.Path(__file__))

        # R-PF-01: manifest loads
        manifest, err = self._load_json(self.manifest_path)
        if err:
            r.add(Violation("R-PF-01","A","Manifest missing or invalid", err),
                  artefacts=["manifest"])
            self._finalise_preflight(r)
            return r
        self.manifest = manifest
        r.pass_rule("R-PF-01", "A", ["manifest"], "Manifest loaded")

        # P03: version fields — no ambiguity
        # R-PF-02: manifest_schema_version
        msv = manifest.get("manifest_schema_version")
        if msv != MANIFEST_SCHEMA_VERSION:
            r.add(Violation("R-PF-02","A",
                f"manifest_schema_version must be '{MANIFEST_SCHEMA_VERSION}', got: {msv!r}"))
        else:
            r.pass_rule("R-PF-02","A", note=f"manifest_schema_version={msv}")

        # R-PF-03: validation_authority_version
        va = manifest.get("validation_authority_version")
        if va != VALIDATION_AUTHORITY_VERSION:
            r.add(Violation("R-PF-03","A",
                f"validation_authority_version must be '{VALIDATION_AUTHORITY_VERSION}', got: {va!r}"))
        else:
            r.pass_rule("R-PF-03","A", note=f"validation_authority_version={va}")

        # R-PF-04: execution_standard_version
        es = manifest.get("execution_standard_version")
        if es != EXECUTION_STANDARD_VERSION:
            r.add(Violation("R-PF-04","A",
                f"execution_standard_version must be '{EXECUTION_STANDARD_VERSION}', got: {es!r}"))
        else:
            r.pass_rule("R-PF-04","A", note=f"execution_standard_version={es}")

        # P02: canonical authority — name AND hash (both required)
        # R-PF-05: exact canonical document name
        doc_name = manifest.get("canonical_validation_doc","")
        if doc_name != CANONICAL_AUTHORITY_DOCNAME:
            r.add(Violation("R-PF-05","A",
                f"canonical_validation_doc must be exactly '{CANONICAL_AUTHORITY_DOCNAME}'",
                f"Got: {doc_name!r}"))
        else:
            r.pass_rule("R-PF-05","A", note="canonical doc name verified")

        # R-PF-06: canonical document SHA-256
        auth_sha = manifest.get("canonical_validation_doc_sha256","")
        if len(auth_sha) != 64 or not all(c in "0123456789abcdef" for c in auth_sha):
            r.add(Violation("R-PF-06","A",
                "canonical_validation_doc_sha256 must be 64-char lowercase hex",
                f"Got: {auth_sha!r}"))
        else:
            r.pass_rule("R-PF-06","A", note="authority SHA format valid")
            if self.authority_path and self.authority_path.exists():
                actual_auth = self._sha256(self.authority_path)
                if actual_auth != auth_sha:
                    r.add(Violation("R-PF-06","A","Authority file hash mismatch",
                        f"Declared: {auth_sha[:16]}... Actual: {actual_auth[:16]}..."))
                else:
                    r.pass_rule("R-PF-06","A",
                        [str(self.authority_path)], "Authority file hash verified")

        # P07: validator hash at preflight matches init hash
        # R-PF-07: validator immutability at preflight
        declared_v_sha = manifest.get("validator_sha256","")
        if not declared_v_sha:
            r.add(Violation("R-PF-07","B",
                "validator_sha256 not declared — immutability unverifiable"))
        else:
            if self._validator_hash_at_preflight != self._validator_hash_at_init:
                r.add(Violation("R-PF-07","A",
                    "Validator changed between init and preflight",
                    f"Init: {self._validator_hash_at_init[:16]}... "
                    f"Preflight: {self._validator_hash_at_preflight[:16]}..."))
            elif (self._validator_hash_at_preflight != "FILE_MISSING"
                  and declared_v_sha != self._validator_hash_at_preflight):
                r.add(Violation("R-PF-07","A",
                    "Declared validator_sha256 does not match runtime validator",
                    f"Declared: {declared_v_sha[:16]}... "
                    f"Runtime: {self._validator_hash_at_preflight[:16]}..."))
            else:
                r.pass_rule("R-PF-07","A", note="Validator hash verified at preflight")

        # R-PF-08: domain
        domain = manifest.get("domain")
        if domain not in ALLOWED_DOMAINS:
            r.add(Violation("R-PF-08","A",
                f"domain must be one of {sorted(ALLOWED_DOMAINS)}, got: {domain!r}"))
        else:
            r.pass_rule("R-PF-08","A", note=f"domain={domain}")

        # R-PF-09: profile_mode
        profile_mode = manifest.get("profile_mode")
        if profile_mode not in PROFILE_RULES:
            r.add(Violation("R-PF-09","A",
                f"profile_mode invalid: {profile_mode!r}",
                f"Must be one of {sorted(PROFILE_RULES.keys())}"))
        else:
            r.pass_rule("R-PF-09","A", note=f"profile={profile_mode}")

        pr = self._profile()

        # R-PF-10: kappa_L
        kappa = manifest.get("kappa_L")
        if not isinstance(kappa, (int, float)) or kappa <= 0:
            r.add(Violation("R-PF-10","A",
                f"kappa_L must be positive number, got: {kappa!r}"))
        else:
            r.pass_rule("R-PF-10","A", note=f"kappa_L={kappa}")

        # R-PF-11: null_samples with profile floor
        ns = manifest.get("null_samples", 0)
        floor = pr["null_floor"]
        if not isinstance(ns, int) or ns < floor:
            r.add(Violation("R-PF-11","A",
                f"null_samples={ns} below floor={floor} for profile='{profile_mode}'",
                "Silent downgrade forbidden (v1.4 §4.3 R4)"))
        else:
            r.pass_rule("R-PF-11","A", note=f"null_samples={ns} >= floor={floor}")

        # P11: alpha uses (int, float)
        # R-PF-12: alpha
        alpha = manifest.get("alpha")
        if not isinstance(alpha, (int, float)) or not (0 < alpha < 1):
            r.add(Violation("R-PF-12","A",
                f"alpha must be numeric in (0,1), got: {alpha!r}"))
        else:
            r.pass_rule("R-PF-12","A", note=f"alpha={alpha}")

        # R-PF-13: fdr_method — Class A
        fdr = manifest.get("fdr_method")
        if fdr not in ALLOWED_FDR:
            r.add(Violation("R-PF-13","A",
                f"fdr_method must be one of {ALLOWED_FDR}, got: {fdr!r}"))
        else:
            r.pass_rule("R-PF-13","A", note=f"fdr_method={fdr}")

        # R-PF-14: seed
        seed = manifest.get("seed")
        if not isinstance(seed, int):
            r.add(Violation("R-PF-14","A",
                f"seed must be integer, got: {seed!r}"))
        else:
            r.pass_rule("R-PF-14","A", note=f"seed={seed}")

        # P19: R-PF-20 — null model invariants declared in manifest
        # Spec §8: one defined null-model procedure with declared invariants is mandatory.
        null_invariants = manifest.get("null_model_invariants")
        if null_invariants is None:
            r.add(Violation("R-PF-20","B",
                "null_model_invariants not declared in manifest — "
                "null procedure cannot be independently verified",
                "Add 'null_model_invariants' array to manifest listing preserved invariants"))
        elif not isinstance(null_invariants, list) or len(null_invariants) == 0:
            r.add(Violation("R-PF-20","B",
                "null_model_invariants declared but empty — "
                "must list at least one preserved invariant"))
        else:
            r.pass_rule("R-PF-20","A",
                note=f"{len(null_invariants)} null model invariant(s) declared")

        # P08: input availability with explicit semantics
        # R-PF-15: inputs
        inputs = manifest.get("inputs", {})
        requires_local = not pr["allows_missing_local_inputs"]
        if not inputs:
            r.add(Violation("R-PF-15","A",
                "No inputs declared — provenance unverifiable"))
        else:
            for inp_name, meta in inputs.items():
                sha = meta.get("sha256","")
                if len(sha) != 64 or not all(c in "0123456789abcdef" for c in sha):
                    r.add(Violation("R-PF-15","A",
                        f"Input '{inp_name}' sha256 is not valid 64-char hex",
                        f"Got: {sha!r}"))
                    continue
                inp_path = pathlib.Path(meta.get("path", inp_name))
                if inp_path.exists():
                    actual = self._sha256(inp_path)
                    if actual != sha:
                        r.add(Violation("R-PF-15","A",
                            f"Input '{inp_name}' hash mismatch",
                            f"Declared: {sha[:16]}... Actual: {actual[:16]}..."))
                    else:
                        r.pass_rule("R-PF-15","A",
                            [str(inp_path)], f"Input '{inp_name}' hash verified")
                elif requires_local:
                    r.add(Violation("R-PF-15","A",
                        f"Input '{inp_name}' not found — required for profile='{profile_mode}'",
                        f"Path: {meta.get('path','<undeclared>')}. "
                        "Declare input_mode='remote' in manifest to allow missing local files."))
                else:
                    r.pass_rule("R-PF-15","B",
                        note=f"Input '{inp_name}' not locally present — allowed for profile='{profile_mode}'")

        # R-PF-16: transformation_operators — Class A
        ops = manifest.get("transformation_operators", [])
        if not ops:
            r.add(Violation("R-PF-16","A",
                "No transformation operators declared",
                "No shadow implementation: undeclared operators forbidden (v1.4 R5)"))
        else:
            for op in ops:
                if op.get("type") not in ALLOWED_OP_TYPES:
                    r.add(Violation("R-PF-16","A",
                        f"Operator {op.get('id','?')}: unknown type {op.get('type')!r}"))
                if "effect_class" not in op:
                    r.add(Violation("R-PF-16","B",
                        f"Operator {op.get('id','?')}: missing effect_class"))
                if "lossless" not in op:
                    r.add(Violation("R-PF-16","B",
                        f"Operator {op.get('id','?')}: missing lossless declaration"))
            if all(op.get("type") in ALLOWED_OP_TYPES for op in ops):
                r.pass_rule("R-PF-16","A", note=f"{len(ops)} operators declared and typed")

        # P05: optional artefacts constrained by profile
        # R-PF-17
        optional_out  = set(manifest.get("optional_artefacts", []))
        blocked       = pr["optional_artefacts_blocked"]
        bad_opt       = optional_out & blocked
        if bad_opt:
            r.add(Violation("R-PF-17","A",
                f"Artefacts {bad_opt} cannot be optional for profile='{profile_mode}'",
                "Optional artefact loophole blocked (v1.4 downgrade prevention)"))
        else:
            r.pass_rule("R-PF-17","A", note="optional_artefacts within profile scope")

        # P04: required_artefacts in manifest must not contradict mandatory baseline
        # R-PF-18
        manifest_required = manifest.get("required_artefacts", [])
        if manifest_required:
            mandatory_set = set(REQUIRED_ARTEFACTS_ALWAYS)
            missing_mandatory = mandatory_set - set(manifest_required)
            if missing_mandatory:
                r.add(Violation("R-PF-18","A",
                    f"manifest required_artefacts omits mandatory baseline: {missing_mandatory}",
                    "required_artefacts must be a superset of the mandatory baseline"))
            else:
                r.pass_rule("R-PF-18","A",
                    note=f"manifest required_artefacts includes all {len(manifest_required)} baseline artefacts")

        # R-PF-19: run_dir exists
        if not self.run_dir.exists():
            r.add(Violation("R-PF-19","A",
                f"Run directory does not exist: {self.run_dir}"))
        else:
            r.pass_rule("R-PF-19","A", note="Run directory exists")

        # P27: R-PF-21 — schema contract self-binding and drift detection
        # Recomputes SHA-256 of ARTEFACT_SCHEMAS canonical serialisation and compares
        # against frozen SCHEMA_AUTHORITY_HASH. Class A on all profiles.
        # Assurance boundary: detects accidental/partial schema drift only.
        # Does not detect coordinated whole-file replacement (covered by R-PF-07).
        try:
            computed_schema_hash = self._compute_schema_hash()
            if computed_schema_hash != SCHEMA_AUTHORITY_HASH:
                r.add(Violation("R-PF-21","A",
                    "Schema contract drift detected: ARTEFACT_SCHEMAS does not match "
                    "the frozen SCHEMA_AUTHORITY_HASH for this validator version",
                    f"Expected: {SCHEMA_AUTHORITY_HASH[:16]}... "
                    f"Computed: {computed_schema_hash[:16]}... "
                    "The inline schema contract has drifted from its declared state. "
                    "Update SCHEMA_AUTHORITY_HASH after an authorised schema change."))
            else:
                r.pass_rule("R-PF-21","A",
                    note=f"Schema contract verified: ARTEFACT_SCHEMAS matches "
                         f"SCHEMA_AUTHORITY_HASH ({computed_schema_hash[:16]}...)")
        except ValueError as e:
            r.add(Violation("R-PF-21","A",
                "Schema contract hash computation failed — unsupported type in "
                "ARTEFACT_SCHEMAS; cannot verify schema integrity",
                str(e)))

        self._finalise_preflight(r)
        return r

    def _finalise_preflight(self, r: ValidationResult):
        self._preflight_result = r
        self._preflight_done   = True
        self._preflight_passed = (r.status != "FAIL")

    # ── PHASE 2: POST_RUN ─────────────────────────────────────────────────────
    def post_run(self) -> ValidationResult:
        r = ValidationResult(phase="POST_RUN")

        # P07: hash at post_run
        self._validator_hash_at_postrun = self._sha256(pathlib.Path(__file__))

        # P01: gate on call order AND Class A outcome
        if not self._preflight_done:
            r.add(Violation("R-GATE-01","A",
                "post_run() called before preflight() — execution gate violated"))
            self._postrun_result = r
            return r
        if not self._preflight_passed:
            r.add(Violation("R-GATE-02","A",
                "post_run() blocked: preflight has unresolved Class A violations",
                "All Class A preflight violations must be resolved first"))
            self._postrun_result = r
            return r
        r.pass_rule("R-GATE-01","A", note="Preflight gate passed (call order + Class A)")

        # P07: validator unchanged across full cycle
        # R-PR-00
        if (self._validator_hash_at_postrun not in ("FILE_MISSING", None)
                and self._validator_hash_at_postrun != self._validator_hash_at_init):
            r.add(Violation("R-PR-00","A",
                "Validator changed during evaluation cycle",
                f"Init: {self._validator_hash_at_init[:16]}... "
                f"Post-run: {self._validator_hash_at_postrun[:16]}..."))
        elif (self._validator_hash_at_postrun
              and self._validator_hash_at_preflight
              and self._validator_hash_at_postrun != self._validator_hash_at_preflight):
            r.add(Violation("R-PR-00","A",
                "Validator changed between preflight and post-run",
                f"Preflight: {self._validator_hash_at_preflight[:16]}... "
                f"Post-run: {self._validator_hash_at_postrun[:16]}..."))
        else:
            r.pass_rule("R-PR-00","A",
                note="Validator hash unchanged: init ↔ preflight ↔ post-run")

        required = self._required_artefacts()
        pr = self._profile()

        # P22: R-RT-01 — runtime completion proof (strengthened from P21)
        # Manifest profile is authoritative. RUN_REPORT.json must not weaken obligations.
        run_report_path = self._art("RUN_REPORT.json")
        if not run_report_path.exists():
            r.add(Violation("R-RT-01","A",
                "RUN_REPORT.json absent — primary execution pipeline did not reach completion",
                "Run is not evaluable. Restart required."))
            self._postrun_result = r
            return r

        run_report_early, rr_err = self._load_json(run_report_path)
        if rr_err or run_report_early is None:
            r.add(Violation("R-RT-01","A",
                "RUN_REPORT.json present but unparseable — completion cannot be verified",
                rr_err or "Unknown parse error"))
            self._postrun_result = r
            return r

        # Tightening 1: manifest profile is authoritative; mismatch in run report = FAIL
        profile_key = self.manifest.get("profile_mode", "standard")
        rr_profile  = run_report_early.get("profile_mode")
        if rr_profile is not None and rr_profile != profile_key:
            r.add(Violation("R-RT-01","A",
                f"Profile mismatch: manifest declares '{profile_key}' but "
                f"RUN_REPORT.json declares '{rr_profile}'",
                "Manifest is authoritative. Runner must not self-report a different profile."))
            self._postrun_result = r
            return r

        # Tightening 2: stages_completed semantic validation
        stages = run_report_early.get("stages_completed")
        stages_invalid = (
            not isinstance(stages, list)
            or len(stages) == 0
            or any((not isinstance(s, str) or not s.strip()) for s in stages)
            or len(set(stages)) != len(stages)
        )
        if stages_invalid:
            r.add(Violation("R-RT-01","A",
                "stages_completed is absent, empty, contains non-string/blank entries, "
                "or contains duplicates — completion declaration is invalid",
                "Runner must emit stages_completed as a non-empty list of unique, "
                "non-empty strings identifying every stage that executed"))
        else:
            # Cross-check: mandatory stage artefacts for this profile must all exist
            mandatory = MANDATORY_STAGE_ARTEFACTS.get(
                profile_key, MANDATORY_STAGE_ARTEFACTS["standard"])
            missing_stage_arts = [a for a in mandatory if not self._art(a).exists()]
            if missing_stage_arts:
                r.add(Violation("R-RT-01","A",
                    f"stages_completed declared but mandatory stage artefacts missing: "
                    f"{missing_stage_arts}",
                    "Declared completion is inconsistent with artefact evidence"))
            else:
                # Tightening 3: file-size check is preliminary evidence only —
                # parseability and schema validation provide the heavier proof later.
                empty_arts = [a for a in mandatory
                              if self._art(a).exists() and self._art(a).stat().st_size == 0]
                if empty_arts:
                    r.add(Violation("R-RT-01","A",
                        f"Preliminary artefact-presence check: stage artefacts are "
                        f"zero-byte and cannot constitute stage evidence: {empty_arts}",
                        "Non-zero size is a necessary but not sufficient condition. "
                        "Schema validation below will enforce semantic completeness."))
                else:
                    r.pass_rule("R-RT-01","A",
                        mandatory,
                        f"Completion consistency confirmed: {len(stages)} stage(s) declared "
                        f"by runner, all {len(mandatory)} mandatory artefacts present and "
                        f"non-zero (preliminary size check only). "
                        f"Note: this proves declared-stage/artefact consistency, not that "
                        f"those stages actually executed — a runner could declare stages "
                        f"without running them. Schema validation below provides the next "
                        f"layer of semantic enforcement.")

        # R-PR-01: artefacts exist
        missing_arts = []
        for art in required:
            if not self._art(art).exists():
                r.add(Violation("R-PR-01","A",
                    f"Required artefact missing: {art}",
                    "Incomplete run = FAIL (v1.4 §4.1)"),
                    artefacts=[art])
                missing_arts.append(art)
            else:
                r.pass_rule("R-PR-01","A", [art], f"Artefact present: {art}")

        # P06: load and schema-validate all present artefacts
        # P23-fix-2: track schema validity per artefact to gate downstream comparisons
        loaded: Dict[str, Any] = {}
        schema_valid: Dict[str, bool] = {}   # P23-fix-2: per-artefact schema validity
        for art_name in ARTEFACT_SCHEMAS:
            path = self._art(art_name)
            if path.exists():
                data, err = self._load_json(path)
                if err:
                    r.add(Violation("R-PR-SCHEMA","A",
                        f"{art_name} present but cannot be parsed: {err}"),
                        artefacts=[art_name])
                    schema_valid[art_name] = False
                else:
                    loaded[art_name] = data
                    ok = self._validate_artefact_schema(art_name, data, r)
                    schema_valid[art_name] = ok
                    if ok:
                        r.pass_rule("R-PR-SCHEMA","A",
                            [art_name], f"{art_name} schema validated")

        run_report = loaded.get("RUN_REPORT.json")
        null_m     = loaded.get("NULL_METRICS.json")
        obs        = loaded.get("OBSERVED_METRICS.json")
        stats      = loaded.get("STATISTICS.json")
        comp       = loaded.get("COMPARISON.json")
        fs         = loaded.get("FAILURE_SUMMARY.json")
        lock       = loaded.get("EXECUTION_BOUNDARY.lock.json")

        # P09: contradiction checks — all 8 pairs
        # R-PR-02: manifest vs run_report versions (evidence supremacy)
        if run_report:
            for vf, exp in [
                ("validation_authority_version", VALIDATION_AUTHORITY_VERSION),
                ("execution_standard_version",   EXECUTION_STANDARD_VERSION),
            ]:
                rv = run_report.get(vf)
                if rv and rv != exp:
                    r.add(Violation("R-PR-02","A",
                        f"Contradiction: RUN_REPORT {vf}={rv!r} != expected {exp!r}",
                        "Evidence supremacy: runtime authority versions are authoritative"))
                elif rv:
                    r.pass_rule("R-PR-02","A",
                        ["RUN_REPORT.json"], f"{vf} consistent")

        # R-PR-03: run_report status validity + status/failure consistency
        if run_report:
            status = run_report.get("status","")
            # P16: ERROR must be special-cased before generic invalid-status check
            if status == EXECUTION_ERROR_STATE:
                r.add(Violation("R-PR-03","A",
                    "RUN_REPORT status=ERROR — execution did not complete to an evaluable state",
                    "ERROR is not a valid classification. Run must be restarted clean."))
                r.status = EXECUTION_ERROR_STATE   # Tier 2 fix: propagate ERROR to phase status
                self._postrun_result = r
                return r
            elif status not in VALID_STATUSES:
                r.add(Violation("R-PR-03","A",
                    f"RUN_REPORT status invalid: {status!r}",
                    f"Must be one of {VALID_STATUSES}"))
            else:
                r.pass_rule("R-PR-03","A", ["RUN_REPORT.json"], f"status={status}")

        # R-PR-04: PASS with Class A failures — contradiction
        if run_report and fs:
            status    = run_report.get("status","")
            class_a_f = fs.get("class_a_failures", [])
            if status == "PASS" and class_a_f:
                r.add(Violation("R-PR-04","A",
                    "Contradiction: status=PASS but FAILURE_SUMMARY has Class A failures",
                    str(class_a_f)))
            else:
                r.pass_rule("R-PR-04","A",
                    ["RUN_REPORT.json","FAILURE_SUMMARY.json"],
                    "Status/failure summary consistent")

        # R-PR-05: null_samples manifest vs runtime
        if null_m:
            actual_ns   = null_m.get("n_samples", 0)
            declared_ns = self.manifest.get("null_samples", 0)
            if actual_ns < declared_ns:
                r.add(Violation("R-PR-05","A",
                    f"Null samples silently downgraded: declared={declared_ns} actual={actual_ns}",
                    "v1.4 §4.3 R4"))
            else:
                r.pass_rule("R-PR-05","A", ["NULL_METRICS.json"],
                            f"null_samples consistent: {actual_ns} >= {declared_ns}")

        # R-PR-06: seed + alpha manifest vs runtime
        if obs:
            seed_used  = obs.get("seed_used")
            alpha_used = obs.get("alpha_used")
            m_seed     = self.manifest.get("seed")
            m_alpha    = self.manifest.get("alpha")
            if seed_used is not None and seed_used != m_seed:
                r.add(Violation("R-PR-06","A",
                    f"Seed contradiction: manifest={m_seed} runtime={seed_used}"))
            elif seed_used is not None:
                r.pass_rule("R-PR-06","A",["OBSERVED_METRICS.json"], "seed consistent")
            if alpha_used is not None and m_alpha is not None:
                if abs(float(alpha_used) - float(m_alpha)) > 1e-15:
                    r.add(Violation("R-PR-06","A",
                        f"Alpha contradiction: manifest={m_alpha} runtime={alpha_used}"))
                else:
                    r.pass_rule("R-PR-06","A",["OBSERVED_METRICS.json"], "alpha consistent")
            if seed_used is None or alpha_used is None:
                r.add(Violation("R-PR-06","B",
                    "OBSERVED_METRICS missing seed_used or alpha_used — "
                    "runtime/manifest consistency unverifiable"))

        # P26: R-PR-07 — comparison-method validation (extended)
        # Source authority hierarchy (declared for all E1-E8 checks):
        #   manifest        = authoritative for configuration (kappa_L, fdr_method, alpha)
        #   COMPARISON.json = authoritative for verdict claims
        #   STATISTICS.json = authoritative for computed statistics
        #   OBSERVED_METRICS.json = authoritative for raw observed metrics
        # Cross-source conflict = Class A. Non-authoritative source attempting to override = Class A.
        # NON-GOALS: this block does not re-execute the statistical test, verify BH/FDR
        # correctness, validate permutation procedure, or verify sample independence.
        # It enforces declared-parameter consistency and output completeness only.
        if run_report and comp:
            rr_status = run_report.get("status","")
            verdict   = comp.get("verdict","")
            kappa_rt  = comp.get("kappa_L")
            kappa_mn  = self.manifest.get("kappa_L")

            # E1: verdict validity — ERROR gate before VALID_STATUSES check
            if verdict == EXECUTION_ERROR_STATE:
                r.add(Violation("R-PR-07","A",
                    "COMPARISON.json verdict=ERROR — comparison result is not evaluable",
                    "ERROR is not a valid verdict. Run must be restarted clean."))
            elif verdict not in VALID_STATUSES:
                r.add(Violation("R-PR-07","A",
                    f"COMPARISON.json verdict invalid: {verdict!r}",
                    f"Must be one of {VALID_STATUSES}"))
            else:
                r.pass_rule("R-PR-07","A",
                    ["COMPARISON.json"], f"verdict valid: {verdict!r}")

            # Existing: status/verdict cross-consistency
            if rr_status == "PASS" and verdict != "PASS":
                r.add(Violation("R-PR-07","A",
                    f"Contradiction: RUN_REPORT status=PASS but COMPARISON verdict={verdict!r}"))
            elif rr_status == "FAIL" and verdict == "PASS":
                r.add(Violation("R-PR-07","A",
                    "Contradiction: status=FAIL but verdict=PASS"))
            else:
                r.pass_rule("R-PR-07","A",
                    ["RUN_REPORT.json","COMPARISON.json"], "status/verdict consistent")

            # Existing: kappa_L consistency
            if kappa_rt is not None and kappa_mn is not None and kappa_rt != kappa_mn:
                r.add(Violation("R-PR-07","A",
                    f"kappa_L contradiction: comparison={kappa_rt} manifest={kappa_mn}",
                    "Evidence supremacy: all kappa_L instances must agree"))
            elif kappa_rt is not None:
                r.pass_rule("R-PR-07","A",
                    ["COMPARISON.json"], f"kappa_L consistent: {kappa_rt}")

            # E2: pass_condition non-empty and non-whitespace
            pass_cond = comp.get("pass_condition","")
            pc_class  = "A" if profile_key in ("final","hostile_audit") else "B"
            if not isinstance(pass_cond, str) or not pass_cond.strip():
                r.add(Violation("R-PR-07", pc_class,
                    "COMPARISON.json pass_condition is absent or blank",
                    f"pass_condition must be a non-empty, non-whitespace string. "
                    f"{'Class A under this profile.' if pc_class == 'A' else 'Class B under this profile.'}"))
            else:
                r.pass_rule("R-PR-07","A",
                    ["COMPARISON.json"],
                    f"pass_condition present and non-blank: {pass_cond[:40]!r}")

            # E3: theta_observed consistency with OBSERVED_METRICS.theta
            # Manifest is authoritative for config; OBSERVED_METRICS is authoritative
            # for raw observed value; COMPARISON must agree with both.
            # Use tolerance to avoid false failures from float representation.
            THETA_TOL = 1e-9
            if comp and obs:
                theta_comp = comp.get("theta_observed")
                theta_obs  = obs.get("theta")
                if theta_comp is not None and theta_obs is not None:
                    if not isinstance(theta_comp, (int,float)) or not isinstance(theta_obs, (int,float)):
                        r.add(Violation("R-PR-07","A",
                            "theta_observed or theta is non-numeric — consistency check failed",
                            f"COMPARISON theta_observed={theta_comp!r}, "
                            f"OBSERVED_METRICS theta={theta_obs!r}"))
                    elif abs(float(theta_comp) - float(theta_obs)) > THETA_TOL:
                        r.add(Violation("R-PR-07","A",
                            f"theta_observed mismatch: COMPARISON declares {theta_comp}, "
                            f"OBSERVED_METRICS declares {theta_obs} "
                            f"(tolerance={THETA_TOL})",
                            "Cross-source conflict: COMPARISON.theta_observed must equal "
                            "OBSERVED_METRICS.theta within tolerance. "
                            "OBSERVED_METRICS is authoritative for raw observed value."))
                    else:
                        r.pass_rule("R-PR-07","A",
                            ["COMPARISON.json","OBSERVED_METRICS.json"],
                            f"theta_observed consistent: {theta_comp} "
                            f"(tolerance={THETA_TOL})")
                elif theta_comp is None and obs:
                    r.add(Violation("R-PR-07","B",
                        "COMPARISON.json missing theta_observed — "
                        "consistency with OBSERVED_METRICS cannot be verified"))

            # E4: fdr_method consistency
            # Manifest is authoritative for declared method.
            # STATISTICS.json must declare the applied method and it must match.
            manifest_fdr = self.manifest.get("fdr_method","")
            stats_fdr    = stats.get("fdr_method") if stats else None
            if stats_fdr is not None:
                # Field present — validate it
                if stats_fdr not in ALLOWED_FDR:
                    r.add(Violation("R-PR-07","A",
                        f"STATISTICS.json fdr_method={stats_fdr!r} is not in ALLOWED_FDR",
                        f"Allowed values: {ALLOWED_FDR}. "
                        "Runner must not invent method names."))
                elif stats_fdr != manifest_fdr:
                    r.add(Violation("R-PR-07","A",
                        f"fdr_method mismatch: manifest declares {manifest_fdr!r} "
                        f"but STATISTICS.json declares {stats_fdr!r}",
                        "Manifest is authoritative for declared method. "
                        "Cross-source conflict = Class A."))
                else:
                    r.pass_rule("R-PR-07","A",
                        ["STATISTICS.json"],
                        f"fdr_method consistent: manifest and STATISTICS agree ({stats_fdr!r})")
            else:
                # Field absent — severity depends on profile
                fdr_abs_class = "A" if profile_key in ("final","hostile_audit") else "B"
                r.add(Violation("R-PR-07", fdr_abs_class,
                    "STATISTICS.json does not declare fdr_method — "
                    "applied statistical method cannot be verified against manifest declaration",
                    f"Manifest declares fdr_method={manifest_fdr!r}. "
                    f"{'Class A: at this profile level, unverifiable method is a blocking failure.' if fdr_abs_class == 'A' else 'Class B: method traceability incomplete.'}"))

            # E8: kappa_L threshold internal consistency
            # Manifest is authoritative for kappa_L.
            # PARTIAL verdict is explicitly skipped — semantics not contractually defined.
            # Use same tolerance as E3.
            if verdict in ("PASS","FAIL"):
                if kappa_mn is None:
                    r.add(Violation("R-PR-07","A",
                        "kappa_L not declared in manifest — threshold consistency "
                        "check cannot be performed",
                        "Manifest is authoritative for kappa_L. "
                        "Without it, verdict/threshold consistency is unverifiable."))
                else:
                    theta_for_e8 = comp.get("theta_observed")
                    if theta_for_e8 is None:
                        r.add(Violation("R-PR-07","B",
                            "COMPARISON.json missing theta_observed — "
                            "kappa_L threshold consistency check skipped"))
                    elif not isinstance(theta_for_e8, (int,float)):
                        r.add(Violation("R-PR-07","A",
                            f"COMPARISON.json theta_observed is non-numeric: "
                            f"{theta_for_e8!r}"))
                    else:
                        kl = float(kappa_mn)
                        th = float(theta_for_e8)
                        if verdict == "PASS" and th < kl - THETA_TOL:
                            r.add(Violation("R-PR-07","A",
                                f"Threshold contradiction: verdict=PASS but "
                                f"theta_observed={th} < kappa_L={kl} (tolerance={THETA_TOL})",
                                "A PASS verdict requires theta_observed >= kappa_L. "
                                "Manifest kappa_L is authoritative."))
                        elif verdict == "FAIL" and th >= kl - THETA_TOL:
                            r.add(Violation("R-PR-07","A",
                                f"Threshold contradiction: verdict=FAIL but "
                                f"theta_observed={th} >= kappa_L={kl} (tolerance={THETA_TOL})",
                                "A FAIL verdict requires theta_observed < kappa_L. "
                                "Manifest kappa_L is authoritative."))
                        else:
                            r.pass_rule("R-PR-07","A",
                                ["COMPARISON.json"],
                                f"Threshold consistent: verdict={verdict!r}, "
                                f"theta_observed={th}, kappa_L={kl} "
                                f"(tolerance={THETA_TOL})")
            else:
                # PARTIAL — explicitly skipped per locked policy
                r.pass_rule("R-PR-07","B",
                    ["COMPARISON.json"],
                    "E8 threshold check skipped for verdict=PARTIAL — "
                    "PARTIAL semantics relative to kappa_L are not contractually defined")

        # P26: R-PR-08 — statistical output completeness and internal consistency (extended)
        # NON-GOALS: does not verify BH/FDR correctness, permutation procedure,
        # or sample independence. Enforces output completeness, field presence, range
        # validity, and internal plausibility only.
        if stats:
            # E9: p_value presence (new — previously only range was checked if present)
            p = stats.get("p_value")
            p_abs_class = "A" if profile_key in ("final","hostile_audit") else "B"
            if p is None:
                r.add(Violation("R-PR-08", p_abs_class,
                    "STATISTICS.json missing p_value — statistical result is incomplete",
                    f"{'Class A: p_value is mandatory at this profile level.' if p_abs_class == 'A' else 'Class B: p_value missing.'}"))
            elif not isinstance(p, (int,float)):
                r.add(Violation("R-PR-08","A",
                    f"p_value is non-numeric: {p!r}"))
            elif not (0.0 <= float(p) <= 1.0):
                r.add(Violation("R-PR-08","A",
                    f"p_value={p} out of [0,1]"))
            else:
                r.pass_rule("R-PR-08","A", ["STATISTICS.json"],
                    f"p_value present and in [0,1]: {p}")

            # E5: fdr_corrected range
            fdr_c = stats.get("fdr_corrected")
            if fdr_c is None:
                fdr_c_class = "A" if profile_key in ("final","hostile_audit") else "B"
                r.add(Violation("R-PR-08", fdr_c_class,
                    "STATISTICS.json missing fdr_corrected",
                    f"{'Class A at this profile level.' if fdr_c_class == 'A' else 'Class B.'}"))
            elif not isinstance(fdr_c, (int,float)):
                r.add(Violation("R-PR-08","A",
                    f"fdr_corrected is non-numeric: {fdr_c!r}"))
            elif not (0.0 <= float(fdr_c) <= 1.0):
                r.add(Violation("R-PR-08","A",
                    f"fdr_corrected={fdr_c} out of [0,1]"))
            else:
                r.pass_rule("R-PR-08","A", ["STATISTICS.json"],
                    f"fdr_corrected present and in [0,1]: {fdr_c}")

            # E6: fdr_corrected plausibility check
            # Class B only — never Class A. Plausibility, not mathematical proof.
            # Guard: both fields must be present and numeric.
            # Only applies to BH and bonferroni methods.
            # fdr_method taken from manifest (authoritative); absent = skip check.
            manifest_fdr_e6 = self.manifest.get("fdr_method","")
            if (manifest_fdr_e6 in ("BH","bonferroni")
                    and p is not None and isinstance(p,(int,float))
                    and fdr_c is not None and isinstance(fdr_c,(int,float))):
                if float(fdr_c) < float(p):
                    r.add(Violation("R-PR-08","B",
                        f"fdr_corrected={fdr_c} < p_value={p} — "
                        f"implausible for fdr_method={manifest_fdr_e6!r}",
                        f"For {manifest_fdr_e6}, FDR-corrected value should be >= raw p_value. "
                        "Class B: plausibility check only, not method correctness proof."))
                else:
                    r.pass_rule("R-PR-08","B", ["STATISTICS.json"],
                        f"fdr_corrected plausibility passed: "
                        f"fdr_corrected={fdr_c} >= p_value={p} "
                        f"for method={manifest_fdr_e6!r}")

            # E7: z_score and effect_size profile-sensitive presence
            # hostile_audit + final = Class A; lower profiles = Class B
            e7_class = "A" if profile_key in ("final","hostile_audit") else "B"
            for field_name in ("z_score","effect_size"):
                val = stats.get(field_name)
                if val is None:
                    r.add(Violation("R-PR-08", e7_class,
                        f"STATISTICS.json missing {field_name}",
                        f"{'Class A: required for complete statistical output at this profile.' if e7_class == 'A' else 'Class B: recommended for complete statistical output.'}"))
                elif not isinstance(val, (int,float)):
                    r.add(Violation("R-PR-08","A",
                        f"{field_name} is non-numeric: {val!r}"))
                else:
                    r.pass_rule("R-PR-08", e7_class, ["STATISTICS.json"],
                        f"{field_name} present: {val}")

        # P15: boundary lock — all required entries enforced
        # R-PR-09
        if lock:
            # Required entries in boundary
            required_lock_fields = {
                "run_id","sealed_at","artefact_hashes","environment",
                "validator_hash","manifest_hash"
            }
            if self.authority_path:
                required_lock_fields.add("authority_hash")
            for lf in required_lock_fields:
                if lf not in lock:
                    r.add(Violation("R-PR-09","A",
                        f"EXECUTION_BOUNDARY.lock.json missing required field: '{lf}'"))
            # Verify artefact hashes
            for art_name, declared_hash in lock.get("artefact_hashes", {}).items():
                actual = self._sha256(self._art(art_name))
                if actual == "FILE_MISSING":
                    r.add(Violation("R-PR-09","A",
                        f"Locked artefact missing post-seal: {art_name}"))
                elif actual != declared_hash:
                    r.add(Violation("R-PR-09","A",
                        f"Artefact hash mismatch post-seal: {art_name}",
                        f"Boundary: {declared_hash[:16]}... Actual: {actual[:16]}..."))
                else:
                    r.pass_rule("R-PR-09","A", [art_name], f"Hash verified: {art_name}")
            # P07: validator hash in boundary matches all three checkpoints
            locked_v = lock.get("validator_hash","")
            for label, stored_hash in [
                ("init",     self._validator_hash_at_init),
                ("preflight",self._validator_hash_at_preflight),
                ("post-run", self._validator_hash_at_postrun),
            ]:
                if stored_hash and stored_hash != "FILE_MISSING" and locked_v and locked_v != stored_hash:
                    r.add(Violation("R-PR-09","A",
                        f"Validator hash in boundary does not match {label} hash",
                        f"Boundary: {locked_v[:16]}... {label}: {stored_hash[:16]}..."))
                    break
            else:
                r.pass_rule("R-PR-09","A", note="Validator hash consistent: init/preflight/post-run/boundary")
            # Manifest hash
            locked_m = lock.get("manifest_hash","")
            actual_m = self._sha256(self.manifest_path)
            if locked_m and locked_m != actual_m:
                r.add(Violation("R-PR-09","A","Manifest hash mismatch in boundary",
                    f"Boundary: {locked_m[:16]}... Actual: {actual_m[:16]}..."))
            elif locked_m:
                r.pass_rule("R-PR-09","A", note="Manifest hash consistent in boundary")
            # P18: runner hash in boundary — Class B (validator cannot compute independently)
            locked_r = lock.get("runner_hash","")
            if not locked_r:
                r.add(Violation("R-PR-09","B",
                    "EXECUTION_BOUNDARY.lock.json missing runner_hash — "
                    "runner identity unverifiable",
                    "Add runner_hash (SHA-256 of execution runner file) to boundary lock"))
            else:
                r.pass_rule("R-PR-09","B",
                    note=f"Runner hash present in boundary: {locked_r[:16]}...")
            # Authority hash if supplied
            if self.authority_path:
                locked_a = lock.get("authority_hash","")
                actual_a = self._sha256(self.authority_path)
                if locked_a and locked_a != actual_a:
                    r.add(Violation("R-PR-09","A",
                        "Authority file hash mismatch in boundary",
                        f"Boundary: {locked_a[:16]}... Actual: {actual_a[:16]}..."))

        # R-PR-10: no shadow implementation
        if run_report and run_report.get("repair_performed"):
            declared_ops = {op["id"] for op in self.manifest.get("transformation_operators",[])}
            used_ops     = set(run_report.get("operators_used", []))
            undeclared   = used_ops - declared_ops
            if undeclared:
                r.add(Violation("R-PR-10","A",
                    f"Repair used undeclared operators: {undeclared}",
                    "No shadow implementation (v1.4 R5)"))
            else:
                r.pass_rule("R-PR-10","A", ["RUN_REPORT.json"], "All repair operators declared")

        # P14: profile-specific Class B tolerance
        # R-PR-11
        max_b = pr["max_class_b_allowed"]
        if max_b is not None:
            class_b_count = sum(1 for v in r.violations if v.cls == "B")
            # Also count preflight B violations
            pf_b = sum(1 for v in (self._preflight_result.violations if self._preflight_result else [])
                       if v.cls == "B")
            total_b = class_b_count + pf_b
            if total_b > max_b:
                r.add(Violation("R-PR-11","A",
                    f"Profile '{self.manifest.get('profile_mode')}' allows max {max_b} Class B "
                    f"violations, found {total_b}",
                    "hostile_audit profile tolerates zero Class B violations"))
            else:
                r.pass_rule("R-PR-11","A",
                    note=f"Class B count {total_b} within profile limit {max_b}")

        # P25/P25-fix: R-PR-12 — determinism comparison under current boundary architecture
        # What this block actually enforces (no more, no less):
        #   1. Rerun boundary exists, parses, and passes schema validation
        #   2. Validator identity gate checked FIRST — mismatch stops all comparison
        #   3. Both boundary hash declarations verified against current disk at shared paths
        #      NOTE: current architecture uses a single shared run_dir — both primary and
        #      rerun boundary hash declarations are checked against the same on-disk
        #      artefact materialisation at self.run_dir. This verifies internal consistency
        #      of each boundary's declared hashes against current disk state; it does NOT
        #      verify separate retained primary and rerun on-disk artefact directories,
        #      as no such separate directories exist in the current architecture.
        #   4. Boundary-defined stable sets (boundary keys minus DETERMINISM_EXCLUDED)
        #      must be identical between primary and rerun
        #   5. Stable artefact hashes must be equal across both boundaries
        #   6. Manifest hash must match across primary and rerun boundaries
        #   7. Manifest inputs verified against manifest declaration (disk-to-manifest only;
        #      no cross-run input evidence artefacts exist in current architecture)
        #   8. Rerun environment record presence checked per locked policy (not equality)
        # Rerun absent: final/hostile_audit = Class A; lower profiles = locked policy
        # Rerun present but incomplete/malformed at any step = Class A FAIL

        DETERMINISM_EXCLUDED = {"EXECUTION_BOUNDARY.lock.json", "RERUN_BOUNDARY.lock.json"}

        rerun_path     = self._art("RERUN_BOUNDARY.lock.json")
        requires_rerun = self._profile().get("requires_rerun_boundary", False)

        if not rerun_path.exists():
            # Rerun absent — profile-governed response (locked policy unchanged)
            det_class = "A" if requires_rerun else "B"
            r.add(Violation("R-PR-12", det_class,
                f"RERUN_BOUNDARY.lock.json absent — determinism cannot be independently "
                f"verified under profile='{profile_key}'. This records non-contradiction "
                f"evidence from a single run only, not determinism proof.",
                "Provide a sealed rerun boundary to achieve independent determinism proof. "
                f"{'This profile requires independent proof (Class A).' if requires_rerun else 'No rerun evidence available. Single-run non-contradiction recorded as Class B. This does not constitute determinism verification.'}"))
            if not requires_rerun:
                r.pass_rule("R-PR-12","B",
                    note=f"Tier B: single-run non-contradiction recorded for "
                         f"profile='{profile_key}'. This is NOT determinism verification. "
                         f"It is the absence of detected contradiction in one run. "
                         f"Class B is within profile tolerance at this level. "
                         f"Independent proof requires RERUN_BOUNDARY.lock.json.")

        else:
            # Rerun boundary present — every failure below is Class A (fix 6 scoped)
            # Any incomplete, malformed, or missing comparison component = Class A FAIL

            # Gate: primary boundary must be loaded and schema-valid
            if lock is None:
                r.add(Violation("R-PR-12","A",
                    "Primary EXECUTION_BOUNDARY.lock.json not loaded — "
                    "determinism comparison cannot proceed",
                    "Primary boundary must be present and valid. "
                    "Check R-PR-09 for primary boundary failures."))
            else:
                primary_boundary_schema_ok = schema_valid.get(
                    "EXECUTION_BOUNDARY.lock.json", False)
                if not primary_boundary_schema_ok:
                    r.add(Violation("R-PR-12","A",
                        "Primary EXECUTION_BOUNDARY.lock.json failed schema validation — "
                        "determinism comparison cannot proceed against invalid boundary",
                        "Fix primary boundary schema violations (see R-PR-SCHEMA above)."))
                else:
                    rerun_data, rerun_err = self._load_json(rerun_path)
                    if rerun_err or rerun_data is None:
                        r.add(Violation("R-PR-12","A",
                            "RERUN_BOUNDARY.lock.json present but unparseable — "
                            "determinism comparison is incomplete (fix 6: Class A)",
                            rerun_err or "Unknown parse error"))
                    else:
                        rerun_schema_ok = self._validate_artefact_schema(
                            "RERUN_BOUNDARY.lock.json", rerun_data, r)
                        if not rerun_schema_ok:
                            r.add(Violation("R-PR-12","A",
                                "RERUN_BOUNDARY.lock.json failed schema validation — "
                                "rerun boundary is inadmissible as determinism evidence "
                                "(fix 6: comparison incomplete = Class A)",
                                "Schema violations recorded above."))
                        else:
                            # ── FIX 5: Validator identity gate — checked FIRST ──────────
                            # Mismatch stops all further comparison immediately
                            pv_hash = lock.get("validator_hash","")
                            rv_hash = rerun_data.get("validator_hash","")
                            if not pv_hash or not rv_hash:
                                missing_side = (
                                    (["primary boundary"] if not pv_hash else []) +
                                    (["rerun boundary"]   if not rv_hash else []))
                                r.add(Violation("R-PR-12","A",
                                    f"Validator hash missing from "
                                    f"{' and '.join(missing_side)} — "
                                    f"measurement instrument identity cannot be verified "
                                    f"(comparison incomplete = Class A)",
                                    "Both boundaries must declare validator_hash."))
                            elif pv_hash != rv_hash:
                                r.add(Violation("R-PR-12","A",
                                    "Validator hash mismatch: rerun used a different "
                                    "validator than primary run — comparison stopped "
                                    "(fix 5: validator identity gate, Class A)",
                                    f"Primary: {pv_hash[:16]}... "
                                    f"Rerun: {rv_hash[:16]}... "
                                    "Same validator required for valid determinism comparison."))
                            else:
                                r.pass_rule("R-PR-12","A",
                                    note=f"Validator identity confirmed: "
                                         f"primary and rerun used same validator "
                                         f"({pv_hash[:16]}...)")

                                primary_hashes = lock.get("artefact_hashes", {})
                                rerun_hashes   = rerun_data.get("artefact_hashes", {})

                                # ── FIX 1: Independent hash recomputation — BOTH sides ───
                                # Recompute SHA256 from disk for every stable artefact in
                                # primary boundary AND rerun boundary before any comparison.
                                # Neither boundary's declared hashes are trusted without
                                # independent disk verification.
                                disk_failures = []
                                for art_name, declared in primary_hashes.items():
                                    if art_name in DETERMINISM_EXCLUDED:
                                        continue
                                    actual = self._sha256(self._art(art_name))
                                    if actual == "FILE_MISSING":
                                        disk_failures.append(
                                            f"primary/{art_name}: file missing on disk")
                                    elif actual != declared:
                                        disk_failures.append(
                                            f"primary/{art_name}: disk={actual[:16]}... "
                                            f"boundary={declared[:16]}...")
                                # Rerun side: recompute from same disk location
                                # (both runs must have produced identical files at same paths)
                                for art_name, declared in rerun_hashes.items():
                                    if art_name in DETERMINISM_EXCLUDED:
                                        continue
                                    actual = self._sha256(self._art(art_name))
                                    if actual == "FILE_MISSING":
                                        disk_failures.append(
                                            f"rerun/{art_name}: file missing on disk")
                                    elif actual != declared:
                                        disk_failures.append(
                                            f"rerun/{art_name}: disk={actual[:16]}... "
                                            f"boundary={declared[:16]}...")
                                if disk_failures:
                                    r.add(Violation("R-PR-12","A",
                                        f"Independent hash recomputation failed for "
                                        f"{len(disk_failures)} boundary entry/entries — "
                                        f"boundary-declared hashes do not match disk state",
                                        "; ".join(disk_failures)))
                                else:
                                    r.pass_rule("R-PR-12","A",
                                        note="Independent hash recomputation passed: "
                                             "all stable artefact hashes in both primary "
                                             "and rerun boundaries verified against disk")

                                    # ── FIX 4 (scoped): Stable set derivation ─────────
                                    # Use boundary-declared stable sets minus excluded files.
                                    # Require exact set equality before value comparison.
                                    # Do NOT substitute _required_artefacts() here —
                                    # that is a broader validator concept, not the
                                    # boundary-architecture stable comparison set.
                                    primary_stable = {
                                        k: v for k, v in primary_hashes.items()
                                        if k not in DETERMINISM_EXCLUDED}
                                    rerun_stable   = {
                                        k: v for k, v in rerun_hashes.items()
                                        if k not in DETERMINISM_EXCLUDED}
                                    primary_keys = set(primary_stable.keys())
                                    rerun_keys   = set(rerun_stable.keys())

                                    if primary_keys != rerun_keys:
                                        only_primary = primary_keys - rerun_keys
                                        only_rerun   = rerun_keys - primary_keys
                                        r.add(Violation("R-PR-12","A",
                                            "Determinism comparison invalid: primary and "
                                            "rerun boundary stable artefact sets differ",
                                            f"Only in primary: {sorted(only_primary) or 'none'}. "
                                            f"Only in rerun: {sorted(only_rerun) or 'none'}. "
                                            f"Excluded from comparison: "
                                            f"{sorted(DETERMINISM_EXCLUDED)}."))
                                    else:
                                        r.pass_rule("R-PR-12","A",
                                            note=f"Boundary stable artefact sets identical: "
                                                 f"{len(primary_keys)} artefact(s) in both "
                                                 f"boundaries (excluded: "
                                                 f"{sorted(DETERMINISM_EXCLUDED)})")

                                        # ── Manifest hash match ───────────────────────
                                        primary_mh = lock.get("manifest_hash","")
                                        rerun_mh   = rerun_data.get("manifest_hash","")
                                        if not primary_mh or not rerun_mh:
                                            r.add(Violation("R-PR-12","A",
                                                "manifest_hash missing from primary or "
                                                "rerun boundary — same execution contract "
                                                "cannot be verified "
                                                "(comparison incomplete = Class A)",
                                                "Both boundaries must declare manifest_hash."))
                                        elif primary_mh != rerun_mh:
                                            r.add(Violation("R-PR-12","A",
                                                "Determinism proof invalid: rerun executed "
                                                "under a different manifest than primary run",
                                                f"Primary: {primary_mh[:16]}... "
                                                f"Rerun: {rerun_mh[:16]}..."))
                                        else:
                                            r.pass_rule("R-PR-12","A",
                                                note="Manifest hash consistent across "
                                                     "primary and rerun boundaries")

                                            # ── Stable artefact hash comparison ──────
                                            mismatches = []
                                            for art in sorted(primary_keys):
                                                h1 = primary_stable[art]
                                                h2 = rerun_stable[art]
                                                if h1 != h2:
                                                    mismatches.append(
                                                        f"{art}: primary={h1[:16]}... "
                                                        f"rerun={h2[:16]}...")
                                            if mismatches:
                                                r.add(Violation("R-PR-12","A",
                                                    f"Determinism failure: "
                                                    f"{len(mismatches)} stable artefact "
                                                    f"hash mismatch(es)",
                                                    "; ".join(mismatches)))
                                            else:
                                                # ── FIX 2 (scoped): Input integrity ──
                                                # Recompute current disk inputs against
                                                # manifest declaration only.
                                                # This is single-point disk-to-manifest
                                                # verification — NOT cross-run input
                                                # comparison. No separate per-run input
                                                # evidence artefacts exist in this
                                                # architecture.
                                                inputs = self.manifest.get("inputs", {})
                                                input_failures = []
                                                for inp_name, meta in inputs.items():
                                                    declared = meta.get("sha256","")
                                                    inp_path = pathlib.Path(
                                                        meta.get("path", inp_name))
                                                    if not inp_path.exists():
                                                        input_failures.append(
                                                            f"{inp_name}: not found on disk")
                                                        continue
                                                    actual = self._sha256(inp_path)
                                                    if actual != declared:
                                                        input_failures.append(
                                                            f"{inp_name}: disk="
                                                            f"{actual[:16]}... "
                                                            f"manifest="
                                                            f"{declared[:16]}...")
                                                if input_failures:
                                                    r.add(Violation("R-PR-12","A",
                                                        f"Input integrity check failed: "
                                                        f"{len(input_failures)} input(s) "
                                                        f"do not match manifest declaration "
                                                        f"(disk-to-manifest verification)",
                                                        "; ".join(input_failures)))
                                                elif not inputs:
                                                    r.add(Violation("R-PR-12","B",
                                                        "No inputs declared in manifest — "
                                                        "input integrity check skipped",
                                                        "Declare inputs with sha256 hashes "
                                                        "in manifest for input verification."))
                                                else:
                                                    r.pass_rule("R-PR-12","A",
                                                        note=f"Input integrity confirmed: "
                                                             f"{len(inputs)} manifest input(s) "
                                                             f"recomputed from current disk "
                                                             f"and match manifest declaration "
                                                             f"(disk-to-manifest only; no "
                                                             f"cross-run input evidence "
                                                             f"artefacts in this architecture)")

                                                    # ── FIX 3 (scoped): Environment ──
                                                    # Reverted to locked policy: presence
                                                    # check only. Equality enforcement was
                                                    # not authorised in locked policy.
                                                    # Class B per original locked standard.
                                                    rerun_env = rerun_data.get("environment")
                                                    if not rerun_env or not isinstance(
                                                            rerun_env, dict):
                                                        env_class = (
                                                            "A" if profile_key ==
                                                            "hostile_audit" else "B")
                                                        r.add(Violation("R-PR-12", env_class,
                                                            "RERUN_BOUNDARY.lock.json "
                                                            "missing or empty environment "
                                                            "record — execution context "
                                                            "cannot be assessed",
                                                            f"{'hostile_audit: Class A.' if env_class == 'A' else 'Environment record recommended (Class B).'}"))
                                                    else:
                                                        r.pass_rule("R-PR-12","B",
                                                            ["RERUN_BOUNDARY.lock.json"],
                                                            "Rerun environment record present")
                                                        r.pass_rule("R-PR-12","A",
                                                            ["EXECUTION_BOUNDARY.lock.json",
                                                             "RERUN_BOUNDARY.lock.json"],
                                                            f"Determinism comparison passed "
                                                            f"under current boundary "
                                                            f"architecture: validator "
                                                            f"identity consistent, manifest "
                                                            f"hash consistent, "
                                                            f"{len(primary_keys)} boundary-"
                                                            f"defined stable artefact "
                                                            f"hash(es) equal across "
                                                            f"boundaries, boundary hash "
                                                            f"declarations verified against "
                                                            f"current disk (shared run_dir), "
                                                            f"inputs match manifest "
                                                            f"declaration. Excluded from "
                                                            f"comparison: "
                                                            f"{sorted(DETERMINISM_EXCLUDED)}.")

        # Tier 2 fix: PARTIAL is reachable — a completed run with Class B but no Class A
        # violations is PARTIAL, not PASS. This makes the aggregate PARTIAL path live.
        if r.status == "PASS" and any(v.cls == "B" for v in r.violations):
            r.status = "PARTIAL"

        self._postrun_result = r
        return r

    # ── REPORT EMISSION (P10, P13) ─────────────────────────────────────────────
    def emit_report(self, output_path: Optional[str] = None) -> dict:
        def ser(res: Optional[ValidationResult]):
            if not res:
                return None
            class_b_count = sum(1 for v in res.violations if v.cls == "B")
            return {
                "phase":            res.phase,
                "status":           res.status,
                "timestamp":        res.timestamp,
                "total_violations": len(res.violations),
                "class_a":          sum(1 for v in res.violations if v.cls == "A"),
                "class_b":          class_b_count,
                "class_c":          sum(1 for v in res.violations if v.cls == "C"),
                "violations":       [asdict(v) for v in res.violations],
                "rule_trace":       [asdict(t) for t in res.traces],
            }

        statuses = [res.status for res in [self._preflight_result, self._postrun_result] if res]
        # P16: ERROR is special-cased before FAIL — it is not a classification, it is an execution failure
        if EXECUTION_ERROR_STATE in statuses:
            overall = EXECUTION_ERROR_STATE
        elif "FAIL" in statuses:
            overall = "FAIL"
        elif "PARTIAL" in statuses:
            overall = "PARTIAL"
        else:
            overall = "PASS"
        pr       = self._profile()

        # P13: explicit sign-off logic
        total_a = sum(sum(1 for v in res.violations if v.cls == "A")
                      for res in [self._preflight_result, self._postrun_result] if res)
        total_b = sum(sum(1 for v in res.violations if v.cls == "B")
                      for res in [self._preflight_result, self._postrun_result] if res)
        profile_mode = self.manifest.get("profile_mode","")

        # P07: final validator hash at emit
        validator_hash_at_emit = self._sha256(pathlib.Path(__file__))
        hash_consistent = (
            validator_hash_at_emit == self._validator_hash_at_init
            == self._validator_hash_at_preflight
        )

        # P26-fix Blocker 3 (Option B — wording only, no logic change):
        # audit_grade_ready is profile-agnostic: any profile reaching PASS with zero
        # Class A violations satisfies it. It is NOT restricted to final/hostile_audit.
        # hostile_audit_ready IS profile-gated (requires hostile_audit profile explicitly).
        # The sign-off block contains profile-governed logic (hostile_audit_ready,
        # correct_profile) but audit_grade_ready itself is profile-agnostic by design.
        audit_grade_ready = (
            overall == "PASS"
            and total_a == 0
        )
        hostile_audit_ready = (
            overall == "PASS"
            and total_a == 0
            and total_b == 0
            and profile_mode == "hostile_audit"
            and hash_consistent
        )

        report = {
            "scar_validator_version":        VALIDATOR_VERSION,
            "manifest_schema_version":       MANIFEST_SCHEMA_VERSION,
            "validation_authority_version":  VALIDATION_AUTHORITY_VERSION,
            "execution_standard_version":    EXECUTION_STANDARD_VERSION,
            "validator_hash_at_init":        self._validator_hash_at_init,
            "validator_hash_at_preflight":   self._validator_hash_at_preflight,
            "validator_hash_at_postrun":     self._validator_hash_at_postrun,
            "validator_hash_at_emit":        validator_hash_at_emit,
            "validator_hash_consistent":     hash_consistent,
            "generated_at":                  datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "overall_status":                overall,
            "preflight":                     ser(self._preflight_result),
            "post_run":                      ser(self._postrun_result),
            # P13: explicit sign-off table
            "sign_off": {
                "overall_status":       overall,
                "class_a_total":        total_a,
                "class_b_total":        total_b,
                "profile_mode":         profile_mode,
                "zero_class_a":         total_a == 0,
                "zero_class_b":         total_b == 0,
                "correct_profile":      profile_mode in ("final","hostile_audit"),
                "validator_immutable":  hash_consistent,
                "audit_grade_ready":    audit_grade_ready,
                "hostile_audit_ready":  hostile_audit_ready,
                "sign_off_verdict":     (
                    "HOSTILE_AUDIT_READY" if hostile_audit_ready else
                    "AUDIT_GRADE_READY"   if audit_grade_ready   else
                    "NOT_READY"
                ),
            },
            "summary": {
                "rules_checked": sum(len(res.traces) for res in [self._preflight_result, self._postrun_result] if res),
                "rules_passed":  sum(sum(1 for t in res.traces if t.result=="PASS") for res in [self._preflight_result, self._postrun_result] if res),
                "rules_failed":  sum(sum(1 for t in res.traces if t.result=="FAIL") for res in [self._preflight_result, self._postrun_result] if res),
            },
        }

        out = pathlib.Path(output_path or "COMPLIANCE_REPORT.json")
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False))
        return report

    # P12: run_all — no duplicate emission
    def run_all(self, output_path: Optional[str] = None) -> dict:
        self.preflight()
        self.post_run()
        return self.emit_report(output_path)


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="SCAR Compliance Validator v1.0 FINAL")
    p.add_argument("manifest")
    p.add_argument("run_dir")
    p.add_argument("--authority")
    p.add_argument("--phase", choices=["preflight","post_run","all"], default="all")
    p.add_argument("--output")
    args = p.parse_args()
    v = SCARValidator(args.manifest, args.run_dir, args.authority)
    # P26-fix Blocker 2: honour --phase argument (previously always ran run_all)
    if args.phase == "preflight":
        result = v.preflight()
        out = pathlib.Path(args.output or "PREFLIGHT_REPORT.json")
        out.write_text(json.dumps(
            {"phase": result.phase, "status": result.status,
             "violations": [{"rule_id": vv.rule_id, "cls": vv.cls,
                             "message": vv.message, "evidence": vv.evidence}
                            for vv in result.violations]},
            indent=2, ensure_ascii=False))
        print(json.dumps({"phase": result.phase, "status": result.status}, indent=2))
        sys.exit(0 if result.status == "PASS" else 1)
    elif args.phase == "post_run":
        # post_run requires preflight to have run first — run both, emit full report
        report = v.run_all(args.output)
        print(json.dumps(report["sign_off"], indent=2))
        sys.exit(0 if report["overall_status"] == "PASS" else 1)
    else:
        # all (default)
        report = v.run_all(args.output)
        print(json.dumps(report["sign_off"], indent=2))
        sys.exit(0 if report["overall_status"] == "PASS" else 1)
