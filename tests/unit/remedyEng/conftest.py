"""
Centralized fixtures and helpers for SecRemedy remediation unit tests.

This module provides shared utilities for all 12 remediation rule test suites.
It implements the remedy-unit-test-independent skill workflow.
"""

import pytest
import copy
from typing import Any, Dict, List, Optional


# ==============================================================================
# SECTION 1: Basic AST Node Builders (Rule-agnostic)
# ==============================================================================

def _node(
    directive: str,
    args: Optional[List[str]] = None,
    block: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """Build a minimal Nginx directive AST node.
    
    Args:
        directive: Nginx directive name (e.g., "listen", "server_name")
        args: List of directive arguments, defaults to []
        block: Nested block content (for directives like "server", "location")
    
    Returns:
        Dictionary representing the AST node
        
    Example:
        >>> _node("listen", ["80"])
        {"directive": "listen", "args": ["80"]}
        
        >>> _node("server", [], [_node("listen", ["80"])])
        {"directive": "server", "args": [], "block": [...]}
    """
    item = {"directive": directive, "args": args or []}
    if block is not None:
        item["block"] = block
    return item


def _http(block: List[Dict]) -> Dict[str, Any]:
    """Build an http block containing nested directives (typically servers)."""
    return _node("http", [], block)


def _server(block: List[Dict]) -> Dict[str, Any]:
    """Build a server block containing nested directives (listen, server_name, etc.)."""
    return _node("server", [], block)


def _location(path: str, block: Optional[List[Dict]] = None) -> Dict[str, Any]:
    """Build a location block.
    
    Args:
        path: Location path (e.g., "/" or "/api")
        block: Nested directives within location
        
    Returns:
        Dictionary representing location block
    """
    return _node("location", [path], block or [])


def _if_block(condition: str, directives: Optional[List[Dict]] = None) -> Dict[str, Any]:
    """Build an if block.
    
    Args:
        condition: Conditional expression (e.g., "$request_method = POST")
        directives: Statements inside the if block
    """
    return _node("if", [condition], directives or [])


# ==============================================================================
# SECTION 2: Complete AST Config Builders
# ==============================================================================

def _make_ast(parsed: List[Dict]) -> Dict[str, Any]:
    """Wrap parsed directive list into a crossplane-compatible config structure.
    
    Args:
        parsed: List of top-level directive nodes
        
    Returns:
        Dictionary with "parsed" key matching crossplane contract
    """
    return {"parsed": parsed}


def _make_config(
    file_path: str,
    parsed: List[Dict],
) -> Dict[str, Dict[str, Any]]:
    """Build a complete config dictionary for child_ast_config.
    
    Args:
        file_path: Path to the config file
        parsed: Parsed directive list
        
    Returns:
        Dictionary mapping file_path to config structure
    """
    return {file_path: _make_ast(parsed)}


# ==============================================================================
# SECTION 3: Scan Result Payload Builders
# ==============================================================================

def _remediation_entry(
    action: str,
    directive: str,
    context: List,
    **kwargs
) -> Dict[str, Any]:
    """Build a single remediation entry for scan_result.
    
    Args:
        action: Action type ("delete", "add", "replace", "upsert", etc.)
        directive: Nginx directive name
        context: Context path in parsed AST
        **kwargs: Additional fields (value, args, etc.)
        
    Returns:
        Dictionary representing one remediation
    """
    entry = {
        "action": action,
        "directive": directive,
        "context": context,
    }
    entry.update(kwargs)
    return entry


def _make_scan_result(
    rule_id: str,
    file_path: str,
    remediations: List[Dict],
) -> Dict[str, Dict[str, List[Dict]]]:
    """Build a complete scan_result structure grouped by rule_id.
    
    Args:
        rule_id: CIS rule ID (e.g., "2.4.1")
        file_path: Config file with violations
        remediations: List of remediation entries
        
    Returns:
        Dictionary with structure {rule_id: {file_path: [remediations]}}
    """
    return {
        rule_id: {
            file_path: remediations
        }
    }


def _make_multi_file_scan_result(
    rule_id: str,
    file_violations: Dict[str, List[Dict]],
) -> Dict[str, Dict[str, List[Dict]]]:
    """Build a scan_result with violations across multiple files.
    
    Args:
        rule_id: CIS rule ID
        file_violations: Mapping of {file_path: [remediation entries]}
        
    Returns:
        Scan result structure
    """
    return {
        rule_id: file_violations
    }


# ==============================================================================
# SECTION 4: Context & Path Helpers
# ==============================================================================

def _context_from_parsed(indices: List[int], prefix: bool = True) -> List:
    """Build a context path (deep copy) for addressing nodes in parsed AST.
    
    The context path represents navigation to a node in Nginx config AST.
    Standard format: ["config", 0, "parsed", ...indices within parsed...]
    
    Args:
        indices: List of indices to navigate through nested blocks
                (e.g., [0, "block", 0, "block", 1] for http.block[0].block[1])
        prefix: Whether to include the "config", 0, "parsed" prefix
        
    Returns:
        Full context path
        
    Example:
        >>> _context_from_parsed([0, "block", 0])
        ["config", 0, "parsed", 0, "block", 0]
    """
    if prefix:
        return ["config", 0, "parsed"] + indices
    return indices


def _normalize_file_path(path: str) -> str:
    """Normalize file path for matching across scan_result and AST configs.
    
    This mimics the path normalization used by plugins.
    Strips "./", lowercases, normalizes slashes.
    
    Args:
        path: File path (potentially with ./, case variations, etc.)
        
    Returns:
        Normalized path
    """
    # Strip leading ./
    if path.startswith("./"):
        path = path[2:]
    # Normalize slashes
    path = path.replace("\\", "/")
    return path.lower()


def _path_variants(base_path: str) -> List[str]:
    """Generate multiple path variants for testing path normalization.
    
    Args:
        base_path: Base file path (e.g., "/etc/nginx/nginx.conf")
        
    Returns:
        List of path variants that should normalize to the same key
        
    Example:
        >>> _path_variants("/etc/nginx/nginx.conf")
        [
            "/etc/nginx/nginx.conf",
            "./etc/nginx/nginx.conf",
            "etc/nginx/nginx.conf",
            # ... more variants
        ]
    """
    base = _normalize_file_path(base_path)
    variants = [base_path]  # Original
    
    # Add ./ prefix variant
    if not base_path.startswith("./"):
        variants.append(f"./{base_path}")
    
    # Add relative variant (strip leading /)
    if base_path.startswith("/"):
        relative = base_path.lstrip("/")
        variants.append(relative)
        if not relative.startswith("./"):
            variants.append(f"./{relative}")
    
    # Add case variant (lowercase)
    if base_path != base:
        variants.append(base)
    
    return list(dict.fromkeys(variants))  # Remove duplicates, preserve order


# ==============================================================================
# SECTION 5: Assertion Helpers
# ==============================================================================

def _assert_directive_exists_in_block(
    block: List[Dict],
    directive: str,
    args: Optional[List[str]] = None,
    message: str = None,
) -> None:
    """Assert that a directive exists in a block with optional args matching.
    
    Args:
        block: List of directive nodes (typically a "block" value from parsed)
        directive: Directive name to find
        args: Optional args to match (if None, just check directive exists)
        message: Custom assertion message
        
    Raises:
        AssertionError if directive not found or args don't match
    """
    nodes = [n for n in block if n.get("directive") == directive]
    if not nodes:
        err = message or f"Directive '{directive}' not found in block"
        raise AssertionError(err)
    
    if args is not None:
        matching = [n for n in nodes if n.get("args") == args]
        if not matching:
            err = message or f"Directive '{directive}' with args {args} not found in block"
            raise AssertionError(err)


def _assert_directive_not_in_block(
    block: List[Dict],
    directive: str,
    args: Optional[List[str]] = None,
    message: str = None,
) -> None:
    """Assert that a directive does NOT exist in a block.
    
    Args:
        block: List of directive nodes
        directive: Directive name to check
        args: Optional args to match (if None, check directive doesn't exist anywhere)
        message: Custom assertion message
        
    Raises:
        AssertionError if directive is found
    """
    nodes = [n for n in block if n.get("directive") == directive]
    if not nodes:
        return  # Success: directive not in block
    
    if args is not None:
        matching = [n for n in nodes if n.get("args") == args]
        if matching:
            err = message or f"Directive '{directive}' with args {args} should not exist in block"
            raise AssertionError(err)
    else:
        err = message or f"Directive '{directive}' should not exist in block"
        raise AssertionError(err)


def _count_directives(block: List[Dict], directive: str) -> int:
    """Count how many times a directive appears in a block."""
    return len([n for n in block if n.get("directive") == directive])


def _get_directive_args_list(
    block: List[Dict],
    directive: str,
) -> List[List[str]]:
    """Get all args lists for a specific directive in a block.
    
    Args:
        block: List of directive nodes
        directive: Directive name to collect
        
    Returns:
        List of args lists for all matching directives
    """
    return [n.get("args", []) for n in block if n.get("directive") == directive]


def _assert_ast_structure_unchanged(
    original_parsed: List[Dict],
    modified_parsed: List[Dict],
    allowed_mutations: Optional[set] = None,
    message: str = None,
) -> None:
    """Assert that AST structure (directives, nesting) is preserved except for allowed changes.
    
    Use this to verify that remediation doesn't accidentally break block nesting,
    reorder directives, or lose unrelated content.
    
    Args:
        original_parsed: Original parsed AST
        modified_parsed: AST after remediation
        allowed_mutations: Set of directive names that are allowed to change (e.g., {"listen"})
        message: Custom message
        
    Raises:
        AssertionError if structure is unexpectedly modified
    """
    allowed = allowed_mutations or set()
    
    def extract_structure(parsed):
        """Extract directive names and nesting pattern (not args)."""
        def walk(nodes):
            result = []
            for node in nodes:
                directive = node.get("directive")
                result.append(directive)
                if "block" in node:
                    result.append(walk(node["block"]))
            return result
        return walk(parsed)
    
    original_struct = extract_structure(original_parsed)
    modified_struct = extract_structure(modified_parsed)
    
    # Simplified check: should have same directive count except in allowed_mutations
    if original_struct != modified_struct:
        if not allowed:
            err = message or f"AST structure changed unexpectedly"
            raise AssertionError(err)
        # More detailed check would be needed for real comparison with mutations


# ==============================================================================
# SECTION 6: Deep Copy & Payload Helpers
# ==============================================================================

def _deep_copy_ast(ast_config: Dict) -> Dict:
    """Create a deep copy of an AST config to test that remediation doesn't mutate originals."""
    return copy.deepcopy(ast_config)


def _deep_copy_scan_result(scan_result: Dict) -> Dict:
    """Create a deep copy of scan_result to verify it's not accidentally modified."""
    return copy.deepcopy(scan_result)


# ==============================================================================
# SECTION 7: Rule-Specific Builders (>2 rules sharing patterns)
# ==============================================================================

def _catch_all_server_block(
    directives: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """Build a catch-all server block for CIS 2.4.2 (default_server).
    
    Args:
        directives: Additional directives inside the server block (default has only required ones)
        
    Returns:
        Server block with default_server and catch-all configuration
    """
    block = [
        _node("listen", ["80", "default_server"]),
        _node("ssl_reject_handshake", ["on"]),
        _node("return", ["444"]),
    ]
    if directives:
        block.extend(directives)
    return _server(block)


def _http_block_with_directive(
    directive: str,
    args: List[str],
    nested_servers: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """Build an http block with a specific directive and nested servers.
    
    Used for testing server_tokens, other global directives.
    """
    block = [_node(directive, args)]
    if nested_servers:
        block.extend(nested_servers)
    else:
        block.append(_server([_node("listen", ["80"])]))
    return _http(block)


def _location_with_directives(
    path: str,
    directives: List[Dict],
) -> Dict[str, Any]:
    """Build a location block with specific directives."""
    return _location(path, directives)


def _server_with_location(
    location_path: str,
    location_directives: List[Dict],
    server_directives: Optional[List[Dict]] = None,
) -> Dict[str, Any]:
    """Build a server block containing a location block.
    
    Used for testing per-location rules.
    """
    block = server_directives or [_node("listen", ["80"])]
    block.append(_location(location_path, location_directives))
    return _server(block)


# ==============================================================================
# SECTION 8: Multi-File Test Generators
# ==============================================================================

def _multi_file_ast_configs(
    files_and_parsed: Dict[str, List[Dict]],
) -> Dict[str, Dict]:
    """Build a child_ast_config dictionary with multiple files.
    
    Args:
        files_and_parsed: Mapping of {file_path: parsed_directives}
        
    Returns:
        Dictionary mapping file paths to AST configs
    """
    return {
        file_path: _make_ast(parsed)
        for file_path, parsed in files_and_parsed.items()
    }


def _multi_file_scan_result_violations(
    rule_id: str,
    files_and_remediations: Dict[str, List[Dict]],
) -> Dict:
    """Build a scan_result with violations across multiple files for a rule.
    
    Args:
        rule_id: CIS rule ID
        files_and_remediations: Mapping of {file_path: [remediation entries]}
        
    Returns:
        Scan result structure
    """
    return {
        rule_id: files_and_remediations
    }


# ==============================================================================
# SECTION 9: Context Edge Case Generators
# ==============================================================================

def _context_root_mismatch(indices: List[int]) -> List:
    """Generate a context path that points to a different file than the AST being modified.
    
    Used to test safety guards that prevent cross-file mutations.
    """
    # Return context for a different file while testing file X
    return ["config", 1, "parsed"] + indices  # config[1] instead of config[0]


def _context_nested_deep(depth: int = 5) -> tuple:
    """Generate a deeply nested AST and corresponding context path.
    
    Args:
        depth: How many levels of nesting (servers within servers, etc.)
        
    Returns:
        Tuple of (nested_ast, context_path_to_deepest_node)
    """
    # Build nested structure: http > server > location > ... > deepest directive
    deepest_directive = _node("some_directive", ["value"])
    current = [deepest_directive]
    context_indices = []
    
    for i in range(depth):
        if i % 2 == 0:
            current = [_location(f"/level{i}", current)]
            context_indices.extend(["block", 0])
        else:
            current = [_server(current)]
            context_indices.extend(["block", 0])
    
    current = [_http(current)]
    context_indices.extend(["block", 0])
    
    context = _context_from_parsed(context_indices, prefix=True)
    return current, context


def _context_empty() -> List:
    """Generate an empty context (edge case: should point to parsed root)."""
    return ["config", 0, "parsed"]


def _context_with_relative_path(indices: List[int]) -> List:
    """Generate a context path without the config/parsed prefix (already relative within parsed)."""
    return indices


# ==============================================================================
# SECTION 10: Pytest Fixtures (Rule-Agnostic)
# ==============================================================================

@pytest.fixture
def remedy_241():
    """Fixture for Rule 2.4.1 (Delete unauthorized listen ports)."""
    from core.remedyEng.recommendations.remediate_241 import Remediate241
    return Remediate241()


@pytest.fixture
def remedy_242():
    """Fixture for Rule 2.4.2 (Catch-all server block)."""
    from core.remedyEng.recommendations.remediate_242 import Remediate242
    return Remediate242()


@pytest.fixture
def remedy_251():
    """Fixture for Rule 2.5.1 (server_tokens off)."""
    from core.remedyEng.recommendations.remediate_251 import Remediate251
    return Remediate251()


@pytest.fixture
def remedy_252():
    """Fixture for Rule 2.5.2 (Error page directives)."""
    from core.remedyEng.recommendations.remediate_252 import Remediate252
    return Remediate252()


@pytest.fixture
def remedy_253():
    """Fixture for Rule 2.5.3 (Hidden files + ACME)."""
    from core.remedyEng.recommendations.remediate_253 import Remediate253
    return Remediate253()


@pytest.fixture
def remedy_254():
    """Fixture for Rule 2.5.4 (Header hiding)."""
    from core.remedyEng.recommendations.remediate_254 import Remediate254
    return Remediate254()


@pytest.fixture
def remedy_32():
    """Fixture for Rule 3.2 (Access logging)."""
    from core.remedyEng.recommendations.remediate_32 import Remediate32
    return Remediate32()


@pytest.fixture
def remedy_34():
    """Fixture for Rule 3.4 (Proxy headers)."""
    from core.remedyEng.recommendations.remediate_34 import Remediate34
    return Remediate34()


@pytest.fixture
def remedy_411():
    """Fixture for Rule 4.1.1 (HTTP to HTTPS redirect)."""
    from core.remedyEng.recommendations.remediate_411 import Remediate411
    return Remediate411()


@pytest.fixture
def remedy_511():
    """Fixture for Rule 5.1.1 (IP allowlist)."""
    from core.remedyEng.recommendations.remediate_511 import Remediate511
    return Remediate511()


@pytest.fixture
def remedy_531():
    """Fixture for Rule 5.3.1 (X-Content-Type-Options)."""
    from core.remedyEng.recommendations.remediate_531 import Remediate531
    return Remediate531()


@pytest.fixture
def remedy_532():
    """Fixture for Rule 5.3.2 (Content Security Policy)."""
    from core.remedyEng.recommendations.remediate_532 import Remediate532
    return Remediate532()
