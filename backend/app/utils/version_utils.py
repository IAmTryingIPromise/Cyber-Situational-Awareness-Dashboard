import re
from packaging import version
from typing import Optional, Tuple, Dict, List, Any
from app.utils.logger import logger

def normalize_version(version_str: str) -> str:
    """Normalize version string for comparison"""
    if not version_str or version_str == "*":
        return ""
    
    # Remove common prefixes
    version_str = version_str.lstrip("v")
    
    # Handle wildcards and ranges
    version_str = version_str.replace("*", "")
    
    # Clean up the version string
    version_str = re.sub(r'[^\d\.]', '', version_str)
    
    return version_str.strip()

def parse_cpe_components(cpe_string: str) -> Dict[str, str]:
    """Parse CPE string into components"""
    parts = cpe_string.split(":")
    if len(parts) < 5:
        return {}
    
    return {
        "uri": parts[0] if len(parts) > 0 else "",
        "version": parts[1] if len(parts) > 1 else "",
        "part": parts[2] if len(parts) > 2 else "",
        "vendor": parts[3] if len(parts) > 3 else "",
        "product": parts[4] if len(parts) > 4 else "",
        "version_component": parts[5] if len(parts) > 5 else "",
        "update": parts[6] if len(parts) > 6 else "",
        "edition": parts[7] if len(parts) > 7 else "",
        "language": parts[8] if len(parts) > 8 else "",
        "sw_edition": parts[9] if len(parts) > 9 else "",
        "target_sw": parts[10] if len(parts) > 10 else "",
        "target_hw": parts[11] if len(parts) > 11 else "",
        "other": parts[12] if len(parts) > 12 else ""
    }

def unescape_cpe_string(cpe_str: str) -> str:
    """Unescape CPE string characters"""
    return cpe_str.replace("\\(", "(").replace("\\)", ")").replace("\\_", "_").replace("\\-", "-").replace("\\/", "/")

def is_version_comparable(version_str: str) -> bool:
    """Check if version string can be compared using packaging.version"""
    try:
        version.parse(normalize_version(version_str))
        return True
    except:
        return False


class CVEVulnerabilityChecker:
    """Enhanced CVE vulnerability checker based on the working implementation"""
    
    def __init__(self, hw_cpe: str, os_cpe: str):
        """
        Initialize the checker with hardware and OS CPE identifiers.
        
        Args:
            hw_cpe: Hardware CPE string
            os_cpe: OS CPE string with version
        """
        self.hw_cpe = hw_cpe
        self.os_cpe = os_cpe
        self.hw_vendor, self.hw_product = self._extract_vendor_product(hw_cpe)
        self.os_vendor, self.os_product = self._extract_vendor_product(os_cpe)
        self.os_version = self._extract_version(os_cpe)
    
    def _extract_vendor_product(self, cpe_str: str) -> Tuple[str, str]:
        """Extract vendor and product from CPE string."""
        parts = cpe_str.split(':')
        if len(parts) >= 5:
            return parts[3], parts[4]
        return '', ''
    
    def _extract_version(self, cpe_str: str) -> str:
        """Extract version from CPE string."""
        parts = cpe_str.split(':')
        if len(parts) >= 6:
            return parts[5]
        return '*'
    
    def cve_applies_to_device(self, cve_config: List[Dict], hw_cpe: str, os_cpe: str) -> bool:
        """
        Check if a CVE applies to the device based on its configurations.
        
        Args:
            cve_config: List of configuration objects from CVE entry
            hw_cpe: Hardware CPE string
            os_cpe: OS CPE string
            
        Returns:
            True if device is vulnerable, False otherwise
        """
        # Iterate through each configuration
        for config in cve_config:
            operator = config.get('operator', 'OR').upper()
            # Each configuration has nodes that need to be evaluated
            # If any configuration evaluates to True, the device is vulnerable
            if self._evaluate_nodes_list(config['nodes'], hw_cpe, os_cpe, operator):
                return True
        
        return False
    
    def _evaluate_nodes_list(self, nodes: List[Dict], hw_cpe: str, os_cpe: str, operator: str) -> bool:
        """
        Evaluate a list of nodes. Default behavior is OR between top-level nodes.
        
        Args:
            nodes: List of node objects
            hw_cpe: Hardware CPE string
            os_cpe: OS CPE string
            operator: Logical operator (AND/OR)
            
        Returns:
            True if conditions are met based on operator
        """
        results = []

        for node in nodes:
            match = self.evaluate_node(node, hw_cpe, os_cpe)
            results.append(match)

        if operator == 'AND':
            return all(results)
        else:
            return any(results)
    
    def evaluate_node(self, node: Dict, hw_cpe: str, os_cpe: str) -> bool:
        """
        Recursively evaluate a node based on its operator and conditions.
        
        Args:
            node: Node object containing operator, cpeMatch, and possibly children
            hw_cpe: Hardware CPE string
            os_cpe: OS CPE string
            
        Returns:
            True if node conditions are met, False otherwise
        """
        operator = node.get('operator', 'OR').upper()
        results = []
        
        # Evaluate cpeMatch entries if present
        for cpe_match in node.get('cpeMatch', []):
            match_result = self.match_cpe(cpe_match, hw_cpe, os_cpe)
            results.append(match_result)
        
        # Apply operator logic
        if not results:
            return False
        
        if operator == 'AND':
            # All must be True
            return all(results)
        else:  # OR
            # At least one must be True
            return any(results)
    
    def match_cpe(self, cpe_match_entry: Dict, hw_cpe: str, os_cpe: str) -> bool:
        """
        Match a CPE entry against hardware or OS CPE.
        
        Args:
            cpe_match_entry: CPE match object from NVD
            hw_cpe: Hardware CPE string
            os_cpe: OS CPE string
            
        Returns:
            True if CPE matches, False otherwise
        """
        criteria = cpe_match_entry.get('criteria', '')
        if not criteria:
            return False
        
        # Determine if this is hardware or OS CPE
        cpe_parts = criteria.split(':')
        if len(cpe_parts) < 3:
            return False
        
        cpe_type = cpe_parts[2]  # 'h' for hardware, 'o' for OS, 'a' for application
        
        if cpe_type == 'h':
            # Hardware CPE - match against hw_cpe
            return self._match_hardware_cpe(criteria, hw_cpe)
        elif cpe_type == 'o' or cpe_type == 'a':
            # Skip if not vulnerable
            if not cpe_match_entry.get('vulnerable', True):
                return False
            # OS or Application CPE - match against os_cpe
            return self._match_os_cpe(cpe_match_entry, criteria, os_cpe)
        
        return False
    
    def _match_hardware_cpe(self, criteria: str, hw_cpe: str) -> bool:
        """
        Match hardware CPE strings.
        
        Args:
            criteria: CPE criteria from vulnerability
            hw_cpe: Device hardware CPE
            
        Returns:
            True if hardware matches
        """
        # Extract vendor and product from criteria
        criteria_parts = criteria.split(':')
        hw_parts = hw_cpe.split(':')
        
        if len(criteria_parts) < 5 or len(hw_parts) < 5:
            return False
        
        # Unescape criteria parts
        criteria_vendor = unescape_cpe_string(criteria_parts[3])
        criteria_product = unescape_cpe_string(criteria_parts[4])
        hw_vendor = unescape_cpe_string(hw_parts[3])
        hw_product = unescape_cpe_string(hw_parts[4])
        
        # Check vendor and product
        if criteria_vendor != hw_vendor:
            return False
        if criteria_product != hw_product:
            return False
        
        return True
    
    def _match_os_cpe(self, cpe_match_entry: Dict, criteria: str, os_cpe: str) -> bool:
        """
        Match OS CPE with version checking.
        
        Args:
            cpe_match_entry: Full CPE match entry with possible version ranges
            criteria: CPE criteria string
            os_cpe: Device OS CPE
            
        Returns:
            True if OS matches including version requirements
        """
        criteria_parts = criteria.split(':')
        os_parts = os_cpe.split(':')
        
        if len(criteria_parts) < 5 or len(os_parts) < 5:
            return False
        
        # Unescape and extract vendor/product
        criteria_vendor = unescape_cpe_string(criteria_parts[3])
        criteria_product = unescape_cpe_string(criteria_parts[4])
        os_vendor = unescape_cpe_string(os_parts[3])
        os_product = unescape_cpe_string(os_parts[4])
        
        # Check vendor and product first
        if criteria_vendor != os_vendor:
            return False
        if criteria_product != os_product:
            return False
        
        # Extract versions
        criteria_version = unescape_cpe_string(criteria_parts[5]) if len(criteria_parts) > 5 else '*'
        os_version = unescape_cpe_string(os_parts[5]) if len(os_parts) > 5 else '*'
        
        # Check for version range fields
        has_range = any(key in cpe_match_entry for key in [
            'versionStartIncluding', 'versionStartExcluding',
            'versionEndIncluding', 'versionEndExcluding'
        ])
        
        if has_range:
            # Use version range checking
            return self.version_in_range(
                os_version,
                cpe_match_entry.get('versionStartIncluding'),
                cpe_match_entry.get('versionStartExcluding'),
                cpe_match_entry.get('versionEndIncluding'),
                cpe_match_entry.get('versionEndExcluding')
            )
        else:
            # Direct version comparison
            if criteria_version == '*':
                return True  # Wildcard matches any version
            elif os_version == '*':
                return False  # Device has wildcard but criteria expects specific version
            else:
                return criteria_version == os_version  # Exact match required
    
    def version_in_range(self, v: str, 
                        start_inc: Optional[str], start_exc: Optional[str],
                        end_inc: Optional[str], end_exc: Optional[str]) -> bool:
        """
        Check if version is within specified range.
        
        Args:
            v: Version to check
            start_inc: Version start including (>=)
            start_exc: Version start excluding (>)
            end_inc: Version end including (<=)
            end_exc: Version end excluding (<)
            
        Returns:
            True if version is in range, False otherwise
        """
        if v == '*':
            return False  # Can't check range on wildcard
        
        try:
            v_parsed = version.parse(v)
            
            # Check lower bound
            if start_inc is not None:
                if v_parsed < version.parse(start_inc):
                    return False
            
            if start_exc is not None:
                if v_parsed <= version.parse(start_exc):
                    return False
            
            # Check upper bound
            if end_inc is not None:
                if v_parsed > version.parse(end_inc):
                    return False
            
            if end_exc is not None:
                if v_parsed >= version.parse(end_exc):
                    return False
            
            return True
            
        except Exception as e:
            logger.warning(f"Version parsing error: {e}")
            # Fall back to string comparison
            if start_inc and v < start_inc:
                return False
            if start_exc and v <= start_exc:
                return False
            if end_inc and v > end_inc:
                return False
            if end_exc and v >= end_exc:
                return False
            return True


def check_cve_vulnerability_new(cve_item: dict, asset_hw_cpe: str, asset_os_cpe: str, asset_version: str) -> bool:
    """
    Enhanced CVE vulnerability checking using the improved algorithm
    """
    try:
        # Create the checker instance
        checker = CVEVulnerabilityChecker(asset_hw_cpe, asset_os_cpe)
        
        # Get configurations from the CVE
        configurations = cve_item.get("cve", {}).get("configurations", [])
        
        # If no configurations, assume not vulnerable
        if not configurations:
            return False
        
        # Use the enhanced checking logic
        return checker.cve_applies_to_device(configurations, asset_hw_cpe, asset_os_cpe)
        
    except Exception as e:
        logger.error(f"Error checking CVE vulnerability: {e}")
        return False


# Legacy functions for backward compatibility
def compare_versions(asset_version: str, cpe_match: Dict[str, Any]) -> bool:
    """Compare asset version against CPE match version constraints - DEPRECATED"""
    try:
        # Get version constraints
        version_start_inc = cpe_match.get("versionStartIncluding")
        version_start_exc = cpe_match.get("versionStartExcluding")
        version_end_inc = cpe_match.get("versionEndIncluding")
        version_end_exc = cpe_match.get("versionEndExcluding")
        
        # If no version constraints, match all versions
        if not any([version_start_inc, version_start_exc, version_end_inc, version_end_exc]):
            return True
        
        # Check if asset version is comparable
        if not is_version_comparable(asset_version):
            # For non-comparable versions, only accept exact equality if explicit version is present
            criteria_parts = parse_cpe_components(cpe_match.get("criteria", ""))
            criteria_version = criteria_parts.get("version_component", "*")
            if criteria_version != "*":
                return unescape_cpe_string(criteria_version).lower() == asset_version.lower()
            else:
                # Flag for manual review - cannot compare non-numeric version against ranges
                logger.warning(f"Cannot compare non-numeric version {asset_version} against version ranges")
                return False
        
        # Normalize and parse asset version
        normalized_asset_version = normalize_version(asset_version)
        asset_version_obj = version.parse(normalized_asset_version)
        
        # Check start version constraints
        if version_start_inc:
            start_version_obj = version.parse(normalize_version(version_start_inc))
            if asset_version_obj < start_version_obj:
                return False
        
        if version_start_exc:
            start_version_obj = version.parse(normalize_version(version_start_exc))
            if asset_version_obj <= start_version_obj:
                return False
        
        # Check end version constraints
        if version_end_inc:
            end_version_obj = version.parse(normalize_version(version_end_inc))
            if asset_version_obj > end_version_obj:
                return False
        
        if version_end_exc:
            end_version_obj = version.parse(normalize_version(version_end_exc))
            if asset_version_obj >= end_version_obj:
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error comparing versions: {e}")
        return False

def cpe_components_match(criteria_components: Dict[str, str], asset_components: Dict[str, str]) -> bool:
    """Check if CPE components match between criteria and asset - DEPRECATED"""
    # Check part, vendor, product
    for component in ["part", "vendor", "product"]:
        criteria_val = criteria_components.get(component, "*")
        asset_val = asset_components.get(component, "")
        
        if criteria_val != "*" and criteria_val.lower() != asset_val.lower():
            return False
    
    return True

def does_cpe_match_asset(cpe_match: Dict[str, Any], asset_hw_cpe: str, asset_os_cpe: str, asset_version: str) -> Tuple[bool, bool]:
    """
    Check if a CPE match applies to the asset - DEPRECATED
    Returns: (matches, is_exclusion)
    """
    criteria = cpe_match.get("criteria", "")
    vulnerable = cpe_match.get("vulnerable", True)
    
    # Parse criteria components
    criteria_components = parse_cpe_components(criteria)
    if not criteria_components:
        return False, False
    
    # Determine if this is hardware or OS/firmware CPE
    criteria_part = criteria_components.get("part", "")
    
    matches = False
    
    if criteria_part == "h":
        # Hardware CPE - compare against asset hardware CPE
        asset_hw_components = parse_cpe_components(asset_hw_cpe)
        if cpe_components_match(criteria_components, asset_hw_components):
            # Check version constraints
            criteria_version = criteria_components.get("version_component", "*")
            if criteria_version == "*":
                # Use version range constraints
                matches = compare_versions(asset_version, cpe_match)
            else:
                # Exact version match required
                unescaped_criteria_version = unescape_cpe_string(criteria_version)
                matches = unescaped_criteria_version.lower() == asset_version.lower()
    
    elif criteria_part in ["o", "a"]:
        # OS/Application CPE - compare against asset OS CPE
        asset_os_components = parse_cpe_components(asset_os_cpe)
        if cpe_components_match(criteria_components, asset_os_components):
            # Check version constraints
            criteria_version = criteria_components.get("version_component", "*")
            if criteria_version == "*":
                # Use version range constraints
                matches = compare_versions(asset_version, cpe_match)
            else:
                # Exact version match required
                unescaped_criteria_version = unescape_cpe_string(criteria_version)
                matches = unescaped_criteria_version.lower() == asset_version.lower()
    
    return matches, not vulnerable  # is_exclusion = not vulnerable

def evaluate_node(node: Dict[str, Any], asset_hw_cpe: str, asset_os_cpe: str, asset_version: str) -> bool:
    """
    Recursively evaluate a configuration node - DEPRECATED
    Returns True if the node indicates the asset is vulnerable
    """
    operator = node.get("operator", "OR")
    negate = node.get("negate", False)
    
    # Evaluate child nodes recursively
    child_results = []
    if "children" in node:
        for child_node in node["children"]:
            child_result = evaluate_node(child_node, asset_hw_cpe, asset_os_cpe, asset_version)
            child_results.append(child_result)
    
    # Evaluate CPE matches
    positive_matches = []
    exclusion_matches = []
    
    if "cpeMatch" in node:
        for cpe_match in node["cpeMatch"]:
            matches, is_exclusion = does_cpe_match_asset(cpe_match, asset_hw_cpe, asset_os_cpe, asset_version)
            if matches:
                if is_exclusion:
                    exclusion_matches.append(cpe_match)
                else:
                    positive_matches.append(cpe_match)
    
    # If any exclusion matches exist in this subtree, return False
    if exclusion_matches:
        result = False
    else:
        # Combine results based on operator
        if operator == "OR":
            result = any(child_results) or len(positive_matches) > 0
        elif operator == "AND":
            # For AND: all child results must be true AND we need positive matches if there are CPE criteria
            if "cpeMatch" in node and node["cpeMatch"]:
                # If this node has CPE matches, we need at least one positive match
                result = all(child_results) and len(positive_matches) > 0
            else:
                # If no CPE matches in this node, just require all children to be true
                result = all(child_results) if child_results else False
        else:
            logger.warning(f"Unknown operator: {operator}")
            result = any(child_results) or len(positive_matches) > 0
    
    # Apply negation
    if negate:
        result = not result
    
    return result

# Keep the old function for backward compatibility but mark it as deprecated
def check_cve_vulnerability(cve_item: dict, os_cpe: str, device_version: str) -> bool:
    """
    DEPRECATED: Use check_cve_vulnerability_new instead
    This is kept for backward compatibility
    """
    # For backward compatibility, treat the os_cpe as both hardware and OS CPE
    return check_cve_vulnerability_new(cve_item, os_cpe, os_cpe, device_version)