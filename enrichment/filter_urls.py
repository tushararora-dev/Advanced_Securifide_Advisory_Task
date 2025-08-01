"""
URL filtering for suspicious extensions and patterns
"""
import logging
import re
from typing import List
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Suspicious file extensions
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
    '.jar', '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    '.msi', '.deb', '.rpm', '.dmg', '.pkg', '.app'
]

# Suspicious URL patterns
SUSPICIOUS_PATTERNS = [
    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses in URLs
    r'[a-z0-9]{10,}\.tk|\.ml|\.ga|\.cf',  # Suspicious TLDs with random subdomains
    r'bit\.ly|tinyurl|t\.co|goo\.gl',  # URL shorteners
    r'download|install|update|urgent|click|free',  # Suspicious keywords
]

def filter_suspicious_urls(iocs: List) -> List:
    """
    Filter URL IOCs to identify suspicious ones
    
    Args:
        iocs: List of normalized IOCs
    
    Returns:
        List of IOCs with suspicious URLs marked
    """
    filtered = []
    
    for ioc in iocs:
        if ioc['type'] == 'url':
            try:
                suspicion_score = calculate_url_suspicion(ioc['value'])
                
                # Add suspicion analysis to metadata
                if 'enrichment' not in ioc:
                    ioc['enrichment'] = {}
                
                ioc['enrichment'].update({
                    'suspicion_score': suspicion_score,
                    'is_suspicious': suspicion_score > 0.5,
                    'suspicious_indicators': get_suspicious_indicators(ioc['value'])
                })
                
                # Only keep URLs that meet the filtering criteria
                if should_keep_url(ioc['value'], suspicion_score):
                    filtered.append(ioc)
                else:
                    logger.debug(f"Filtered out URL with low suspicion score: {ioc['value']}")
            
            except Exception as e:
                logger.error(f"Error filtering URL {ioc['value']}: {str(e)}")
                filtered.append(ioc)  # Keep on error
        else:
            filtered.append(ioc)
    
    logger.info(f"URL filtering: kept {len([i for i in filtered if i['type'] == 'url'])} URLs out of {len([i for i in iocs if i['type'] == 'url'])}")
    return filtered

def calculate_url_suspicion(url: str) -> float:
    """
    Calculate suspicion score for a URL
    
    Args:
        url: URL to analyze
    
    Returns:
        Suspicion score between 0.0 and 1.0
    """
    score = 0.0
    url_lower = url.lower()
    
    # Check for suspicious extensions
    for ext in SUSPICIOUS_EXTENSIONS:
        if ext in url_lower:
            score += 0.3
            break
    
    # Check for suspicious patterns
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url_lower, re.IGNORECASE):
            score += 0.2
    
    # Parse URL for additional checks
    try:
        parsed = urlparse(url)
        
        # Check domain characteristics
        domain = parsed.netloc.lower()
        
        # Long random-looking subdomains
        if len(domain) > 30 and any(char.isdigit() for char in domain):
            score += 0.2
        
        # IP addresses as domains
        if re.match(r'^[0-9.]+$', domain):
            score += 0.4
        
        # Suspicious ports
        if parsed.port and parsed.port in [8080, 8443, 9999]:
            score += 0.1
        
        # Very long URLs
        if len(url) > 200:
            score += 0.1
        
        # Path characteristics
        path = parsed.path.lower()
        if '/admin' in path or '/wp-admin' in path or '/upload' in path:
            score += 0.1
    
    except Exception:
        # If URL parsing fails, it's suspicious
        score += 0.3
    
    return min(score, 1.0)

def get_suspicious_indicators(url: str) -> List[str]:
    """
    Get list of suspicious indicators found in the URL
    
    Args:
        url: URL to analyze
    
    Returns:
        List of suspicious indicators
    """
    indicators = []
    url_lower = url.lower()
    
    # Check extensions
    for ext in SUSPICIOUS_EXTENSIONS:
        if ext in url_lower:
            indicators.append(f"suspicious_extension:{ext}")
    
    # Check patterns
    pattern_names = [
        'ip_address', 'suspicious_tld', 'url_shortener', 'suspicious_keywords'
    ]
    
    for i, pattern in enumerate(SUSPICIOUS_PATTERNS):
        if re.search(pattern, url_lower, re.IGNORECASE):
            indicators.append(f"pattern:{pattern_names[i]}")
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if len(domain) > 30:
            indicators.append("long_domain")
        
        if re.match(r'^[0-9.]+$', domain):
            indicators.append("ip_domain")
        
        if len(url) > 200:
            indicators.append("long_url")
        
        if parsed.port and parsed.port in [8080, 8443, 9999]:
            indicators.append(f"suspicious_port:{parsed.port}")
    
    except Exception:
        indicators.append("malformed_url")
    
    return indicators

def should_keep_url(url: str, suspicion_score: float) -> bool:
    """
    Determine if a URL should be kept based on filtering criteria
    
    Args:
        url: URL to evaluate
        suspicion_score: Calculated suspicion score
    
    Returns:
        True if URL should be kept
    """
    # Keep URLs with specific suspicious extensions
    url_lower = url.lower()
    high_priority_extensions = ['.exe', '.zip', '.bat', '.scr']
    
    if any(ext in url_lower for ext in high_priority_extensions):
        return True
    
    # Keep URLs with high suspicion scores
    if suspicion_score > 0.4:
        return True
    
    # Keep URLs from certain patterns (like IP addresses)
    if re.search(SUSPICIOUS_PATTERNS[0], url_lower):  # IP address pattern
        return True
    
    return False
