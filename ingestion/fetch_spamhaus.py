"""
Fetch and parse Spamhaus DROP list
"""
import requests
import logging
from typing import List, Dict
import re

logger = logging.getLogger(__name__)

SPAMHAUS_URL = "http://www.spamhaus.org/drop/drop.txt"

def fetch_spamhaus_feed() -> List[Dict]:
    """
    Fetch and parse the Spamhaus DROP list
    
    Returns:
        List of raw IOC dictionaries
    """
    try:
        logger.info(f"Fetching Spamhaus feed from {SPAMHAUS_URL}")
        
        response = requests.get(SPAMHAUS_URL, timeout=30)
        response.raise_for_status()
        
        content = response.text
        iocs = []
        
        # Parse line by line
        for line_num, line in enumerate(content.strip().split('\n'), 1):
            line = line.strip()
            
            # Skip empty lines and comments (lines starting with ;)
            if not line or line.startswith(';'):
                continue
            
            # Spamhaus format: "CIDR ; SBL123456"
            # Extract the CIDR part
            parts = line.split(';')
            if parts:
                cidr = parts[0].strip()
                
                if is_valid_cidr(cidr):
                    # Extract SBL reference if available
                    sbl_ref = parts[1].strip() if len(parts) > 1 else None
                    
                    iocs.append({
                        'value': cidr,
                        'type': 'ip',
                        'source': 'spamhaus',
                        'source_url': SPAMHAUS_URL,
                        'category': 'botnet_range',
                        'raw_data': line,
                        'line_number': line_num,
                        'sbl_reference': sbl_ref
                    })
                else:
                    logger.warning(f"Invalid CIDR format in Spamhaus feed line {line_num}: {cidr}")
        
        logger.info(f"Successfully parsed {len(iocs)} CIDR blocks from Spamhaus feed")
        return iocs
    
    except requests.RequestException as e:
        logger.error(f"Error fetching Spamhaus feed: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error parsing Spamhaus feed: {str(e)}")
        raise

def is_valid_cidr(cidr: str) -> bool:
    """
    Basic CIDR notation validation
    
    Args:
        cidr: CIDR notation string to validate
    
    Returns:
        True if valid CIDR format
    """
    # CIDR pattern: IP/prefix
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    
    if re.match(cidr_pattern, cidr):
        ip_part, prefix_part = cidr.split('/')
        
        # Validate IP part
        octets = ip_part.split('.')
        if not all(0 <= int(octet) <= 255 for octet in octets):
            return False
        
        # Validate prefix
        prefix = int(prefix_part)
        return 0 <= prefix <= 32
    
    return False
