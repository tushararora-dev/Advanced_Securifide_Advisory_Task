"""
Fetch and parse blocklist.de apache.txt feed
"""
import requests
import logging
from typing import List, Dict
import re

logger = logging.getLogger(__name__)

BLOCKLIST_URL = "http://www.blocklist.de/lists/apache.txt"

def fetch_blocklist_feed() -> List[Dict]:
    """
    Fetch and parse the blocklist.de apache.txt feed
    
    Returns:
        List of raw IOC dictionaries
    """
    try:
        logger.info(f"Fetching blocklist feed from {BLOCKLIST_URL}")
        
        response = requests.get(BLOCKLIST_URL, timeout=30)
        response.raise_for_status()
        
        content = response.text
        iocs = []
        
        # Parse line by line, each line should be an IP address
        for line_num, line in enumerate(content.strip().split('\n'), 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Validate IP address format
            if is_valid_ip(line):
                iocs.append({
                    'value': line,
                    'type': 'ip',
                    'source': 'blocklist',
                    'source_url': BLOCKLIST_URL,
                    'category': 'brute_force',
                    'raw_data': line,
                    'line_number': line_num
                })
            else:
                logger.warning(f"Invalid IP format in blocklist feed line {line_num}: {line}")
        
        logger.info(f"Successfully parsed {len(iocs)} IPs from blocklist feed")
        return iocs
    
    except requests.RequestException as e:
        logger.error(f"Error fetching blocklist feed: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error parsing blocklist feed: {str(e)}")
        raise

def is_valid_ip(ip: str) -> bool:
    """
    Basic IP address validation
    
    Args:
        ip: IP address string to validate
    
    Returns:
        True if valid IP format
    """
    # Simple IPv4 regex pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    if re.match(ipv4_pattern, ip):
        # Check each octet is between 0-255
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    return False
