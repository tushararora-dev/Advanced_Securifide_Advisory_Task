"""
Fetch and parse DigitalSide malicious URLs feed
"""
import requests
import logging
from typing import List, Dict
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DIGITALSIDE_URL = "https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt"

def fetch_digitalside_feed() -> List[Dict]:
    """
    Fetch and parse the DigitalSide malicious URLs feed
    
    Returns:
        List of raw IOC dictionaries
    """
    try:
        logger.info(f"Fetching DigitalSide feed from {DIGITALSIDE_URL}")
        
        response = requests.get(DIGITALSIDE_URL, timeout=30)
        response.raise_for_status()
        
        content = response.text
        iocs = []
        
        # Parse line by line, each line should be a URL
        for line_num, line in enumerate(content.strip().split('\n'), 1):
            line = line.strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            
            # Basic URL validation
            if is_valid_url(line):
                parsed_url = urlparse(line)
                
                iocs.append({
                    'value': line,
                    'type': 'url',
                    'source': 'digitalside',
                    'source_url': DIGITALSIDE_URL,
                    'category': 'malware',
                    'raw_data': line,
                    'line_number': line_num,
                    'domain': parsed_url.netloc,
                    'path': parsed_url.path,
                    'scheme': parsed_url.scheme
                })
            else:
                logger.warning(f"Invalid URL format in DigitalSide feed line {line_num}: {line}")
        
        logger.info(f"Successfully parsed {len(iocs)} URLs from DigitalSide feed")
        return iocs
    
    except requests.RequestException as e:
        logger.error(f"Error fetching DigitalSide feed: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error parsing DigitalSide feed: {str(e)}")
        raise

def is_valid_url(url: str) -> bool:
    """
    Basic URL validation
    
    Args:
        url: URL string to validate
    
    Returns:
        True if valid URL format
    """
    try:
        parsed = urlparse(url)
        return all([parsed.scheme, parsed.netloc])
    except Exception:
        return False
