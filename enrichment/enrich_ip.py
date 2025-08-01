"""
IP address enrichment using mock database or external API
"""
import json
import os
import logging
import requests
from typing import Dict, Optional
from dotenv import load_dotenv
load_dotenv()  # This will load .env values into os.environ
api_key = os.getenv('IPINFO_API_KEY')

logger = logging.getLogger(__name__)

def enrich_ip_iocs(iocs: list) -> list:
    """
    Enrich IP IOCs with geolocation and ISP information
    
    Args:
        iocs: List of normalized IOCs
    
    Returns:
        List of enriched IOCs
    """
    enriched = []
    mock_db = load_mock_ip_db()
    
    for ioc in iocs:
        if ioc['type'] == 'ip':
            try:
                # Extract IP from CIDR if needed
                ip_address = ioc['value'].split('/')[0]
                
                # Try to enrich the IP
                enrichment_data = enrich_single_ip(ip_address, mock_db)
                
                if enrichment_data:
                    ioc['enrichment'] = enrichment_data
                
                enriched.append(ioc)
                
            except Exception as e:
                logger.error(f"Error enriching IP {ioc['value']}: {str(e)}")
                enriched.append(ioc)
        else:
            enriched.append(ioc)
    
    return enriched

def enrich_single_ip(ip_address: str, mock_db: dict) -> Optional[Dict]:
    """
    Enrich a single IP address
    
    Args:
        ip_address: IP address to enrich
        mock_db: Mock database for enrichment
    
    Returns:
        Enrichment data dictionary or None
    """
    # First try mock database
    enrichment = get_mock_enrichment(ip_address, mock_db)
    
    if enrichment:
        return enrichment
    
    # Try external API if available
    api_key = os.getenv('IPINFO_API_KEY')
    if api_key:
        return get_ipinfo_enrichment(ip_address, api_key)
    
    # Fallback to basic classification
    return get_basic_enrichment(ip_address)

def load_mock_ip_db() -> dict:
    """
    Load mock IP database for enrichment
    
    Returns:
        Mock database dictionary
    """
    try:
        mock_db_path = os.path.join('data', 'mock_ip_db.json')
        
        if os.path.exists(mock_db_path):
            with open(mock_db_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            logger.warning("Mock IP database not found, using empty database")
            return {}
    
    except Exception as e:
        logger.error(f"Error loading mock IP database: {str(e)}")
        return {}

def get_mock_enrichment(ip_address: str, mock_db: dict) -> Optional[Dict]:
    """
    Get enrichment data from mock database
    
    Args:
        ip_address: IP address to look up
        mock_db: Mock database
    
    Returns:
        Enrichment data or None
    """
    return mock_db.get(ip_address)

def get_ipinfo_enrichment(ip_address: str, api_key: str) -> Optional[Dict]:
    """
    Get enrichment data from ipinfo.io API
    
    Args:
        ip_address: IP address to enrich
        api_key: ipinfo.io API key
    
    Returns:
        Enrichment data or None
    """
    try:
        url = f"https://ipinfo.io/{ip_address}/json?token={api_key}"
        
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        return {
            'country': data.get('country'),
            'region': data.get('region'),
            'city': data.get('city'),
            'org': data.get('org'),
            'timezone': data.get('timezone'),
            'source': 'ipinfo.io'
        }
    
    except Exception as e:
        logger.error(f"Error enriching IP {ip_address} with ipinfo.io: {str(e)}")
        return None

def get_basic_enrichment(ip_address: str) -> Dict:
    """
    Basic IP enrichment without external APIs
    
    Args:
        ip_address: IP address to classify
    
    Returns:
        Basic enrichment data
    """
    # Basic classification based on IP ranges
    first_octet = int(ip_address.split('.')[0])
    
    if first_octet in [10]:
        classification = 'private'
    elif first_octet == 172:
        second_octet = int(ip_address.split('.')[1])
        classification = 'private' if 16 <= second_octet <= 31 else 'public'
    elif first_octet == 192:
        second_octet = int(ip_address.split('.')[1])
        classification = 'private' if second_octet == 168 else 'public'
    elif first_octet in [127, 169]:
        classification = 'special'
    else:
        classification = 'public'
    
    return {
        'classification': classification,
        'source': 'basic_analysis'
    }
