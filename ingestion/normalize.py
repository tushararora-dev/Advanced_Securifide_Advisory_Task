"""
Normalize IOCs into a common schema
"""
import logging
from typing import List, Dict
from datetime import datetime

logger = logging.getLogger(__name__)

def normalize_iocs(raw_iocs: List[Dict]) -> List[Dict]:
    """
    Normalize IOCs from different sources into a common schema
    
    Args:
        raw_iocs: List of raw IOC dictionaries from various sources
    
    Returns:
        List of normalized IOC dictionaries
    """
    normalized = []
    current_time = datetime.utcnow().isoformat()
    
    for ioc in raw_iocs:
        try:
            normalized_ioc = {
                'id': generate_ioc_id(ioc),
                'value': ioc['value'],
                'type': ioc['type'],
                'source': ioc['source'],
                'source_url': ioc.get('source_url'),
                'category': ioc.get('category'),
                'first_seen': current_time,
                'last_updated': current_time,
                'confidence': calculate_confidence(ioc),
                'metadata': extract_metadata(ioc)
            }
            
            normalized.append(normalized_ioc)
            
        except Exception as e:
            logger.error(f"Error normalizing IOC {ioc}: {str(e)}")
            continue
    
    logger.info(f"Normalized {len(normalized)} IOCs from {len(raw_iocs)} raw entries")
    return normalized

def generate_ioc_id(ioc: Dict) -> str:
    """
    Generate a unique ID for an IOC
    
    Args:
        ioc: IOC dictionary
    
    Returns:
        Unique identifier string
    """
    import hashlib
    
    # Create ID based on value, type, and source
    id_string = f"{ioc['value']}-{ioc['type']}-{ioc['source']}"
    return hashlib.md5(id_string.encode()).hexdigest()

def calculate_confidence(ioc: Dict) -> float:
    """
    Calculate confidence score for an IOC based on source and metadata
    
    Args:
        ioc: IOC dictionary
    
    Returns:
        Confidence score between 0.0 and 1.0
    """
    # Base confidence by source
    source_confidence = {
        'blocklist': 0.8,
        'spamhaus': 0.9,
        'digitalside': 0.7
    }
    
    base_score = source_confidence.get(ioc['source'], 0.5)
    
    # Adjust based on type and additional factors
    if ioc['type'] == 'ip':
        # CIDR blocks typically have higher confidence
        if '/' in ioc['value']:
            base_score += 0.05
    
    elif ioc['type'] == 'url':
        # URLs with suspicious extensions get higher confidence
        suspicious_extensions = ['.exe', '.zip', '.rar', '.bat', '.scr']
        if any(ext in ioc['value'].lower() for ext in suspicious_extensions):
            base_score += 0.1
    
    return min(base_score, 1.0)

def extract_metadata(ioc: Dict) -> Dict:
    """
    Extract relevant metadata from the raw IOC data
    
    Args:
        ioc: Raw IOC dictionary
    
    Returns:
        Metadata dictionary
    """
    metadata = {
        'raw_data': ioc.get('raw_data'),
        'line_number': ioc.get('line_number')
    }
    
    # Add source-specific metadata
    if ioc['source'] == 'spamhaus':
        metadata['sbl_reference'] = ioc.get('sbl_reference')
    
    elif ioc['source'] == 'digitalside' and ioc['type'] == 'url':
        metadata.update({
            'domain': ioc.get('domain'),
            'path': ioc.get('path'),
            'scheme': ioc.get('scheme')
        })
    
    # Remove None values
    return {k: v for k, v in metadata.items() if v is not None}
