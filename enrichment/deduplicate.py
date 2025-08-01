"""
IOC deduplication module
"""
import logging
from typing import List, Dict, Set

logger = logging.getLogger(__name__)

def deduplicate_iocs(iocs: List[Dict]) -> List[Dict]:
    """
    Remove duplicate IOCs based on value and type
    
    Args:
        iocs: List of IOCs to deduplicate
    
    Returns:
        List of deduplicated IOCs
    """
    seen_keys: Set[str] = set()
    deduplicated = []
    
    for ioc in iocs:
        # Create a unique key based on value and type
        key = f"{ioc['value']}:{ioc['type']}"
        
        if key not in seen_keys:
            seen_keys.add(key)
            deduplicated.append(ioc)
        else:
            # Handle duplicate by merging metadata if needed
            existing_ioc = next((item for item in deduplicated if f"{item['value']}:{item['type']}" == key), None)
            if existing_ioc:
                merge_duplicate_metadata(existing_ioc, ioc)
    
    original_count = len(iocs)
    deduplicated_count = len(deduplicated)
    removed_count = original_count - deduplicated_count
    
    logger.info(f"Deduplication: removed {removed_count} duplicates, kept {deduplicated_count} unique IOCs")
    
    return deduplicated

def merge_duplicate_metadata(existing_ioc: Dict, duplicate_ioc: Dict) -> None:
    """
    Merge metadata from duplicate IOC into existing one
    
    Args:
        existing_ioc: The IOC to keep
        duplicate_ioc: The duplicate IOC to merge data from
    """
    # Merge sources if different
    existing_sources = existing_ioc.get('sources', [existing_ioc['source']])
    if duplicate_ioc['source'] not in existing_sources:
        existing_sources.append(duplicate_ioc['source'])
        existing_ioc['sources'] = existing_sources
    
    # Update confidence if duplicate has higher confidence
    if duplicate_ioc.get('confidence', 0) > existing_ioc.get('confidence', 0):
        existing_ioc['confidence'] = duplicate_ioc['confidence']
    
    # Merge enrichment data
    if 'enrichment' in duplicate_ioc:
        if 'enrichment' not in existing_ioc:
            existing_ioc['enrichment'] = {}
        
        # Add any new enrichment fields
        for key, value in duplicate_ioc['enrichment'].items():
            if key not in existing_ioc['enrichment']:
                existing_ioc['enrichment'][key] = value
    
    # Track that this IOC was seen in multiple sources
    if 'duplicate_count' not in existing_ioc:
        existing_ioc['duplicate_count'] = 1
    existing_ioc['duplicate_count'] += 1

def deduplicate_by_normalized_value(iocs: List[Dict]) -> List[Dict]:
    """
    Advanced deduplication that normalizes values before comparing
    
    Args:
        iocs: List of IOCs to deduplicate
    
    Returns:
        List of deduplicated IOCs
    """
    normalized_map = {}
    deduplicated = []
    
    for ioc in iocs:
        normalized_value = normalize_ioc_value(ioc['value'], ioc['type'])
        key = f"{normalized_value}:{ioc['type']}"
        
        if key not in normalized_map:
            normalized_map[key] = ioc
            deduplicated.append(ioc)
        else:
            # Merge with existing
            existing_ioc = normalized_map[key]
            merge_duplicate_metadata(existing_ioc, ioc)
    
    return deduplicated

def normalize_ioc_value(value: str, ioc_type: str) -> str:
    """
    Normalize IOC value for better deduplication
    
    Args:
        value: IOC value
        ioc_type: Type of IOC (ip, url)
    
    Returns:
        Normalized value
    """
    if ioc_type == 'url':
        # Remove trailing slashes, convert to lowercase
        normalized = value.lower().rstrip('/')
        
        # Remove common URL parameters that don't affect the threat
        if '?' in normalized:
            normalized = normalized.split('?')[0]
        
        return normalized
    
    elif ioc_type == 'ip':
        # For IPs, just strip whitespace
        return value.strip()
    
    return value
