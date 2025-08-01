"""
Utility functions for the Flask application
"""
import json
import os
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

def load_iocs() -> List[Dict]:
    """
    Load IOCs from the processed data file
    
    Returns:
        List of IOC dictionaries
    """
    try:
        data_file = os.path.join('data', 'processed_iocs.json')
        
        if not os.path.exists(data_file):
            logger.warning("Processed IOCs file not found, returning empty list")
            return []
        
        with open(data_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return data.get('iocs', [])
    
    except Exception as e:
        logger.error(f"Error loading IOCs: {str(e)}")
        return []

def filter_iocs(iocs: List[Dict], ioc_type: Optional[str] = None, 
                source: Optional[str] = None) -> List[Dict]:
    """
    Filter IOCs based on type and/or source
    
    Args:
        iocs: List of IOC dictionaries
        ioc_type: Filter by type ('ip' or 'url')
        source: Filter by source ('blocklist', 'spamhaus', 'digitalside')
    
    Returns:
        Filtered list of IOCs
    """
    filtered = iocs
    
    if ioc_type:
        filtered = [ioc for ioc in filtered if ioc.get('type') == ioc_type]
    
    if source:
        filtered = [ioc for ioc in filtered if ioc.get('source') == source]
    
    logger.info(f"Filtered {len(iocs)} IOCs to {len(filtered)} based on type={ioc_type}, source={source}")
    
    return filtered

def ensure_data_directory():
    """Ensure the data directory exists"""
    data_dir = 'data'
    raw_dir = os.path.join(data_dir, 'raw')
    
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)
