"""
Load IOC data from JSON storage
"""
import json
import os
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

def load_processed_iocs() -> Dict:
    """
    Load processed IOCs from JSON file
    
    Returns:
        Dictionary containing metadata and IOCs
    """
    try:
        data_file = os.path.join('data', 'processed_iocs.json')
        
        if not os.path.exists(data_file):
            logger.warning("Processed IOCs file not found")
            return {
                'metadata': {
                    'total_iocs': 0,
                    'ioc_types': {},
                    'sources': {},
                    'last_updated': None
                },
                'iocs': []
            }
        
        with open(data_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        logger.info(f"Loaded {len(data.get('iocs', []))} IOCs from storage")
        return data
    
    except Exception as e:
        logger.error(f"Error loading processed IOCs: {str(e)}")
        return {
            'metadata': {
                'total_iocs': 0,
                'ioc_types': {},
                'sources': {},
                'last_updated': None,
                'error': str(e)
            },
            'iocs': []
        }

def load_iocs_list() -> List[Dict]:
    """
    Load just the IOCs list
    
    Returns:
        List of IOC dictionaries
    """
    data = load_processed_iocs()
    return data.get('iocs', [])

def load_metadata() -> Dict:
    """
    Load just the metadata
    
    Returns:
        Metadata dictionary
    """
    data = load_processed_iocs()
    return data.get('metadata', {})

def load_statistics() -> List[Dict]:
    """
    Load processing statistics
    
    Returns:
        List of statistics entries
    """
    try:
        stats_file = os.path.join('data', 'processing_stats.json')
        
        if not os.path.exists(stats_file):
            return []
        
        with open(stats_file, 'r', encoding='utf-8') as f:
            stats = json.load(f)
        
        return stats
    
    except Exception as e:
        logger.error(f"Error loading statistics: {str(e)}")
        return []

def get_latest_backup() -> Optional[str]:
    """
    Get the path to the latest backup file
    
    Returns:
        Path to latest backup file or None
    """
    try:
        data_dir = 'data'
        
        if not os.path.exists(data_dir):
            return None
        
        backup_files = [f for f in os.listdir(data_dir) 
                       if f.startswith('processed_iocs_backup_') and f.endswith('.json')]
        
        if not backup_files:
            return None
        
        # Sort by filename (which includes timestamp)
        backup_files.sort(reverse=True)
        latest_backup = backup_files[0]
        
        return os.path.join(data_dir, latest_backup)
    
    except Exception as e:
        logger.error(f"Error finding latest backup: {str(e)}")
        return None

def restore_from_backup(backup_path: str) -> bool:
    """
    Restore IOCs from a backup file
    
    Args:
        backup_path: Path to backup file
    
    Returns:
        True if restore successful
    """
    try:
        if not os.path.exists(backup_path):
            logger.error(f"Backup file not found: {backup_path}")
            return False
        
        # Load backup data
        with open(backup_path, 'r', encoding='utf-8') as f:
            backup_data = json.load(f)
        
        # Save as current data
        main_file = os.path.join('data', 'processed_iocs.json')
        with open(main_file, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Successfully restored from backup: {backup_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error restoring from backup: {str(e)}")
        return False

def check_data_integrity() -> Dict:
    """
    Check the integrity of stored data
    
    Returns:
        Integrity check results
    """
    try:
        data = load_processed_iocs()
        iocs = data.get('iocs', [])
        metadata = data.get('metadata', {})
        
        # Basic integrity checks
        issues = []
        
        # Check if IOC count matches metadata
        actual_count = len(iocs)
        reported_count = metadata.get('total_iocs', 0)
        
        if actual_count != reported_count:
            issues.append(f"IOC count mismatch: actual={actual_count}, reported={reported_count}")
        
        # Check for required fields in IOCs
        required_fields = ['id', 'value', 'type', 'source', 'confidence']
        for i, ioc in enumerate(iocs):
            missing_fields = [field for field in required_fields if field not in ioc]
            if missing_fields:
                issues.append(f"IOC {i} missing fields: {missing_fields}")
        
        # Check for duplicate IDs
        ids = [ioc.get('id') for ioc in iocs if 'id' in ioc]
        duplicate_ids = [id for id in set(ids) if ids.count(id) > 1]
        if duplicate_ids:
            issues.append(f"Duplicate IOC IDs found: {duplicate_ids}")
        
        return {
            'is_valid': len(issues) == 0,
            'total_iocs': actual_count,
            'issues': issues,
            'metadata': metadata
        }
    
    except Exception as e:
        return {
            'is_valid': False,
            'error': str(e),
            'issues': [f"Failed to check integrity: {str(e)}"]
        }
