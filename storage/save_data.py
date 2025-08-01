"""
Save processed IOC data to JSON storage
"""
import json
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

def save_processed_iocs(iocs: List[Dict], metadata: Optional[Dict] = None) -> bool:
    """
    Save processed IOCs to JSON file
    
    Args:
        iocs: List of processed IOC dictionaries
        metadata: Optional metadata about the processing run
    
    Returns:
        True if save successful, False otherwise
    """
    try:
        # Ensure data directory exists
        data_dir = 'data'
        os.makedirs(data_dir, exist_ok=True)
        
        # Prepare data structure
        data = {
            'metadata': {
                'last_updated': datetime.utcnow().isoformat(),
                'total_iocs': len(iocs),
                'ioc_types': count_ioc_types(iocs),
                'sources': count_sources(iocs),
                **(metadata or {})
            },
            'iocs': iocs
        }
        
        # Save to main file
        main_file = os.path.join(data_dir, 'processed_iocs.json')
        with open(main_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        # Save backup with timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(data_dir, f'processed_iocs_backup_{timestamp}.json')
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Successfully saved {len(iocs)} IOCs to {main_file}")
        return True
    
    except Exception as e:
        logger.error(f"Error saving IOCs: {str(e)}")
        return False

def save_raw_feed_data(feed_name: str, raw_data: str) -> bool:
    """
    Save raw feed data for debugging/archival purposes
    
    Args:
        feed_name: Name of the feed (e.g., 'blocklist', 'spamhaus', 'digitalside')
        raw_data: Raw feed content
    
    Returns:
        True if save successful
    """
    try:
        # Ensure raw data directory exists
        raw_dir = os.path.join('data', 'raw')
        os.makedirs(raw_dir, exist_ok=True)
        
        # Save with timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"{feed_name}_{timestamp}.txt"
        filepath = os.path.join(raw_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(raw_data)
        
        # Also save latest version
        latest_file = os.path.join(raw_dir, f"{feed_name}_latest.txt")
        with open(latest_file, 'w', encoding='utf-8') as f:
            f.write(raw_data)
        
        logger.debug(f"Saved raw {feed_name} feed data to {filepath}")
        return True
    
    except Exception as e:
        logger.error(f"Error saving raw feed data for {feed_name}: {str(e)}")
        return False

def count_ioc_types(iocs: List[Dict]) -> Dict[str, int]:
    """Count IOCs by type"""
    type_counts = {}
    for ioc in iocs:
        ioc_type = ioc.get('type', 'unknown')
        type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
    return type_counts

def count_sources(iocs: List[Dict]) -> Dict[str, int]:
    """Count IOCs by source"""
    source_counts = {}
    for ioc in iocs:
        source = ioc.get('source', 'unknown')
        source_counts[source] = source_counts.get(source, 0) + 1
    return source_counts

def save_statistics(stats: Dict) -> bool:
    """
    Save processing statistics
    
    Args:
        stats: Statistics dictionary
    
    Returns:
        True if save successful
    """
    try:
        data_dir = 'data'
        os.makedirs(data_dir, exist_ok=True)
        
        stats_file = os.path.join(data_dir, 'processing_stats.json')
        
        # Load existing stats if available
        existing_stats = []
        if os.path.exists(stats_file):
            try:
                with open(stats_file, 'r', encoding='utf-8') as f:
                    existing_stats = json.load(f)
            except Exception:
                existing_stats = []
        
        # Add new stats entry
        stats['timestamp'] = datetime.utcnow().isoformat()
        existing_stats.append(stats)
        
        # Keep only last 100 entries
        if len(existing_stats) > 100:
            existing_stats = existing_stats[-100:]
        
        # Save updated stats
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(existing_stats, f, indent=2)
        
        logger.debug(f"Saved processing statistics to {stats_file}")
        return True
    
    except Exception as e:
        logger.error(f"Error saving statistics: {str(e)}")
        return False
