"""
Main threat intelligence processing pipeline
"""
import logging
from datetime import datetime
from typing import Dict

# Import modules
from ingestion.fetch_blocklist import fetch_blocklist_feed
from ingestion.fetch_spamhaus import fetch_spamhaus_feed
from ingestion.fetch_digitalside import fetch_digitalside_feed
from ingestion.normalize import normalize_iocs
from enrichment.enrich_ip import enrich_ip_iocs
from enrichment.filter_urls import filter_suspicious_urls
from enrichment.deduplicate import deduplicate_iocs
from enrichment.ml_classifier import classify_url_iocs
from storage.save_data import save_processed_iocs, save_statistics
from app.utils import ensure_data_directory

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def run_pipeline() -> Dict:
    """
    Run the complete threat intelligence processing pipeline
    
    Returns:
        Dictionary with pipeline results
    """
    start_time = datetime.utcnow()
    logger.info("Starting threat intelligence pipeline")
    
    try:
        # Ensure data directory exists
        ensure_data_directory()
        
        # Step 1: Ingestion
        logger.info("Step 1: Ingesting threat feeds")
        raw_iocs = []
        
        # Fetch each feed
        feeds = [
            ('blocklist', fetch_blocklist_feed),
            ('spamhaus', fetch_spamhaus_feed),
            ('digitalside', fetch_digitalside_feed)
        ]
        
        ingestion_stats = {}
        for feed_name, fetch_func in feeds:
            try:
                logger.info(f"Fetching {feed_name} feed...")
                feed_iocs = fetch_func()
                raw_iocs.extend(feed_iocs)
                ingestion_stats[feed_name] = len(feed_iocs)
                logger.info(f"Fetched {len(feed_iocs)} IOCs from {feed_name}")
            except Exception as e:
                logger.error(f"Failed to fetch {feed_name} feed: {str(e)}")
                ingestion_stats[feed_name] = 0
        
        logger.info(f"Total raw IOCs ingested: {len(raw_iocs)}")
        
        if not raw_iocs:
            return {
                'success': False,
                'error': 'No IOCs were successfully ingested',
                'processed_count': 0
            }
        
        # Step 2: Normalization
        logger.info("Step 2: Normalizing IOCs")
        normalized_iocs = normalize_iocs(raw_iocs)
        logger.info(f"Normalized {len(normalized_iocs)} IOCs")
        
        # Step 3: Deduplication
        logger.info("Step 3: Deduplicating IOCs")
        deduplicated_iocs = deduplicate_iocs(normalized_iocs)
        logger.info(f"After deduplication: {len(deduplicated_iocs)} unique IOCs")
        
        # Step 4: Enrichment
        logger.info("Step 4: Enriching IOCs")
        
        # IP enrichment
        logger.info("Enriching IP addresses...")
        enriched_iocs = enrich_ip_iocs(deduplicated_iocs)
        
        # URL filtering
        logger.info("Filtering URLs...")
        filtered_iocs = filter_suspicious_urls(enriched_iocs)
        
        # ML classification for URLs
        logger.info("Applying ML classification...")
        classified_iocs = classify_url_iocs(filtered_iocs)
        
        # Step 5: Storage
        logger.info("Step 5: Saving processed IOCs")
        
        # Prepare metadata
        end_time = datetime.utcnow()
        processing_time = (end_time - start_time).total_seconds()
        
        metadata = {
            'processing_start': start_time.isoformat(),
            'processing_end': end_time.isoformat(),
            'processing_time_seconds': processing_time,
            'ingestion_stats': ingestion_stats,
            'pipeline_version': '1.0'
        }
        
        # Save IOCs
        save_success = save_processed_iocs(classified_iocs, metadata)
        
        if not save_success:
            logger.error("Failed to save processed IOCs")
            return {
                'success': False,
                'error': 'Failed to save processed IOCs',
                'processed_count': len(classified_iocs)
            }
        
        # Save statistics
        stats = {
            'raw_iocs': len(raw_iocs),
            'normalized_iocs': len(normalized_iocs),
            'deduplicated_iocs': len(deduplicated_iocs),
            'final_iocs': len(classified_iocs),
            'processing_time_seconds': processing_time,
            'ingestion_stats': ingestion_stats
        }
        
        save_statistics(stats)
        
        logger.info(f"Pipeline completed successfully in {processing_time:.2f} seconds")
        logger.info(f"Processed {len(classified_iocs)} final IOCs")
        
        return {
            'success': True,
            'processed_count': len(classified_iocs),
            'processing_time': processing_time,
            'statistics': stats
        }
    
    except Exception as e:
        logger.error(f"Pipeline failed: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'processed_count': 0
        }

def run_ingestion_only() -> Dict:
    """
    Run only the ingestion part of the pipeline
    
    Returns:
        Dictionary with ingestion results
    """
    logger.info("Running ingestion only")
    
    try:
        ensure_data_directory()
        
        raw_iocs = []
        feeds = [
            ('blocklist', fetch_blocklist_feed),
            ('spamhaus', fetch_spamhaus_feed),
            ('digitalside', fetch_digitalside_feed)
        ]
        
        for feed_name, fetch_func in feeds:
            try:
                feed_iocs = fetch_func()
                raw_iocs.extend(feed_iocs)
                logger.info(f"Fetched {len(feed_iocs)} IOCs from {feed_name}")
            except Exception as e:
                logger.error(f"Failed to fetch {feed_name}: {str(e)}")
        
        return {
            'success': True,
            'raw_iocs_count': len(raw_iocs),
            'raw_iocs': raw_iocs
        }
    
    except Exception as e:
        logger.error(f"Ingestion failed: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

if __name__ == '__main__':
    # Run pipeline when script is executed directly
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--ingestion-only':
        result = run_ingestion_only()
    else:
        result = run_pipeline()
    
    if result['success']:
        print(f"Pipeline completed successfully. Processed {result.get('processed_count', 0)} IOCs.")
    else:
        print(f"Pipeline failed: {result.get('error', 'Unknown error')}")
        sys.exit(1)
