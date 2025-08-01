#!/usr/bin/env python3
"""
Script to run the threat intelligence pipeline with proper logging
"""
import os
import sys
import logging
from datetime import datetime
import argparse
from pipeline import run_pipeline, run_ingestion_only
import shutil

def setup_logging(log_level='INFO', log_to_file=True):
    """
    Set up logging with both console and file output
    """
    # Create logs directory if it doesn't exist
    logs_dir = 'logs'
    os.makedirs(logs_dir, exist_ok=True)
    
    # Set up logging level
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Set up root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(numeric_level)
    root_logger.addHandler(console_handler)
    
    # File handler (if enabled)
    if log_to_file:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_filename = os.path.join(logs_dir, f'pipeline_{timestamp}.log')
        
        file_handler = logging.FileHandler(log_filename)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        root_logger.addHandler(file_handler)
        
        print(f"📁 Logs will be saved to: {log_filename}")
        
        # Copy the latest log file instead of using a symlink
        latest_log = os.path.join(logs_dir, 'latest.log')
        shutil.copyfile(log_filename, latest_log)
        print(f"📁 Latest log available at: {latest_log}")
    
    return root_logger

def main():
    """Main entry point for pipeline execution"""
    parser = argparse.ArgumentParser(description='Run Threat Intelligence Pipeline')
    parser.add_argument('--mode', choices=['full', 'ingestion'], default='full',
                       help='Pipeline mode: full (default) or ingestion only')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       default='INFO', help='Logging level (default: INFO)')
    parser.add_argument('--no-file-log', action='store_true',
                       help='Disable logging to file (console only)')
    parser.add_argument('--quiet', action='store_true',
                       help='Reduce console output (equivalent to --log-level WARNING)')
    
    args = parser.parse_args()
    
    # Adjust log level for quiet mode
    if args.quiet:
        args.log_level = 'WARNING'
    
    try:
        # Set up logging
        logger = setup_logging(
            log_level=args.log_level, 
            log_to_file=not args.no_file_log
        )
        
        print("🚀 Starting Threat Intelligence Pipeline")
        print(f"📋 Mode: {args.mode}")
        print(f"📊 Log Level: {args.log_level}")
        print("-" * 50)
        
        start_time = datetime.now()
        
        # Run pipeline based on mode
        if args.mode == 'full':
            result = run_pipeline()
        else:
            result = run_ingestion_only()
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Print results
        print("-" * 50)
        if result['success']:
            print("✅ Pipeline completed successfully!")
            if 'processed_count' in result:
                print(f"📊 Processed {result['processed_count']} IOCs")
            if 'raw_iocs_count' in result:
                print(f"📊 Ingested {result['raw_iocs_count']} raw IOCs")
            print(f"⏱️  Total time: {duration:.2f} seconds")
        else:
            print("❌ Pipeline failed!")
            print(f"💥 Error: {result.get('error', 'Unknown error')}")
            sys.exit(1)
        
        # Show where data is stored
        print(f"💾 Data saved to: data/processed_iocs.json")
        if not args.no_file_log:
            print(f"📝 Logs saved to: logs/latest.log")
        
    except KeyboardInterrupt:
        print("\n⚠️  Pipeline interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"💥 Unexpected error: {str(e)}")
        try:
            logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        except:
            pass  # Logger might not be initialized yet
        sys.exit(1)

if __name__ == '__main__':
    main()