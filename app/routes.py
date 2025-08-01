"""
Flask routes for threat intelligence API
"""
from flask import Blueprint, jsonify, request, render_template
import logging
from app.utils import load_iocs, filter_iocs
from pipeline import run_pipeline

main = Blueprint('main', __name__)
logger = logging.getLogger(__name__)

@main.route('/iocs', methods=['GET'])
def get_iocs():
    """
    GET /iocs - Return all IOCs with optional filtering
    Query parameters:
    - type: filter by IOC type (ip, url)
    - source: filter by source (blocklist, spamhaus, digitalside)
    """
    try:
        # Load all IOCs
        iocs = load_iocs()
        
        # Apply filters if provided
        ioc_type = request.args.get('type')
        source = request.args.get('source')
        
        if ioc_type or source:
            iocs = filter_iocs(iocs, ioc_type=ioc_type, source=source)
        
        return jsonify({
            'success': True,
            'count': len(iocs),
            'data': iocs
        })
    
    except Exception as e:
        logger.error(f"Error retrieving IOCs: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve IOCs'
        }), 500

@main.route('/refresh', methods=['POST'])
def refresh_iocs():
    """
    POST /refresh - Trigger ingestion and enrichment pipeline
    """
    try:
        logger.info("Starting IOC refresh pipeline...")
        
        # Run the full pipeline
        result = run_pipeline()
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'IOCs refreshed successfully',
                'processed_count': result.get('processed_count', 0)
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Pipeline failed')
            }), 500
    
    except Exception as e:
        logger.error(f"Error refreshing IOCs: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to refresh IOCs'
        }), 500

@main.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'threat-intel-api'
    })

@main.route('/', methods=['GET'])
def dashboard():
    """Web dashboard for threat intelligence"""
    return render_template('index.html')

@main.route('/api/stats', methods=['GET'])
def api_stats():
    """Get API statistics"""
    try:
        iocs = load_iocs()
        
        # Calculate statistics
        stats = {
            'total_iocs': len(iocs),
            'by_type': {},
            'by_source': {},
            'by_confidence': {
                'high': 0,  # > 0.8
                'medium': 0,  # 0.5 - 0.8
                'low': 0    # < 0.5
            }
        }
        
        for ioc in iocs:
            # Type statistics
            ioc_type = ioc.get('type', 'unknown')
            stats['by_type'][ioc_type] = stats['by_type'].get(ioc_type, 0) + 1
            
            # Source statistics
            source = ioc.get('source', 'unknown')
            stats['by_source'][source] = stats['by_source'].get(source, 0) + 1
            
            # Confidence statistics
            confidence = float(ioc.get('confidence', 0))
            if confidence > 0.8:
                stats['by_confidence']['high'] += 1
            elif confidence >= 0.5:
                stats['by_confidence']['medium'] += 1
            else:
                stats['by_confidence']['low'] += 1
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Error retrieving statistics: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve statistics'
        }), 500
