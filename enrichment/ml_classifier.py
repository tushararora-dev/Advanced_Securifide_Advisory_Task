"""
ML-based URL classifier using keyword heuristics and simple scoring
"""
import logging
import re
from typing import Dict, List, Tuple
from collections import Counter

logger = logging.getLogger(__name__)

# Malicious keyword patterns and their weights
MALICIOUS_KEYWORDS = {
    'high_risk': {
        'keywords': ['malware', 'virus', 'trojan', 'ransomware', 'backdoor', 'keylogger', 'spyware'],
        'weight': 0.8
    },
    'suspicious_actions': {
        'keywords': ['download', 'install', 'update', 'crack', 'keygen', 'activator', 'loader'],
        'weight': 0.6
    },
    'social_engineering': {
        'keywords': ['urgent', 'immediate', 'click', 'verify', 'confirm', 'expire', 'suspend'],
        'weight': 0.5
    },
    'file_types': {
        'keywords': ['exe', 'zip', 'rar', 'bat', 'scr', 'jar', 'msi'],
        'weight': 0.4
    },
    'suspicious_domains': {
        'keywords': ['temp', 'test', 'admin', 'root', 'user', 'guest', 'anonymous'],
        'weight': 0.3
    }
}

BENIGN_KEYWORDS = {
    'legitimate_sites': {
        'keywords': ['github', 'microsoft', 'google', 'amazon', 'apple', 'facebook'],
        'weight': -0.5
    },
    'documentation': {
        'keywords': ['docs', 'help', 'support', 'manual', 'guide', 'tutorial'],
        'weight': -0.2
    }
}

class URLClassifier:
    """Simple ML-inspired URL classifier using keyword heuristics"""
    
    def __init__(self):
        self.malicious_patterns = self._compile_patterns(MALICIOUS_KEYWORDS)
        self.benign_patterns = self._compile_patterns(BENIGN_KEYWORDS)
    
    def _compile_patterns(self, keyword_dict: Dict) -> List[Tuple[re.Pattern, float]]:
        """Compile keyword patterns with their weights"""
        patterns = []
        
        for category, data in keyword_dict.items():
            for keyword in data['keywords']:
                pattern = re.compile(rf'\b{re.escape(keyword)}\b', re.IGNORECASE)
                patterns.append((pattern, data['weight']))
        
        return patterns
    
    def classify_url(self, url: str) -> Dict:
        """
        Classify a URL as suspicious or benign
        
        Args:
            url: URL to classify
        
        Returns:
            Classification result dictionary
        """
        try:
            # Calculate malicious score
            malicious_score = self._calculate_score(url, self.malicious_patterns)
            
            # Calculate benign score
            benign_score = self._calculate_score(url, self.benign_patterns)
            
            # Combined score
            total_score = malicious_score + benign_score
            
            # Normalize to 0-1 range
            probability = max(0, min(1, (total_score + 1) / 2))
            
            # Classify based on threshold
            is_suspicious = probability > 0.5
            
            # Get matched features
            features = self._extract_features(url)
            
            return {
                'is_suspicious': is_suspicious,
                'probability': probability,
                'malicious_score': malicious_score,
                'benign_score': benign_score,
                'features': features,
                'classification': 'suspicious' if is_suspicious else 'benign'
            }
        
        except Exception as e:
            logger.error(f"Error classifying URL {url}: {str(e)}")
            return {
                'is_suspicious': False,
                'probability': 0.5,
                'error': str(e),
                'classification': 'unknown'
            }
    
    def _calculate_score(self, url: str, patterns: List[Tuple[re.Pattern, float]]) -> float:
        """Calculate score based on pattern matches"""
        score = 0.0
        
        for pattern, weight in patterns:
            matches = len(pattern.findall(url))
            if matches > 0:
                # Diminishing returns for multiple matches of same pattern
                score += weight * min(matches, 3) / 3
        
        return score
    
    def _extract_features(self, url: str) -> Dict:
        """Extract features used in classification"""
        features = {
            'length': len(url),
            'suspicious_keywords': [],
            'benign_keywords': [],
            'special_chars': self._count_special_chars(url),
            'domain_characteristics': self._analyze_domain(url)
        }
        
        # Find matched keywords
        for pattern, weight in self.malicious_patterns:
            matches = pattern.findall(url)
            if matches:
                features['suspicious_keywords'].extend(matches)
        
        for pattern, weight in self.benign_patterns:
            matches = pattern.findall(url)
            if matches:
                features['benign_keywords'].extend(matches)
        
        return features
    
    def _count_special_chars(self, url: str) -> Dict:
        """Count special characters in URL"""
        special_chars = ['-', '_', '/', '?', '=', '&', '%', '@']
        counts = {}
        
        for char in special_chars:
            counts[char] = url.count(char)
        
        return counts
    
    def _analyze_domain(self, url: str) -> Dict:
        """Analyze domain characteristics"""
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            return {
                'length': len(domain),
                'has_subdomain': domain.count('.') > 1,
                'has_port': parsed.port is not None,
                'is_ip': re.match(r'^[0-9.]+$', domain) is not None,
                'tld': domain.split('.')[-1] if '.' in domain else None
            }
        
        except Exception:
            return {'error': 'Failed to parse domain'}

def classify_url_iocs(iocs: List[Dict]) -> List[Dict]:
    """
    Apply ML classification to URL IOCs
    
    Args:
        iocs: List of IOCs to classify
    
    Returns:
        List of IOCs with ML classification results
    """
    classifier = URLClassifier()
    classified = []
    
    url_count = 0
    for ioc in iocs:
        if ioc['type'] == 'url':
            url_count += 1
            
            # Perform classification
            classification = classifier.classify_url(ioc['value'])
            
            # Add classification to enrichment data
            if 'enrichment' not in ioc:
                ioc['enrichment'] = {}
            
            ioc['enrichment']['ml_classification'] = classification
            
            # Update confidence based on ML results
            if classification['is_suspicious']:
                # Boost confidence for URLs classified as suspicious
                ml_boost = classification['probability'] * 0.2
                ioc['confidence'] = min(1.0, ioc.get('confidence', 0.5) + ml_boost)
        
        classified.append(ioc)
    
    logger.info(f"ML classification applied to {url_count} URLs")
    return classified

def train_simple_model(training_urls: List[Tuple[str, bool]]) -> Dict:
    """
    Train a simple keyword-based model from labeled URLs
    
    Args:
        training_urls: List of (url, is_malicious) tuples
    
    Returns:
        Training statistics
    """
    malicious_urls = [url for url, is_mal in training_urls if is_mal]
    benign_urls = [url for url, is_mal in training_urls if not is_mal]
    
    # Extract keywords from malicious URLs
    malicious_keywords = Counter()
    for url in malicious_urls:
        words = re.findall(r'\b\w+\b', url.lower())
        malicious_keywords.update(words)
    
    # Extract keywords from benign URLs
    benign_keywords = Counter()
    for url in benign_urls:
        words = re.findall(r'\b\w+\b', url.lower())
        benign_keywords.update(words)
    
    # Calculate keyword importance
    keyword_scores = {}
    for keyword in set(malicious_keywords.keys()) | set(benign_keywords.keys()):
        mal_freq = malicious_keywords.get(keyword, 0)
        ben_freq = benign_keywords.get(keyword, 0)
        
        # Simple scoring: ratio of malicious to benign frequency
        if ben_freq == 0:
            score = mal_freq
        else:
            score = mal_freq / ben_freq
        
        keyword_scores[keyword] = score
    
    return {
        'total_urls': len(training_urls),
        'malicious_count': len(malicious_urls),
        'benign_count': len(benign_urls),
        'top_malicious_keywords': malicious_keywords.most_common(20),
        'top_benign_keywords': benign_keywords.most_common(20),
        'keyword_scores': dict(sorted(keyword_scores.items(), 
                                    key=lambda x: x[1], reverse=True)[:50])
    }
