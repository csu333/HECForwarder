#!/usr/bin/env python3
"""
Splunk HTTP Event Collector Emulator
Caches incoming requests and forwards them to Splunk indexers when available.
Stores cache on disk to prevent data loss.
"""

import json
import os
import time
import threading
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass, asdict
from queue import Queue, Empty
import requests
from flask import Flask, request, jsonify
import sqlite3
import hashlib
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class CachedEvent:
    """Represents a cached event"""
    id: str
    timestamp: float
    token: str
    data: str
    source_ip: str
    headers: Dict[str, str]
    retry_count: int = 0
    last_retry: Optional[float] = None

@dataclass
class IndexerConfig:
    """Splunk indexer configuration"""
    url: str
    token: str
    enabled: bool = True
    max_retries: int = 3
    timeout: int = 30

class DiskCache:
    """Disk-based cache using SQLite for persistence"""
    
    def __init__(self, cache_dir: str = "./hec_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.db_path = self.cache_dir / "events.db"
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp REAL,
                token TEXT,
                data TEXT,
                source_ip TEXT,
                headers TEXT,
                retry_count INTEGER DEFAULT 0,
                last_retry REAL
            )
        ''')
        conn.commit()
        conn.close()
    
    def add_event(self, event: CachedEvent):
        """Add event to cache"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            INSERT OR REPLACE INTO events 
            (id, timestamp, token, data, source_ip, headers, retry_count, last_retry)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.id, event.timestamp, event.token, event.data,
            event.source_ip, json.dumps(event.headers),
            event.retry_count, event.last_retry
        ))
        conn.commit()
        conn.close()
    
    def get_pending_events(self, limit: int = 100) -> List[CachedEvent]:
        """Get pending events from cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute('''
            SELECT id, timestamp, token, data, source_ip, headers, retry_count, last_retry
            FROM events 
            ORDER BY timestamp ASC 
            LIMIT ?
        ''', (limit,))
        
        events = []
        for row in cursor.fetchall():
            events.append(CachedEvent(
                id=row[0],
                timestamp=row[1],
                token=row[2],
                data=row[3],
                source_ip=row[4],
                headers=json.loads(row[5]),
                retry_count=row[6],
                last_retry=row[7]
            ))
        
        conn.close()
        return events
    
    def remove_event(self, event_id: str):
        """Remove event from cache"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('DELETE FROM events WHERE id = ?', (event_id,))
        conn.commit()
        conn.close()
    
    def update_retry_count(self, event_id: str, retry_count: int):
        """Update retry count for an event"""
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            UPDATE events 
            SET retry_count = ?, last_retry = ? 
            WHERE id = ?
        ''', (retry_count, time.time(), event_id))
        conn.commit()
        conn.close()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute('SELECT COUNT(*) FROM events')
        total_events = cursor.fetchone()[0]
        
        cursor = conn.execute('SELECT COUNT(*) FROM events WHERE retry_count > 0')
        failed_events = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_events': total_events,
            'failed_events': failed_events,
            'cache_size_mb': self.db_path.stat().st_size / (1024 * 1024)
        }

class SplunkForwarder:
    """Handles forwarding cached events to Splunk indexers"""
    
    def __init__(self, indexers: List[IndexerConfig], cache: DiskCache):
        self.indexers = indexers
        self.cache = cache
        self.running = False
        self.worker_thread = None
        self.session = requests.Session()
        
    def start(self):
        """Start the forwarder worker thread"""
        if not self.running:
            self.running = True
            self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
            self.worker_thread.start()
            logger.info("Splunk forwarder started")
    
    def stop(self):
        """Stop the forwarder worker thread"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        logger.info("Splunk forwarder stopped")
    
    def _worker_loop(self):
        """Main worker loop for processing cached events"""
        while self.running:
            try:
                events = self.cache.get_pending_events(limit=50)
                if not events:
                    time.sleep(5)  # Wait before checking again
                    continue
                
                for event in events:
                    if not self.running:
                        break
                    
                    success = self._forward_event(event)
                    if success:
                        self.cache.remove_event(event.id)
                        logger.info(f"Successfully forwarded event {event.id}")
                    else:
                        # Update retry count
                        event.retry_count += 1
                        if event.retry_count >= 5:  # Max retries
                            logger.error(f"Event {event.id} exceeded max retries, removing")
                            self.cache.remove_event(event.id)
                        else:
                            self.cache.update_retry_count(event.id, event.retry_count)
                            logger.warning(f"Failed to forward event {event.id}, retry count: {event.retry_count}")
                
                time.sleep(2)  # Brief pause between batches
                
            except Exception as e:
                logger.error(f"Error in forwarder worker loop: {e}")
                time.sleep(10)
    
    def _forward_event(self, event: CachedEvent) -> bool:
        """Forward a single event to available indexers"""
        for indexer in self.indexers:
            if not indexer.enabled:
                continue
            
            try:
                # Prepare the request
                headers = {
                    'Authorization': f'Splunk {indexer.token}',
                    'Content-Type': 'application/json'
                }
                
                # Parse the original event data
                event_data = json.loads(event.data)
                
                # Send to Splunk HEC endpoint
                response = self.session.post(
                    f"{indexer.url}/services/collector/event",
                    headers=headers,
                    data=event.data,
                    timeout=indexer.timeout
                )
                
                if response.status_code == 200:
                    return True
                else:
                    logger.warning(f"Indexer {indexer.url} returned status {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.warning(f"Failed to connect to indexer {indexer.url}: {e}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error forwarding to {indexer.url}: {e}")
                continue
        
        return False

class HTTPEventCollector:
    """Main HTTP Event Collector emulator"""
    
    def __init__(self, config_file: str = "hec_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        self.cache = DiskCache(self.config.get('cache_dir', './hec_cache'))
        self.forwarder = SplunkForwarder(self._load_indexers(), self.cache)
        self.app = Flask(__name__)
        self._setup_routes()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            'port': 8088,
            'host': '0.0.0.0',
            'valid_tokens': ['default-token'],
            'cache_dir': './hec_cache',
            'indexers': [
                {
                    'url': 'https://splunk-indexer:8088',
                    'token': 'your-splunk-token',
                    'enabled': True
                }
            ]
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    default_config.update(config)
            else:
                # Create default config file
                with open(self.config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
                logger.info(f"Created default config file: {self.config_file}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
        
        return default_config
    
    def _load_indexers(self) -> List[IndexerConfig]:
        """Load indexer configurations"""
        indexers = []
        for idx_config in self.config.get('indexers', []):
            indexers.append(IndexerConfig(
                url=idx_config['url'],
                token=idx_config['token'],
                enabled=idx_config.get('enabled', True),
                max_retries=idx_config.get('max_retries', 3),
                timeout=idx_config.get('timeout', 30)
            ))
        return indexers
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/services/collector/event', methods=['POST'])
        def collect_event():
            return self._handle_event_collection()
        
        @self.app.route('/services/collector/event/1.0', methods=['POST'])
        def collect_event_v1():
            return self._handle_event_collection()
        
        @self.app.route('/services/collector/health', methods=['GET'])
        def health_check():
            return jsonify({'status': 'healthy', 'cache_stats': self.cache.get_cache_stats()})
        
        @self.app.route('/services/collector/stats', methods=['GET'])
        def get_stats():
            return jsonify({
                'cache_stats': self.cache.get_cache_stats(),
                'indexers': [{'url': idx.url, 'enabled': idx.enabled} for idx in self.forwarder.indexers]
            })
    
    def _handle_event_collection(self):
        """Handle incoming event collection requests"""
        try:
            # Validate authorization
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Splunk '):
                return jsonify({'text': 'Invalid authorization', 'code': 2}), 401
            
            token = auth_header[7:]  # Remove 'Splunk ' prefix
            if token not in self.config['valid_tokens']:
                return jsonify({'text': 'Invalid token', 'code': 3}), 401
            
            # Get request data
            if request.content_type == 'application/json':
                data = request.get_data(as_text=True)
            else:
                return jsonify({'text': 'Invalid content type', 'code': 5}), 400
            
            # Validate JSON
            try:
                json.loads(data)
            except json.JSONDecodeError:
                return jsonify({'text': 'Invalid JSON', 'code': 6}), 400
            
            # Create cached event
            event = CachedEvent(
                id=str(uuid.uuid4()),
                timestamp=time.time(),
                token=token,
                data=data,
                source_ip=request.remote_addr,
                headers=dict(request.headers)
            )
            
            # Cache the event
            self.cache.add_event(event)
            logger.info(f"Cached event {event.id} from {event.source_ip}")
            
            return jsonify({'text': 'Success', 'code': 0}), 200
            
        except Exception as e:
            logger.error(f"Error handling event collection: {e}")
            return jsonify({'text': 'Server error', 'code': 8}), 500
    
    def run(self):
        """Start the HTTP Event Collector"""
        try:
            # Start the forwarder
            self.forwarder.start()
            
            # Start the Flask app
            logger.info(f"Starting HTTP Event Collector on {self.config['host']}:{self.config['port']}")
            self.app.run(
                host=self.config['host'],
                port=self.config['port'],
                debug=False,
                threaded=True
            )
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            self.forwarder.stop()

if __name__ == '__main__':
    # Example usage
    collector = HTTPEventCollector()
    collector.run()
