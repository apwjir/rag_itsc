#!/usr/bin/env python3
"""
Elasticsearch Index Initialization Script
==========================================
This script creates the Elasticsearch index with explicit field mappings
to ensure correct data types. Run this after you've deleted the index
to reinitialize it with proper field types.

Usage:
    python init_es_index.py [--delete-existing]

Options:
    --delete-existing    Delete the existing index before creating a new one
"""

import os
import sys
from dotenv import load_dotenv
from elasticsearch import Elasticsearch

# Load environment variables
load_dotenv()

ES_URL = os.getenv("ES_URL", "http://localhost:9200")
INDEX_NAME = os.getenv("ES_INDEX", "cmu-incidents-fastapi")

# Connect to Elasticsearch
es = Elasticsearch(ES_URL)


# Define the index mapping with explicit field types
INDEX_MAPPING = {
    "settings": {
        "number_of_shards": 2,
        "number_of_replicas": 1,
        "analysis": {
            "analyzer": {
                "default": {
                    "type": "standard"
                }
            }
        }
    },
    "mappings": {
        "properties": {
            # Incident Basic Info
            "IncidentsId": {"type": "long"},  # Changed to long for numeric IDs
            "TicketId": {"type": "keyword"},
            "IncidentSubject": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword", "ignore_above": 512}
                }
            },
            "IncidentMessage": {"type": "text"},
            
            # Category and Priority
            "CategoryEN": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword", "ignore_above": 256}
                }
            },
            "CategoryTH": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword", "ignore_above": 256}
                }
            },
            "PiorityId": {"type": "integer"},  # Explicitly set as integer
            "PiorityEN": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword", "ignore_above": 256}
                }
            },
            "PiorityTH": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword", "ignore_above": 256}
                }
            },
            
            # Dates - explicitly set as date type
            "CreateDate": {"type": "date"},
            "ingested_at": {"type": "date"},
            "ai_generated_at": {"type": "date"},
            
            # AI Analysis Status
            "ai_status": {
                "type": "keyword"  # pending, processing, auto_generated, failed
            },
            
            # AI Analysis Results (nested object)
            "ai_analysis": {
                "type": "object",
                "properties": {
                    "mitigation_plan": {
                        "type": "nested",
                        "properties": {
                            "method_id": {"type": "integer"},
                            "action": {"type": "text"},
                            "reason": {"type": "text"}
                        }
                    },
                    "related_threats": {
                        "type": "nested",
                        "properties": {
                            "mitre_id": {
                                "type": "keyword"
                            },
                            "name": {
                                "type": "text",
                                "fields": {
                                    "keyword": {"type": "keyword"}
                                }
                            }
                        }
                    }
                }
            },
            
            # SOC Action (nested object)
            "soc_action": {
                "type": "object",
                "properties": {
                    "selected_method_id": {"type": "integer"},
                    "selected_at": {"type": "date"},
                    "rating": {"type": "integer"},  # 1-5 rating
                    "feedback": {"type": "text"}
                }
            },
            
            # Risk Score
            "risk_score": {"type": "float"},
            
            # Additional fields (add more as needed based on your CSV structure)
            "Status": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword"}
                }
            },
            "AssignedTo": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword", "ignore_above": 256}
                }
            },
            
            # Generic uid field
            "uid": {"type": "keyword"}
        }
    }
}


def check_connection():
    """Check if Elasticsearch is reachable"""
    if not es.ping():
        print(f"❌ Cannot connect to Elasticsearch at {ES_URL}")
        print("Please make sure Elasticsearch is running (docker-compose up -d)")
        sys.exit(1)
    print(f"✅ Connected to Elasticsearch at {ES_URL}")


def delete_index():
    """Delete the existing index"""
    if es.indices.exists(index=INDEX_NAME):
        print(f"🗑️  Deleting existing index: {INDEX_NAME}")
        es.indices.delete(index=INDEX_NAME)
        print(f"✅ Index {INDEX_NAME} deleted")
    else:
        print(f"ℹ️  Index {INDEX_NAME} does not exist, skipping deletion")


def create_index():
    """Create the index with the defined mapping"""
    if es.indices.exists(index=INDEX_NAME):
        print(f"⚠️  Index {INDEX_NAME} already exists!")
        print(f"   If you want to recreate it, run with --delete-existing flag")
        sys.exit(1)
    
    print(f"📝 Creating index: {INDEX_NAME}")
    es.indices.create(index=INDEX_NAME, body=INDEX_MAPPING)
    print(f"✅ Index {INDEX_NAME} created successfully with proper mappings")


def show_mapping():
    """Display the current index mapping"""
    if es.indices.exists(index=INDEX_NAME):
        mapping = es.indices.get_mapping(index=INDEX_NAME)
        print(f"\n📋 Current mapping for {INDEX_NAME}:")
        import json
        print(json.dumps(mapping, indent=2))
    else:
        print(f"❌ Index {INDEX_NAME} does not exist")


def main():
    print("=" * 60)
    print("Elasticsearch Index Initialization")
    print("=" * 60)
    
    # Check connection
    check_connection()
    
    # Parse command line arguments
    delete_existing = "--delete-existing" in sys.argv
    show_only = "--show-mapping" in sys.argv
    
    if show_only:
        show_mapping()
        return
    
    # Delete if requested
    if delete_existing:
        delete_index()
    
    # Create index
    create_index()
    
    print("\n" + "=" * 60)
    print("✅ Initialization complete!")
    print("=" * 60)
    print(f"\nIndex Name: {INDEX_NAME}")
    print(f"Elasticsearch URL: {ES_URL}")
    print("\nYou can now upload your CSV data via the /upload-log/ endpoint")
    print("or use the --show-mapping flag to view the current mapping")


if __name__ == "__main__":
    main()
