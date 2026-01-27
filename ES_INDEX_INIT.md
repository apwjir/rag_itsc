# Elasticsearch Index Management Guide

## Problem
You removed the Elasticsearch index and need to reinitialize it with proper field type mappings to avoid dynamic mapping issues.

## Solution

### 1. Initialize the Index

Run the initialization script to create the index with proper field type mappings:

```bash
python init_es_index.py
```

This will create the index `cmu-incidents-fastapi` (or whatever is set in your `.env` file as `ES_INDEX`) with explicit field type mappings.

### 2. Recreate Index (if it already exists)

If the index already exists and you want to delete and recreate it with the new mappings:

```bash
python init_es_index.py --delete-existing
```

⚠️ **Warning**: This will delete all existing data in the index!

### 3. View Current Mapping

To see the current index mapping without making changes:

```bash
python init_es_index.py --show-mapping
```

## Key Field Type Mappings

The script sets explicit types for important fields:

- **Numeric fields**: `IncidentsId` (long), `PiorityId` (integer), `risk_score` (float)
- **Date fields**: `CreateDate`, `ingested_at`, `ai_generated_at` (all as date type)
- **Keyword fields**: `ai_status`, `TicketId.keyword`, category and priority keywords
- **Nested objects**: `ai_analysis`, `soc_action` with their sub-fields properly typed

## Workflow

1. **Stop your application** (if running)
2. **Delete the old index** (if needed): 
   ```bash
   python init_es_index.py --delete-existing
   ```
3. **Verify index creation**:
   ```bash
   python init_es_index.py --show-mapping
   ```
4. **Start your application** and upload data via `/upload-log/` endpoint

## Customizing Field Types

To modify field types, edit the `INDEX_MAPPING` dictionary in `init_es_index.py`:

```python
INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "your_field_name": {"type": "your_desired_type"},
            # ... more fields
        }
    }
}
```

Common Elasticsearch field types:
- `text`: Full-text searchable
- `keyword`: Exact match, aggregations, sorting
- `long`, `integer`, `short`, `byte`: Numeric types
- `float`, `double`: Floating-point numbers
- `date`: Date/datetime values
- `boolean`: true/false
- `object`: JSON object (not searchable as nested)
- `nested`: Array of objects (searchable individually)

## Troubleshooting

**Index already exists error**:
```bash
python init_es_index.py --delete-existing
```

**Cannot connect to Elasticsearch**:
```bash
# Make sure Docker containers are running
docker-compose up -d

# Check Elasticsearch is healthy
curl http://localhost:9200/_cluster/health
```

**Field type conflicts after upload**:
- Make sure your CSV data matches the field types in the mapping
- Check that date fields are in valid ISO format or handle in the upload code
