from datetime import datetime, timedelta

from app.db.es_client import es, INDEX_NAME
from langchain.tools import tool

# @tool(description="Calculate top weighted risks")
async def calculate_top_weighted_risks(limit: int = None):
    es_size = limit if limit is not None else 1000 

    # Only consider logs from the past 1 year (matches AI suggestion scope)
    one_year_ago = (datetime.now() - timedelta(days=365)).isoformat()

    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"CreateDate": {"gte": one_year_ago}}}
                ]
            }
        },
        "aggs": {
            "categories": {
                "terms": {
                    "field": "CategoryEN.keyword",
                    "size": es_size,
                    "order": { "total_risk_sum": "desc" }
                },
                "aggs": {
                    "total_risk_sum": {
                        "sum": {
                            "script": {
                                "source": """
                                    if (doc['PiorityEN.keyword'].size() == 0) return 1;
                                    def p = doc['PiorityEN.keyword'].value;
                                    if (p.startsWith('Critical')) return 5;
                                    if (p.startsWith('High')) return 4;
                                    if (p.startsWith('Medium')) return 3;
                                    if (p.startsWith('Low')) return 2;
                                    return 1;
                                """
                            }
                        }
                    }
                }
            }
        }
    }

    res = es.search(index=INDEX_NAME, body=body)
    buckets = res["aggregations"]["categories"]["buckets"]

    processed_data = []
    for b in buckets:
        processed_data.append({
            "category": b["key"],
            "incident_count": b["doc_count"],
            "risk_score": b["total_risk_sum"]["value"]
        })

    return processed_data[:limit] if limit else processed_data