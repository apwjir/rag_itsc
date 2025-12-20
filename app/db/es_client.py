from elasticsearch import Elasticsearch
import os

ES_URL = os.getenv("ES_URL", "http://localhost:9200")
INDEX_NAME = os.getenv("ES_INDEX", "cmu-incidents-fastapi")

es = Elasticsearch(ES_URL)
