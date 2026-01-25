from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

DATE_FORMATS = [
    "%Y-%m-%d",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y",
    "%m/%d/%Y %H:%M:%S",
]

def build_organization_filter(
    organizations: Optional[List[str]],
) -> List[Dict[str, Any]]:
    if not organizations:
        return []

    cleaned = [o.strip() for o in organizations if str(o).strip()]
    if not cleaned:
        return []

    return [{"terms": {"OrganizationMaskEn.keyword": cleaned}}]

def normalize_date(
    value: Optional[str],
    *,
    end_of_day: bool = False,
    allow_now_if_missing: bool = False, 
) -> Optional[str]:
    if not value:
        if allow_now_if_missing:
            return datetime.now(timezone.utc).isoformat()
        return None  

    value = str(value).strip()

    for fmt in DATE_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)

            if end_of_day:
                dt = dt.replace(hour=23, minute=59, second=59)
            else:
                dt = dt.replace(hour=0, minute=0, second=0)

            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue

    raise ValueError(f"Unsupported date format: {value}")
