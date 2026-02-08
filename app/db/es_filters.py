from typing import List, Optional, Dict, Any
from datetime import datetime, timezone , date

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
                dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            else:
                dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)

            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue

    raise ValueError(f"Unsupported date format: {value}")


def build_time_range_filter(
    range: str,
    from_date: str | None = None,
    to_date: str | None = None,
):
    if range == "7d":
        return {"range": {"CreateDate": {"gte": "now-7d/d", "lte": "now"}}}
    if range == "30d":
        return {"range": {"CreateDate": {"gte": "now-30d/d", "lte": "now"}}}
    if range == "custom" and from_date and to_date:
        return {
            "range": {
                "CreateDate": {
                    "gte": normalize_date(from_date),
                    "lte": normalize_date(to_date, end_of_day=True),
                }
            }
        }
    return None


def resolve_calendar_interval(
    range: str,
    from_date: str | None = None,
    to_date: str | None = None,
) -> str:
    if range in ["7d", "30d"]:
        return "day"

    if range == "custom" and from_date and to_date:
        d1 = date.fromisoformat(from_date)
        d2 = date.fromisoformat(to_date)
        days = (d2 - d1).days

        return "month" if days > 90 else "day"

    return "day"