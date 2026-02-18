from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, date, timedelta

BANGKOK_TZ = timezone(timedelta(hours=7))

DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%S%z",   # ISO 8601 with timezone
    "%Y-%m-%dT%H:%M:%S",     # ISO 8601 without timezone
    "%Y-%m-%d %H:%M:%S%z",   # Space separator with timezone (pandas XLSX)
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
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
    keep_time: bool = True,
) -> Optional[str]:
    if not value:
        if allow_now_if_missing:
            return datetime.now(timezone.utc).isoformat()
        return None  

    value = str(value).strip()

    for fmt in DATE_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)

            has_time_info = "%H" in fmt or "%I" in fmt
            
            if has_time_info and keep_time:
                pass
            elif end_of_day:
                dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
            else:
                dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)

            # If naive (no timezone), assume Bangkok (+07:00)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=BANGKOK_TZ)
            return dt.astimezone(BANGKOK_TZ).isoformat()
        except ValueError:
            continue

    # Fallback: try fromisoformat for edge cases
    try:
        dt = datetime.fromisoformat(value)
        if keep_time:
            pass  # preserve original time
        elif end_of_day:
            dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
        else:
            dt = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=BANGKOK_TZ)
        return dt.astimezone(BANGKOK_TZ).isoformat()
    except ValueError:
        pass

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