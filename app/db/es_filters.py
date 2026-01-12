from typing import List, Optional, Dict, Any

def build_organization_filter(
    organizations: Optional[List[str]],
) -> List[Dict[str, Any]]:
    if not organizations:
        return []

    cleaned = [o.strip() for o in organizations if str(o).strip()]
    if not cleaned:
        return []

    return [{"terms": {"OrganizationMaskEn.keyword": cleaned}}]
