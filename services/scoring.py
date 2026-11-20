from __future__ import annotations
from datetime import datetime, timezone
LEVELS = [(0,"CLEAN"),(16,"LOW"),(31,"MEDIUM"),(51,"HIGH"),(76,"CRITICAL")]

def classify_score(score: int) -> str:
    score=max(0,min(100,int(score))); level="CLEAN"
    for threshold,name in LEVELS:
        if score>=threshold: level=name
    return level

def calculate_score(malicious=0,suspicious=0,misp_match=False,malwarebazaar_match=False,recent=False,known_family=False,multi_source=False,behavior_score=0):
    score=min(int(malicious)*5,35)+min(int(suspicious)*2,10)
    score += 20 if misp_match else 0
    score += 30 if malwarebazaar_match else 0
    score += 10 if recent else 0
    score += 15 if known_family else 0
    score += 15 if multi_source else 0
    score += min(int(behavior_score),30)
    return min(score,100)

def is_recent(value,hours=72):
    if not value:return False
    if value.tzinfo is None:value=value.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc)-value).total_seconds()<=hours*3600
