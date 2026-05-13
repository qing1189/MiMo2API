"""用量统计持久化存储（JSON 文件）。

支持 3 个维度：
  - 按模型 (model)
  - 按 MiMo 账号 (account: user_id)
  - 按 API Key (api_key, 存储时做脱敏 mask)
每个维度都提供 今日 / 本周（最近 7 天） / 全部 汇总。

持久化结构（v2）：
{
  "schema": 2,
  "total": { prompt_tokens, completion_tokens, total_tokens, requests },
  "models":   { "<model>":    { ...count } },
  "accounts": { "<user_id>":  { ...count } },
  "api_keys": { "<masked>":   { ...count } },
  "daily": {
    "YYYY-MM-DD": {
      "models":   { "<model>":   { ...count } },
      "accounts": { "<user_id>": { ...count } },
      "api_keys": { "<masked>":  { ...count } }
    }
  }
}

向后兼容：仍从旧格式（无 schema 字段、只有 models/total/daily[date][model]）加载；
首次 add_usage 会自动升级。
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

_USAGE_FILE = Path(__file__).parent.parent / "usage.json"
_LOCK = threading.Lock()
_SCHEMA = 2

_DIMENSIONS = ("models", "accounts", "api_keys")


# ─── 工具函数 ────────────────────────────────────────────────

def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _zero_count() -> dict:
    return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "requests": 0}


def _empty_state() -> dict:
    return {
        "schema": _SCHEMA,
        "total": _zero_count(),
        "models": {},
        "accounts": {},
        "api_keys": {},
        "daily": {},
    }


def _mask_api_key(raw: Optional[str]) -> Optional[str]:
    """对 API Key 做脱敏：只保留前 6 + 后 4，中间 ***。"""
    if not raw:
        return None
    key = raw.replace("Bearer ", "").strip()
    if not key:
        return None
    if len(key) <= 12:
        return key[:3] + "***"
    return key[:6] + "***" + key[-4:]


def _migrate_if_needed(data: dict) -> dict:
    """把旧版格式迁移到 v2 结构。"""
    if data.get("schema") == _SCHEMA:
        # 保证所有键都存在
        for d in _DIMENSIONS:
            data.setdefault(d, {})
        data.setdefault("total", _zero_count())
        data.setdefault("daily", {})
        return data

    # 旧版：{"models": {...}, "total": {...}, "daily": {date: {model: {...}}}}
    migrated = _empty_state()
    migrated["total"] = dict(data.get("total") or _zero_count())
    migrated["models"] = dict(data.get("models") or {})
    # 按日迁移：旧日维度直接当模型维度
    for day, payload in (data.get("daily") or {}).items():
        if not isinstance(payload, dict):
            continue
        migrated["daily"][day] = {
            "models": dict(payload),
            "accounts": {},
            "api_keys": {},
        }
    return migrated


def _load() -> dict:
    if not _USAGE_FILE.exists():
        return _empty_state()
    try:
        with open(_USAGE_FILE, "r") as f:
            data = json.load(f)
        return _migrate_if_needed(data)
    except Exception:
        return _empty_state()


def _save(data: dict):
    tmp = _USAGE_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    tmp.replace(_USAGE_FILE)


def _bump(counter: dict, prompt_tokens: int, completion_tokens: int):
    counter["prompt_tokens"] += prompt_tokens
    counter["completion_tokens"] += completion_tokens
    counter["total_tokens"] += prompt_tokens + completion_tokens
    counter["requests"] += 1


def _ensure(d: dict, key: str) -> dict:
    if key not in d:
        d[key] = _zero_count()
    return d[key]


# ─── 写入 ────────────────────────────────────────────────────

def add_usage(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    account_id: Optional[str] = None,
    api_key: Optional[str] = None,
):
    """累加一次用量到三个维度（线程安全）。

    Args:
        model: 模型名
        prompt_tokens / completion_tokens: token 数
        account_id: MiMo 账号 user_id（可选，None 时不计入"账号"维度）
        api_key: 原始 API Key 字符串（可选，内部会脱敏后存储）
    """
    with _LOCK:
        data = _load()
        day = _today()

        model = model or "unknown"
        masked_key = _mask_api_key(api_key)

        # 1) 全局
        _bump(data["total"], prompt_tokens, completion_tokens)

        # 2) 按维度（累计）
        _bump(_ensure(data["models"], model), prompt_tokens, completion_tokens)
        if account_id:
            _bump(_ensure(data["accounts"], account_id), prompt_tokens, completion_tokens)
        if masked_key:
            _bump(_ensure(data["api_keys"], masked_key), prompt_tokens, completion_tokens)

        # 3) 按日 × 维度
        daily = data["daily"]
        if day not in daily:
            daily[day] = {"models": {}, "accounts": {}, "api_keys": {}}
        day_data = daily[day]
        for dim in _DIMENSIONS:
            day_data.setdefault(dim, {})
        _bump(_ensure(day_data["models"], model), prompt_tokens, completion_tokens)
        if account_id:
            _bump(_ensure(day_data["accounts"], account_id), prompt_tokens, completion_tokens)
        if masked_key:
            _bump(_ensure(day_data["api_keys"], masked_key), prompt_tokens, completion_tokens)

        _save(data)


# ─── 读取 ────────────────────────────────────────────────────

def _merge(dest: dict, src: dict):
    """把 src 的计数合并到 dest（原地）。"""
    for key, counts in (src or {}).items():
        if not isinstance(counts, dict):
            continue
        tgt = _ensure(dest, key)
        for k in ("prompt_tokens", "completion_tokens", "total_tokens", "requests"):
            tgt[k] += int(counts.get(k, 0) or 0)


def _sum_counters(d: dict) -> dict:
    total = _zero_count()
    for counts in (d or {}).values():
        for k in ("prompt_tokens", "completion_tokens", "total_tokens", "requests"):
            total[k] += int(counts.get(k, 0) or 0)
    return total


def _aggregate_period(data: dict, start: Optional[str]) -> dict:
    """聚合从 start（含）到今天的日维度数据；start=None 表示全部（用 lifetime）。"""
    result = {"models": {}, "accounts": {}, "api_keys": {}}
    if start is None:
        # lifetime 用顶层累计即可
        return {
            "models": dict(data.get("models") or {}),
            "accounts": dict(data.get("accounts") or {}),
            "api_keys": dict(data.get("api_keys") or {}),
        }
    for day, payload in (data.get("daily") or {}).items():
        if day < start:
            continue
        for dim in _DIMENSIONS:
            _merge(result[dim], (payload or {}).get(dim) or {})
    return result


def _period_bundle(agg: dict) -> dict:
    """把一个已聚合的 {models, accounts, api_keys} 变成 UI 友好结构，
    每个维度都附带 total 合计（用 models 的合计作为权威 total）。"""
    total = _sum_counters(agg.get("models") or {})
    return {
        "models":   {"items": agg.get("models") or {},   "total": total},
        "accounts": {"items": agg.get("accounts") or {}, "total": _sum_counters(agg.get("accounts") or {})},
        "api_keys": {"items": agg.get("api_keys") or {}, "total": _sum_counters(agg.get("api_keys") or {})},
        # 兼容旧前端：保留扁平 models / total
        "total": total,
    }


def get_usage() -> dict:
    """返回用量统计。

    结构：
    {
      "today" / "week" / "total": {
          "models":   { "items": {<model>: counts}, "total": counts },
          "accounts": { "items": {<user_id>: counts}, "total": counts },
          "api_keys": { "items": {<masked>: counts}, "total": counts },
          "total":    counts   # 兼容字段 = models.total
      }
    }
    """
    data = _load()
    today = _today()
    # 最近 7 天（含今天）
    week_start = (datetime.now(timezone.utc) - timedelta(days=6)).strftime("%Y-%m-%d")

    today_agg = _aggregate_period(data, start=today)
    week_agg = _aggregate_period(data, start=week_start)
    total_agg = _aggregate_period(data, start=None)

    return {
        "today":  _period_bundle(today_agg),
        "week":   _period_bundle(week_agg),
        "total":  _period_bundle(total_agg),
    }


def clear_usage():
    """清空全部用量统计数据。"""
    with _LOCK:
        _save(_empty_state())
