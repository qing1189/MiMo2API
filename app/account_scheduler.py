"""MiMo 账号智能调度器。

功能：
 - 加权随机选择账号，降低风控
 - 失败自动降权 + 冷却；冷却结束后线性恢复
 - 区分失败类型（401/403 认证失败、429 限流、5xx/超时/网络错误）
 - 支持手动禁用 / 启用 / 重置
 - 向 Web UI 暴露实时状态

设计不改变现有 HTTP 流程，只是替换 get_next_account() 的选择算法，
并由 MimoClient 在每次请求完成时自动上报成功/失败。
"""

from __future__ import annotations

import random
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ─── 调优参数 ────────────────────────────────────────────────

MAX_WEIGHT = 100
MIN_WEIGHT = 1          # 最低权重（避免完全不可选）
RECOVERY_PER_MIN = 10   # 冷却结束后每分钟恢复的权重

# 不同失败类型的惩罚配置：(新权重 or None=减量, 冷却秒, 备注)
PENALTIES = {
    "auth":    {"set_weight": 10, "cooldown": 600, "desc": "auth_error"},    # 401/403
    "rate":    {"div_weight": 2,  "cooldown": 300, "desc": "rate_limited"},  # 429
    "server":  {"sub_weight": 20, "cooldown": 60,  "desc": "server_error"},  # 5xx / 网络 / 超时
    "client":  {"sub_weight": 10, "cooldown": 30,  "desc": "client_error"},  # 其他 4xx
    "unknown": {"sub_weight": 15, "cooldown": 60,  "desc": "unknown_error"},
}


# ─── 账号运行时状态 ──────────────────────────────────────────

@dataclass
class AccountStat:
    user_id: str
    weight: float = MAX_WEIGHT
    success_count: int = 0
    fail_count: int = 0
    last_success_ts: float = 0.0
    last_fail_ts: float = 0.0
    last_fail_reason: str = ""
    last_fail_status: Optional[int] = None
    penalty_until: float = 0.0     # 冷却截止时间（Unix 秒）
    last_used_ts: float = 0.0
    disabled: bool = False         # 手动禁用
    # 恢复基准时间戳：冷却结束后每分钟 RECOVERY_PER_MIN 地抬权重
    recovery_base_ts: float = 0.0
    recovery_base_weight: float = MAX_WEIGHT

    def effective_weight(self, now: float) -> float:
        """当前实际有效权重（经过恢复计算后的值）。"""
        if self.disabled:
            return 0.0
        if now < self.penalty_until:
            # 仍在冷却中，返回惩罚后的权重（但至少 MIN_WEIGHT 给所有人都冷却时做保底）
            return max(self.weight, 0.0)
        # 冷却结束：按恢复速率向 MAX_WEIGHT 线性回升
        if self.weight < MAX_WEIGHT and self.recovery_base_ts > 0:
            elapsed_min = max(0.0, (now - self.recovery_base_ts)) / 60.0
            recovered = self.recovery_base_weight + elapsed_min * RECOVERY_PER_MIN
            if recovered > MAX_WEIGHT:
                recovered = MAX_WEIGHT
            return recovered
        return self.weight

    def state(self, now: float) -> str:
        """对外的状态标签：disabled / cooldown / degraded / healthy。"""
        if self.disabled:
            return "disabled"
        if now < self.penalty_until:
            return "cooldown"
        ew = self.effective_weight(now)
        if ew < MAX_WEIGHT * 0.8:
            return "degraded"
        return "healthy"

    def to_dict(self, now: Optional[float] = None) -> dict:
        now = now if now is not None else time.time()
        return {
            "user_id": self.user_id,
            "weight": round(self.effective_weight(now), 1),
            "raw_weight": round(self.weight, 1),
            "max_weight": MAX_WEIGHT,
            "state": self.state(now),
            "disabled": self.disabled,
            "success_count": self.success_count,
            "fail_count": self.fail_count,
            "total_requests": self.success_count + self.fail_count,
            "success_rate": (
                round(self.success_count * 100.0 / (self.success_count + self.fail_count), 1)
                if (self.success_count + self.fail_count) > 0 else None
            ),
            "last_success_ts": int(self.last_success_ts) if self.last_success_ts else 0,
            "last_fail_ts": int(self.last_fail_ts) if self.last_fail_ts else 0,
            "last_fail_reason": self.last_fail_reason,
            "last_fail_status": self.last_fail_status,
            "last_used_ts": int(self.last_used_ts) if self.last_used_ts else 0,
            "penalty_until": int(self.penalty_until) if self.penalty_until else 0,
            "cooldown_remaining": max(0, int(self.penalty_until - now)) if self.penalty_until > now else 0,
        }


# ─── 调度器 ───────────────────────────────────────────────────

class AccountScheduler:
    """线程安全的账号调度器。"""

    def __init__(self):
        self._stats: Dict[str, AccountStat] = {}
        self._lock = threading.RLock()
        # 累计选择次数（用于调试和 UI）
        self._total_picks = 0

    # ── 内部：同步账号列表 ──
    def _sync_accounts(self, user_ids: List[str]):
        """根据当前账号列表，新增缺失的 AccountStat、删除已移除的。"""
        active = set(user_ids)
        for uid in user_ids:
            if uid not in self._stats:
                self._stats[uid] = AccountStat(user_id=uid)
        # 删除已不存在的
        for uid in list(self._stats.keys()):
            if uid not in active:
                del self._stats[uid]

    # ── 选一个账号 ──
    def pick(self, accounts: list) -> Optional[object]:
        """accounts: List[MimoAccount]。返回一个 MimoAccount（或 None）。"""
        if not accounts:
            return None
        with self._lock:
            self._sync_accounts([a.user_id for a in accounts])
            now = time.time()

            # 1) 候选 = 未禁用 + 未冷却
            candidates = []
            for a in accounts:
                st = self._stats[a.user_id]
                if st.disabled:
                    continue
                if now < st.penalty_until:
                    continue
                w = st.effective_weight(now)
                if w <= 0:
                    continue
                candidates.append((a, w))

            chosen = None
            if candidates:
                total = sum(w for _, w in candidates)
                r = random.random() * total
                acc = 0.0
                for a, w in candidates:
                    acc += w
                    if r <= acc:
                        chosen = a
                        break
                if chosen is None:
                    chosen = candidates[-1][0]
            else:
                # 全部在冷却：选冷却最早结束的，保证服务可用（降级模式）
                alive = [a for a in accounts if not self._stats[a.user_id].disabled]
                if not alive:
                    return None
                alive.sort(key=lambda a: self._stats[a.user_id].penalty_until)
                chosen = alive[0]

            self._stats[chosen.user_id].last_used_ts = now
            self._total_picks += 1
            return chosen

    # ── 上报成功 ──
    def report_success(self, user_id: str):
        with self._lock:
            st = self._stats.get(user_id)
            if not st:
                st = AccountStat(user_id=user_id)
                self._stats[user_id] = st
            now = time.time()
            st.success_count += 1
            st.last_success_ts = now
            # 成功时，若之前被惩罚过，小步恢复（连续成功可以快速拉回）
            if st.weight < MAX_WEIGHT:
                st.weight = min(MAX_WEIGHT, st.weight + 5)
                st.recovery_base_ts = now
                st.recovery_base_weight = st.weight

    # ── 上报失败 ──
    def report_failure(
        self,
        user_id: str,
        status_code: Optional[int] = None,
        error: str = "",
    ):
        with self._lock:
            st = self._stats.get(user_id)
            if not st:
                st = AccountStat(user_id=user_id)
                self._stats[user_id] = st
            now = time.time()
            st.fail_count += 1
            st.last_fail_ts = now
            st.last_fail_status = status_code

            # 分类
            kind = _classify_failure(status_code, error)
            rule = PENALTIES[kind]
            old = st.weight
            if "set_weight" in rule:
                st.weight = float(rule["set_weight"])
            elif "div_weight" in rule:
                st.weight = max(MIN_WEIGHT, st.weight / rule["div_weight"])
            elif "sub_weight" in rule:
                st.weight = max(MIN_WEIGHT, st.weight - rule["sub_weight"])

            st.penalty_until = now + rule["cooldown"]
            st.recovery_base_ts = st.penalty_until
            st.recovery_base_weight = st.weight
            st.last_fail_reason = f"{rule['desc']}{' HTTP ' + str(status_code) if status_code else ''}"
            if error and len(error) < 200:
                st.last_fail_reason += f" · {error.strip()[:160]}"

    # ── 快照（给前端看）──
    def snapshot(self, accounts: list) -> dict:
        with self._lock:
            self._sync_accounts([a.user_id for a in accounts])
            now = time.time()
            items = [self._stats[a.user_id].to_dict(now) for a in accounts]
            summary = {
                "total_picks": self._total_picks,
                "healthy": sum(1 for it in items if it["state"] == "healthy"),
                "degraded": sum(1 for it in items if it["state"] == "degraded"),
                "cooldown": sum(1 for it in items if it["state"] == "cooldown"),
                "disabled": sum(1 for it in items if it["state"] == "disabled"),
                "recovery_per_min": RECOVERY_PER_MIN,
                "max_weight": MAX_WEIGHT,
            }
            return {"summary": summary, "accounts": items}

    # ── 手动操作 ──
    def reset(self, user_id: str):
        with self._lock:
            st = self._stats.get(user_id)
            if st:
                st.weight = MAX_WEIGHT
                st.penalty_until = 0.0
                st.recovery_base_ts = 0.0
                st.recovery_base_weight = MAX_WEIGHT
                st.last_fail_reason = ""
                st.last_fail_status = None

    def disable(self, user_id: str):
        with self._lock:
            st = self._stats.get(user_id)
            if not st:
                self._stats[user_id] = AccountStat(user_id=user_id, disabled=True)
            else:
                st.disabled = True

    def enable(self, user_id: str):
        with self._lock:
            st = self._stats.get(user_id)
            if st:
                st.disabled = False

    def reset_all(self):
        with self._lock:
            for st in self._stats.values():
                st.weight = MAX_WEIGHT
                st.penalty_until = 0.0
                st.recovery_base_ts = 0.0
                st.recovery_base_weight = MAX_WEIGHT
                st.last_fail_reason = ""
                st.last_fail_status = None
                st.disabled = False


def _classify_failure(status_code: Optional[int], error: str) -> str:
    if status_code is not None:
        if status_code in (401, 403):
            return "auth"
        if status_code == 429:
            return "rate"
        if 500 <= status_code < 600:
            return "server"
        if 400 <= status_code < 500:
            return "client"
    err_l = (error or "").lower()
    if any(k in err_l for k in ("timeout", "timed out", "connect", "reset", "eof", "network")):
        return "server"
    return "unknown"


# 全局单例
scheduler = AccountScheduler()
