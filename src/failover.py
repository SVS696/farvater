"""Priority and hysteresis logic; no networking, shell or secrets in this module."""
from dataclasses import dataclass, field


@dataclass
class Health:
    failures: int = 0
    healthy_since: float | None = None
    available: bool = False


@dataclass
class PrioritySelector:
    priority: list[str]
    current: str
    failures_to_leave: int = 3
    recovery_seconds: float = 30
    health: dict[str, Health] = field(default_factory=dict)
    manual: str | None = None

    def __post_init__(self):
        if not self.priority or len(set(self.priority)) != len(self.priority):
            raise ValueError('Priority list must be nonempty and unique')
        if self.current not in self.priority or self.failures_to_leave < 1 or self.recovery_seconds < 0:
            raise ValueError('Invalid selector configuration')
        self.health = {tag: Health() for tag in self.priority}

    def sample(self, observations: dict[str, bool], now: float) -> dict:
        if set(observations) != set(self.priority):
            raise ValueError('Every exit needs an explicit observation')
        for tag in self.priority:
            state = self.health[tag]
            if observations[tag]:
                if state.healthy_since is None:
                    state.healthy_since = now
                state.failures = 0
                state.available = True
            else:
                state.healthy_since = None
                state.failures += 1
                state.available = False
        before = self.current
        if self.manual is not None:
            if self.manual not in self.priority:
                raise ValueError('Unknown manual exit')
            self.current = self.manual
            reason = 'manual selection; health still reported'
        elif self.health[self.current].failures >= self.failures_to_leave:
            candidates = [tag for tag in self.priority if self.health[tag].available]
            if candidates:
                self.current = candidates[0]
                reason = 'current exit failed consecutive checks'
            else:
                reason = 'all exits unavailable; no false healthy fallback'
        else:
            index = self.priority.index(self.current)
            candidates = [tag for tag in self.priority[:index]
                          if self.health[tag].healthy_since is not None
                          and now-self.health[tag].healthy_since >= self.recovery_seconds]
            if candidates:
                self.current = candidates[0]
                reason = 'higher priority exit recovered and stayed healthy'
            else:
                reason = 'keep current exit'
        return {'selected':self.current, 'changed':before != self.current,
                'healthy':self.health[self.current].available, 'reason':reason}
