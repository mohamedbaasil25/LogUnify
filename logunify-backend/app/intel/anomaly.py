"""Online anomaly scoring with Isolation Forest.

Lifecycle: collect feature vectors -> fit after `warmup` samples -> refit every `refit_every` samples on a
sliding window (in a background thread, atomic model swap). Until the first fit, score is 0.0 and
`model_ready` is False (every template is "new" at startup, so scoring then would only produce noise).

Score calibration (0.0-1.0): raw = -score_samples (higher = more anomalous). With med / p99 taken from the
training window, x = (raw - med) / (p99 - med):
    x <= 0 -> 0.0;  0 < x <= 1 -> 0.7 * x;  x > 1 -> 0.7 + 0.3 * min(x - 1, 1)
so ~1% of training-like traffic lands above the 0.7 alert threshold; clearly more isolated points go to 1.0.
"""
import threading
from collections import deque
from dataclasses import dataclass

import numpy as np
from sklearn.ensemble import IsolationForest


@dataclass(frozen=True)
class _Model:
    forest: IsolationForest
    med: float
    p99: float


class AnomalyScorer:
    def __init__(self, warmup: int = 200, refit_every: int = 1000, window: int = 5000,
                 n_estimators: int = 50, seed: int = 42):
        self.warmup, self.refit_every = warmup, refit_every
        self._n_estimators, self._seed = n_estimators, seed
        self._data: deque[list[float]] = deque(maxlen=window)
        self._model: _Model | None = None
        self._since_fit = 0
        self._fitting = False
        self._cache: dict[tuple, float] = {}
        self._lock = threading.Lock()

    @property
    def ready(self) -> bool:
        return self._model is not None

    def score(self, features: list[float], learn: bool = True) -> float:
        """Optionally record the sample, maybe trigger a (re)fit, return the calibrated 0-1 anomaly score."""
        if learn:
            self._data.append(features)
            self._since_fit += 1
            n = len(self._data)
            if not self._fitting and ((self._model is None and n >= self.warmup) or
                                      (self._model is not None and self._since_fit >= self.refit_every)):
                self.fit_async()
        model = self._model
        if model is None:
            return 0.0
        key = tuple(round(x, 3) for x in features)
        if (hit := self._cache.get(key)) is not None:
            return hit
        raw = float(-model.forest.score_samples(np.asarray([features]))[0])
        s = self._calibrate(raw, model)
        if len(self._cache) > 4096:
            self._cache.clear()
        self._cache[key] = s
        return s

    def score_many(self, rows: list[list[float]], learn: list[bool]) -> list[float]:
        """Batch version of `score`: record the samples, maybe trigger one (re)fit, then score all rows in ONE forest call
        (rows seen recently are served from the cache and not re-scored)."""
        for features, do_learn in zip(rows, learn):
            if do_learn:
                self._data.append(features)
                self._since_fit += 1
        n = len(self._data)
        if not self._fitting and any(learn) and ((self._model is None and n >= self.warmup) or
                                                 (self._model is not None and self._since_fit >= self.refit_every)):
            self.fit_async()
        model = self._model
        if model is None:
            return [0.0] * len(rows)
        keys = [tuple(round(x, 3) for x in r) for r in rows]
        todo: dict[tuple, list[float]] = {k: r for k, r in zip(keys, rows) if k not in self._cache}
        if todo:
            raw = -model.forest.score_samples(np.asarray(list(todo.values()), dtype=float))
            if len(self._cache) + len(todo) > 4096:
                self._cache.clear()
            for k, r in zip(todo, raw):
                self._cache[k] = self._calibrate(float(r), model)
        return [self._cache[k] for k in keys]

    @staticmethod
    def _calibrate(raw: float, m: _Model) -> float:
        x = (raw - m.med) / max(m.p99 - m.med, 1e-6)
        if x <= 0:
            return 0.0
        return round(0.7 * x if x <= 1 else 0.7 + 0.3 * min(x - 1, 1), 4)

    # ---- persistence (feature vectors only: no pickled model is ever stored or loaded) --------------------------------
    @property
    def samples(self) -> int:
        return len(self._data)

    def export_window(self) -> list[list[float]]:
        for _ in range(8):                                  # another thread (the pipeline) may append mid-copy
            try:
                return [list(r) for r in self._data]
            except RuntimeError:
                continue
        return []

    def import_window(self, rows: list[list[float]]) -> bool:
        """Restore the training window and, if it is large enough, refit now so scoring is live right after a restart."""
        width = len(rows[0]) if rows else 0
        if not rows or any(len(r) != width for r in rows) or any(not all(isinstance(x, (int, float)) for x in r) for r in rows):
            return False
        self._data.extend(rows)
        if len(self._data) >= self.warmup:
            self.fit_sync()
        return self._model is not None

    # ---- training -------------------------------------------------------
    def fit_async(self) -> None:
        with self._lock:
            if self._fitting:
                return
            self._fitting = True
        snapshot = np.asarray(self._data, dtype=float)
        self._since_fit = 0
        threading.Thread(target=self._fit, args=(snapshot,), daemon=True, name="iforest-fit").start()

    def fit_sync(self) -> None:
        with self._lock:
            self._fitting = True
        self._since_fit = 0
        self._fit(np.asarray(self._data, dtype=float))

    def _fit(self, X: np.ndarray) -> None:
        try:
            forest = IsolationForest(n_estimators=self._n_estimators, random_state=self._seed,
                                     max_samples=min(256, len(X)), contamination="auto").fit(X)
            raw = -forest.score_samples(X)
            self._model = _Model(forest, float(np.median(raw)), float(np.percentile(raw, 99)))
            self._cache = {}
        finally:
            self._fitting = False
