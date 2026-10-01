"""Fan-out of normalized documents to live subscribers (Server-Sent Events), replacing 2-second polling.

Each subscriber has a bounded queue; a slow client loses the OLDEST events (counted) and never slows the pipeline. `publish()` is
safe from any thread (the dry-run endpoint processes logs in a worker thread) and costs one truthiness check when nobody listens.
"""
import asyncio


class Subscription:
    def __init__(self, maxsize: int):
        self.q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self.dropped = 0


class StreamHub:
    def __init__(self):
        self._subs: set[Subscription] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self.published = 0

    @property
    def subscribers(self) -> int:
        return len(self._subs)

    def subscribe(self, maxsize: int = 1000) -> Subscription:
        self._loop = asyncio.get_running_loop()
        s = Subscription(maxsize)
        self._subs.add(s)
        return s

    def unsubscribe(self, s: Subscription) -> None:
        self._subs.discard(s)

    def publish(self, doc: dict) -> None:
        if not self._subs:
            return
        self.published += 1
        try:
            same_loop = asyncio.get_running_loop() is self._loop
        except RuntimeError:
            same_loop = False
        if same_loop:
            self._fan(doc)
        elif self._loop is not None and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._fan, doc)

    def _fan(self, doc: dict) -> None:
        for s in list(self._subs):
            if s.q.full():
                try:
                    s.q.get_nowait()                    # drop the oldest, keep the stream current
                    s.dropped += 1
                except asyncio.QueueEmpty:
                    pass
            s.q.put_nowait(doc)
