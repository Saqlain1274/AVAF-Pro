import asyncio
import heapq

class QueueManager:

    def __init__(self):

        self._heap = []

        self._lock = asyncio.Lock()

        self._not_empty = asyncio.Event()

        self._finished = asyncio.Event()

        self._finished.set()

        self._unfinished = 0

        self._queued = set()

        self._closed = False

        self.statistics = {

            "queued": 0,

            "finished": 0,

            "duplicates": 0

        }


    def enqueue(
        self,
        url,
        depth,
        priority=0
    ):
    
        if self._closed:
            return False
    
        key = (url, depth)
    
        if key in self._queued:
    
            self.statistics["duplicates"] += 1
    
            return False
    
        self._queued.add(key)
    
        heapq.heappush(
    
            self._heap,
    
            (-priority, url, depth)
    
        )
    
        self.statistics["queued"] += 1
    
        self._unfinished += 1
    
        self._finished.clear()
    
        self._not_empty.set()
    
        return True

    async def dequeue(self):

        while True:

            async with self._lock:

                if self._heap:

                    _, url, depth = heapq.heappop(
                        self._heap
                    )

                    if not self._heap:
                        self._not_empty.clear()

                    return url, depth

                # No queued work and no active unfinished work means
                # the browser-observed discovery frontier has converged.
                if self._unfinished == 0 or self._closed:
                    self._not_empty.clear()
                    return None

            await self._not_empty.wait()
                
    def task_done(self):

        self.statistics["finished"] += 1

        self._unfinished -= 1

        if self._unfinished <= 0:

            self._unfinished = 0

            self._finished.set()

            # Wake workers that may be waiting in dequeue().
            # They will re-check _unfinished and terminate cleanly.
            self._not_empty.set()
            
    async def join(self):
    
        await self._finished.wait()
        
    def close(self):
    
        self._closed = True
    
        self._not_empty.set()
        
    def reset(self):
    
        self._heap.clear()
    
        self._queued.clear()
    
        self._closed = False
    
        self._unfinished = 0
    
        self.statistics = {
    
            "queued": 0,
    
            "finished": 0,
    
            "duplicates": 0
    
        }
    
        self._finished.set()
    
        self._not_empty.clear()
        
    def empty(self):
    
        return len(self._heap) == 0
    
    def size(self):
    
        return len(self._heap)
    
    def progress(self):
    
        return {
    
            "queued": self.statistics["queued"],
    
            "finished": self.statistics["finished"],
    
            "remaining": len(self._heap),
    
            "duplicates": self.statistics["duplicates"]
    
        }
        
    def export(self):
    
        return self.progress()