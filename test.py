
from typing import List, Iterator, NamedTuple, Union

import os
import time
import argparse
import warnings
import hashlib
from pathlib import Path
from contextlib import closing
from queue import Queue
from threading import Thread, Event, current_thread
from datetime import datetime

import pyewf


class Timer:
    name: str
    start_point: float
    display: bool

    def __init__(self, name: str, display: bool = True):
        self.name = name
        self.display = display

    def __enter__(self):
        self.start_point = time.time()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.display:
            print(self.name, time.time() - self.start_point)


class Task(NamedTuple):
    read_complete_event: Event  # TODO: for buffer reuse in the future, useless now
    write_complete_event: Event
    size: int
    offset: int
    buffer: bytearray


class ReaderPool:
    _names: str
    _thread_count: int
    _block_size: int
    _queue_size: int
    _queue: "Queue[Union[Task,None]]"  # Python3.9+, None means complete
    _threads: List[Thread]
    _disk_size: int
    _verbose: bool

    def __init__(
        self,
        ewf_path: Path,
        parallelism: int = 3,
        block_size: int = 1024 * 1024 * 512,
        verbose: bool = False,
    ):
        # backup for recovery
        current_dir = os.getcwd()

        if str(ewf_path) != ewf_path.name:
            warnings.warn(
                "pyewf can only handle file in current dir, current dir may change!"
            )
            os.chdir(ewf_path.absolute().parent)
            ewf_path = Path(ewf_path.name)

        ewf_path: str = str(ewf_path)

        self._names = pyewf.glob(ewf_path)
        self._thread_count = parallelism
        self._block_size = block_size
        self._queue_size = parallelism + 3
        self._queue = Queue(maxsize=self._queue_size)
        self._threads = [Thread(target=self.worker) for _ in range(parallelism)]
        self._verbose = verbose

        disk: pyewf.handle
        with closing(pyewf.open(self._names)) as disk:
            self._disk_size = disk.media_size

        for t in self._threads:
            t.start()

        os.chdir(current_dir)

    @property
    def disk_size(self) -> int:
        return self._disk_size

    def worker(self):
        disk: pyewf.handle = pyewf.open(self._names)
        queue = self._queue

        while True:
            with Timer(f"({current_thread().ident})Reading spends:", display=False):
                task = queue.get()
                if task is None:  # get None, exit
                    break
                task.read_complete_event.wait()  # wait until read complete

            task.buffer[:] = disk.read_buffer_at_offset(task.size, task.offset)
            task.write_complete_event.set()  # write complete

            queue.task_done()  # useless now

    def __iter__(self):
        def task_generator() -> Iterator:
            disk_size = self._disk_size
            block_size = self._block_size
            offset = 0

            while offset < disk_size:
                reading = Event()
                writing = Event()
                buffer = bytearray()

                reading.set()  # nothing read, just set

                task = Task(reading, writing, block_size, offset, buffer)

                offset += block_size
                yield task

        def producer(consumer_queue: "Queue[Union[Task,None]]"):
            task_queue = self._queue

            for t in task_generator():
                task_queue.put(t)
                consumer_queue.put(t)

            # everything done, put None for exiting
            for _ in range(self._thread_count):
                task_queue.put(None)
                consumer_queue.put(None)

        def consumer() -> Iterator:
            consumer_queue = Queue(
                maxsize=self._queue_size
            )  # use maxsize to block task generator

            producer_thread = Thread(target=producer, args=(consumer_queue,))
            producer_thread.start()

            while True:

                task: Task = consumer_queue.get()
                if task is None:
                    break  # TODO: make sure thread exit
                task.write_complete_event.wait()
                yield task.buffer
                task.read_complete_event.clear()

        return consumer()


def main():
    parser = argparse.ArgumentParser(description="Fast EWF(E01) hash calculator")
    parser.add_argument("name", help="EWF file name (1 name enough).")
    parser.add_argument(
        "--hash",
        default="md5",
        choices=sorted(hashlib.algorithms_available),
        help="Hash type you want to use. (default: md5)",
    )
    parser.add_argument(
        "--block-size",
        type=int,
        default=1024 * 1024 * 256,
        help="Block size(byte) read from disk, larger means faster, "
        "but cost more memory. (default: 268435456(256MiB))",
    )
    parser.add_argument(
        "--parallelism",
        type=int,
        default=3,
        help="Thread count, improve decompress performance, \n"
        "but large number have negative effect on read performance. (default: 3)",
    )
    parser.add_argument(
        "-V",
        "--verbose",
        action="store_true",
        help="Show more information for debugging.",
    )

    args = parser.parse_args()

    ewf_path = Path(args.name)
    parallelism = args.parallelism
    block_size = args.block_size
    hash_type = args.hash
    verbose = args.verbose

    # Process data

    pool = ReaderPool(
        ewf_path=ewf_path,
        parallelism=parallelism,
        block_size=block_size,
        verbose=verbose,
    )
    hasher = hashlib.new(hash_type)

    total_size = pool.disk_size // 1024 // 1024
    with Timer("total time use"):
        for i, block in enumerate(pool):
            with Timer("hash use", display=verbose):
                hasher.update(block)
            print(
                (i * block_size + len(block)) // 1024 // 1024,
                "/",
                total_size,
                "MiB processed",
            )

    result = hasher.hexdigest()

    # Print result

    info = f"""
{ewf_path} ({ewf_path.stat().st_size}Bytes)
{datetime.now()}
{args.hash}: {result}
""".strip()

    print(info)
    ewf_path.with_suffix(".hash").write_text(info)


if __name__ == "__main__":
    main()