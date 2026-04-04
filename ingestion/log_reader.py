import os
from typing import Generator, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ingestion.parser import parse_line, Event


def read_file(path: str) -> Generator[Event, None, None]:
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                event = parse_line(line, source_file=path)
                if event is not None:
                    yield event
    except FileNotFoundError:
        print(f"[WARN] Log file not found: {path}")


def read_all_files(paths: list) -> Generator[Event, None, None]:
    for path in paths:
        yield from read_file(path)


class LogFileHandler(FileSystemEventHandler):
    def __init__(self, callback: Callable[[Event], None], paths: list):
        super().__init__()
        self._callback = callback
        self._offsets: dict = {os.path.abspath(p): 0 for p in paths}

    def on_modified(self, event):
        if event.is_directory:
            return
        abs_path = os.path.abspath(event.src_path)
        if abs_path not in self._offsets:
            self._offsets[abs_path] = 0
        try:
            with open(abs_path, "r", errors="replace") as f:
                f.seek(self._offsets[abs_path])
                new_lines = f.readlines()
                self._offsets[abs_path] = f.tell()
            for line in new_lines:
                event_obj = parse_line(line, source_file=abs_path)
                if event_obj is not None:
                    self._callback(event_obj)
        except (FileNotFoundError, OSError):
            pass

    def on_created(self, event):
        if not event.is_directory:
            abs_path = os.path.abspath(event.src_path)
            self._offsets[abs_path] = 0


def start_watcher(paths: list, callback: Callable[[Event], None]) -> Observer:
    handler = LogFileHandler(callback, paths)
    observer = Observer()
    watched_dirs = set(os.path.dirname(os.path.abspath(p)) for p in paths)
    for directory in watched_dirs:
        observer.schedule(handler, directory, recursive=False)
    observer.start()
    return observer
