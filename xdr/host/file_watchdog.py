"""
file_watchdog.py - filesystem watcher, pushing standardized alert dicts into
the shared alert queue on file create/modify/delete events. Runs on the
watchdog library's own Observer, which manages its own background thread
internally.
"""
import os

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from xdr.core.alert_queue import push_alert
from xdr.core.events import SecurityEvent, Vector
from xdr.core.event_bus import ENGINE

class XdrFileWatchdog(FileSystemEventHandler):
    """Watches a directory tree for file create/modify/delete events and
    pushes a standardized alert dict into the shared ALERT_QUEUE for each."""

    def __init__(self, watch_path: str, recursive: bool = True):
        super().__init__()
        self.watch_path = watch_path
        self.recursive = recursive
        self.observer = Observer()

    def on_created(self, event):
        if event.is_directory:
            return
        push_alert("file_created", event.src_path, severity="low")
        print(f"[WATCHDOG] file created: {event.src_path}")
        ENGINE.publish_threadsafe(SecurityEvent(
            vector=Vector.BINARY, event_type="file_created",
            src = event.src_path, severity =1,
        ))

    def on_modified(self, event):
        if event.is_directory:
            return
        push_alert("file_modified", event.src_path, severity="low")
        print(f"[WATCHDOG] file modified: {event.src_path}")
        ENGINE.publish_threadsafe(SecurityEvent(
            vector=Vector.BINARY, event_type = "file_modified", 
            src= event.src_path, severity = 1,
        ))

    def on_deleted(self, event):
        if event.is_directory:
            return
        push_alert("file_deleted", event.src_path, severity="medium")
        print(f"[WATCHDOG] file deleted: {event.src_path}")
        ENGINE.publish_threadsafe(SecurityEvent(
            vector = Vector.BINARY, event_type="file_deleted",
            src = event.src_path, severity = 3,
        ))

    def on_moved(self, event):
        if event.is_directory:
            return
        push_alert("file_moved", f"{event.src_path} -> {event.dest_path}", severity="low")
        print(f"[WATCHDOG] file moved: {event.src_path} -> {event.dest_path}")
        ENGINE.publish_threadsafe(SecurityEvent(
            vector = Vector.BINARY, event_type ="file moved",
            src = f"{event.src_path} -> {event.dest_path}", severity = 1,
            metadata = {"src_path": event.src_path, "dest_path": event.dest_path},
        ))

    def start(self):
        os.makedirs(self.watch_path, exist_ok=True)
        self.observer.schedule(self, self.watch_path, recursive=self.recursive)
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
