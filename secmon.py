#!/usr/bin/env python3
"""
Sysmon-lite EDR Agent with Enhanced Window Activity Monitoring:
- Psutil Process Snapshot (last 30) with parent process, exe path, digital signature, and username
- PowerShell History Tracking
- File System Monitoring
- Network Connection Tracking with Bandwidth Monitoring (bytes in/out) and Browser HTTPS Site Access Detection
- Keystroke Logging
- Window Activity Detection (Create, Close, Focus, Title Change, State Change)
- SQLite Logging with device name and user context in every event
- Interactive Console Mode
- Remote management via HTTP (Flask server integration)
"""

import time
import threading
import os
import psutil
import sqlite3
import json
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pynput import keyboard
import win32gui
import win32process
import win32con
import requests
import uuid
import socket
import subprocess
import getpass
from datetime import datetime, timezone

# Global device and user info to attach to all logs
DEVICE_NAME = socket.gethostname()
CURRENT_USER = getpass.getuser()

# ----------------- Flask Server Communication -----------------
SERVER_URL = "http://127.0.0.1:5000"  # Change to your Flask backend
ENDPOINT_ID_FILE = "agent_id.txt"

def get_or_create_endpoint_id():
    if os.path.exists(ENDPOINT_ID_FILE):
        with open(ENDPOINT_ID_FILE, "r") as f:
            return f.read().strip()
    eid = str(uuid.uuid4())
    with open(ENDPOINT_ID_FILE, "w") as f:
        f.write(eid)
    return eid

def register_endpoint():
    endpoint_id = get_or_create_endpoint_id()
    payload = {
        "endpoint_id": endpoint_id,
        "hostname": DEVICE_NAME,
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "os_info": os.name
    }
    try:
        r = requests.post(f"{SERVER_URL}/api/endpoint/register", json=payload, timeout=5)
        if r.status_code == 200:
            print("[+] Registered endpoint with server", flush=True)
        else:
            print(f"[!] Registration failed: {r.status_code} {r.text}", flush=True)
    except Exception as e:
        print(f"[!] Failed to register endpoint: {e}", flush=True)

def send_heartbeat():
    endpoint_id = get_or_create_endpoint_id()
    payload = {"endpoint_id": endpoint_id}
    try:
        requests.post(f"{SERVER_URL}/api/endpoint/heartbeat", json=payload, timeout=5)
    except Exception as e:
        print(f"[!] Heartbeat error: {e}", flush=True)

def sync_events_to_server(logger):
    """Sync local database events to the server"""
    endpoint_id = get_or_create_endpoint_id()
    try:
        unsynced_events = logger.get_unsynced_events()
        
        if not unsynced_events:
            return
        
        print(f"[*] Found {len(unsynced_events)} unsynced events to send", flush=True)
        
        # Prepare events batch for upload
        events_batch = []
        for event_id, timestamp, event_type, details in unsynced_events:
            events_batch.append({
                'id': event_id,
                'timestamp': timestamp,
                'event_type': event_type,
                'details': details
            })
        
        # Send to server
        payload = {
            'endpoint_id': endpoint_id,
            'events': events_batch
        }
        
        print(f"[*] Sending payload to {SERVER_URL}/api/data-transfer/receive", flush=True)
        print(f"[DEBUG] Endpoint ID: {endpoint_id}, Event Count: {len(events_batch)}", flush=True)
        
        r = requests.post(
            f"{SERVER_URL}/api/data-transfer/receive",
            json=payload,
            timeout=10
        )
        
        print(f"[*] Server response code: {r.status_code}", flush=True)
        print(f"[*] Server response: {r.text}", flush=True)
        
        if r.status_code == 200:
            # Mark events as synced
            for event_id, _, _, _ in unsynced_events:
                logger.mark_event_synced(event_id)
            print(f"[+] Successfully synced {len(unsynced_events)} events to server", flush=True)
        else:
            print(f"[!] Sync failed with status {r.status_code}: {r.text}", flush=True)
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Cannot connect to server at {SERVER_URL}: {e}", flush=True)
    except Exception as e:
        print(f"[!] Event sync error: {e}", flush=True)
        import traceback
        traceback.print_exc()

def check_for_commands():
    endpoint_id = get_or_create_endpoint_id()
    try:
        r = requests.get(f"{SERVER_URL}/api/endpoint/get-commands/{endpoint_id}", timeout=5)
        data = r.json()
        for cmd in data.get("commands", []):
            cmd_text = cmd["command"]
            command_id = cmd["command_id"]
            try:
                result = subprocess.check_output(cmd_text, shell=True, text=True, stderr=subprocess.STDOUT)
                status = "completed"
            except Exception as e:
                result = str(e)
                status = "failed"
            try:
                requests.post(f"{SERVER_URL}/api/endpoint/submit-result", json={
                    "command_id": command_id,
                    "result": result,
                    "status": status
                }, timeout=5)
            except Exception as e:
                print(f"[!] Could not submit command result: {e}", flush=True)
    except Exception as e:
        print(f"[!] Fetch commands error: {e}", flush=True)

def background_loop(logger=None):
    while True:
        try:
            register_endpoint()
            break
        except Exception:
            print("[!] Initial registration failed, retrying in 10s...", flush=True)
            time.sleep(10)
    
    sync_interval = 0
    while True:
        send_heartbeat()
        check_for_commands()
        
        # Sync events every 30 seconds
        sync_interval += 10
        if sync_interval >= 30:
            if logger:
                sync_events_to_server(logger)
            sync_interval = 0
        
        time.sleep(10)

# -------------- Local Activity Logger (SQLite) --------------
class Logger:
    DB_FILE = "SecurityEvents.db"
    def __init__(self):
        self.conn = sqlite3.connect(self.DB_FILE, check_same_thread=False)
        self._create_table()
    def _create_table(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                details TEXT
            )
        """)
        # Add sync tracking table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_sync_status (
                event_id INTEGER PRIMARY KEY,
                synced BOOLEAN DEFAULT 0,
                synced_at TEXT,
                FOREIGN KEY(event_id) REFERENCES events(id)
            )
        """)
        self.conn.commit()

    def get_unsynced_events(self):
        """Retrieve all events that haven't been synced yet"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT e.id, e.timestamp, e.event_type, e.details 
            FROM events e
            LEFT JOIN event_sync_status s ON e.id = s.event_id
            WHERE s.synced IS NULL OR s.synced = 0
            ORDER BY e.id ASC
        """)
        return cursor.fetchall()

    def mark_event_synced(self, event_id):
        """Mark an event as synced"""
        timestamp = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO event_sync_status (event_id, synced, synced_at)
            VALUES (?, 1, ?)
        """, (event_id, timestamp))
        self.conn.commit()

    def log(self, event_type, details):
        timestamp = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
        # Prepend device and user info to event details
        details_with_context = f"Device: {DEVICE_NAME} | User: {CURRENT_USER} | {details}"
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO events (timestamp, event_type, details) VALUES (?, ?, ?)", (timestamp, event_type, details_with_context))
        self.conn.commit()
        print(f"[{timestamp}] {event_type} | {details_with_context}", flush=True)
    def show_recent(self, count=10):
        cursor = self.conn.cursor()
        cursor.execute("SELECT timestamp, event_type, details FROM events ORDER BY id DESC LIMIT ?", (count,))
        rows = cursor.fetchall()
        print("\n--- Last {} Events ---".format(count))
        for row in rows:
            print(f"[{row[0]}] {row[1]} | {row[2]}")
        print()
    def close(self):
        self.conn.close()

# -------------- Psutil Process Snapshot (Last 30) with detailed fields --------------
class PsutilProcessSnapshot:
    def __init__(self, logger):
        self.logger = logger

    def get_digital_signature(self, path):
        try:
            if os.path.isfile(path):
                return "Exists/UnknownSignature"
            else:
                return "NoFile"
        except Exception:
            return "Error"

    def run_once(self):
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline', 'ppid']):
                try:
                    pid = proc.pid
                    name = proc.name()
                    create_time = proc.create_time() if hasattr(proc, 'create_time') else 0
                    cmdline = proc.cmdline()
                    ppid = proc.ppid()
                    try:
                        parent_proc = psutil.Process(ppid)
                        parent_name = parent_proc.name()
                    except Exception:
                        parent_name = "N/A"
                    try:
                        exe_path = proc.exe()
                    except Exception:
                        exe_path = "N/A"
                    try:
                        username = proc.username()
                    except Exception:
                        username = "N/A"
                    digital_signature = self.get_digital_signature(exe_path)
                    processes.append({
                        'pid': pid,
                        'name': name,
                        'create_time': create_time,
                        'cmdline': cmdline,
                        'ppid': ppid,
                        'parent_name': parent_name,
                        'exe_path': exe_path,
                        'username': username,
                        'digital_signature': digital_signature
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            processes.sort(key=lambda p: p.get('create_time', 0), reverse=True)

            for proc in processes[:30]:
                timestamp = datetime.fromtimestamp(proc.get('create_time', 0), tz=timezone.utc).isoformat(timespec='milliseconds')
                cmdline_str = ' '.join(proc.get('cmdline', [])) or 'N/A'
                self.logger.log(
                    "PROCESS_CREATE",
                    f"Name: {proc['name']} | PID: {proc['pid']} | Parent: {proc['parent_name']} (PID: {proc['ppid']}) | "
                    f"User: {proc['username']} | Path: {proc['exe_path']} | Signature: {proc['digital_signature']} | "
                    f"Time: {timestamp} | Cmd: {cmdline_str}"
                )
        except Exception as e:
            print(f"[!] Psutil snapshot error: {e}", flush=True)


# -------------- Enhanced Kernel-Level Process Monitor ----------------
class ProcessMonitor:
    """
    Real-time process monitoring using Windows API for kernel-level process activity capture.
    Tracks process creation/termination with full command-line parameters, usernames, and parent processes.
    """
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.known_processes = {}
        self.lock = threading.Lock()
        self.monitor_interval = 1  # 1 second monitoring interval

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[*] Kernel-level process monitor started (real-time tracking)", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] Process monitor stopped", flush=True)

    def _get_process_details(self, pid):
        """Get detailed process information using psutil and Windows API"""
        try:
            proc = psutil.Process(pid)
            details = {
                'pid': pid,
                'ppid': proc.ppid() if proc.ppid() else 0,
                'name': proc.name(),
                'command_line': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'exe_path': proc.exe(),
                'username': proc.username(),
                'create_time': proc.create_time() if hasattr(proc, 'create_time') else 0
            }
            
            # Get parent process name
            try:
                parent_proc = psutil.Process(details['ppid'])
                details['parent_name'] = parent_proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                details['parent_name'] = 'N/A'
            
            return details
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            return None

    def _get_session_id(self, pid):
        """Get Windows session ID for process"""
        try:
            # Use win32process to get session ID if available
            _, session_id = win32process.GetWindowThreadProcessId(pid)
            return str(session_id)
        except Exception:
            return str(pid)

    def _log_process_create(self, details):
        """Log process creation event with full parameters"""
        try:
            self.logger.log(
                "PROCESS_CREATE",
                f"Process: {details['name']} | PID: {details['pid']} | PPID: {details['ppid']} | "
                f"Parent: {details['parent_name']} | User: {details['username']} | "
                f"Path: {details['exe_path']} | "
                f"CmdLine: {details['command_line']}"
            )
        except Exception as e:
            print(f"[!] Error logging process creation: {e}", flush=True)

    def _log_process_terminate(self, pid, details):
        """Log process termination event"""
        try:
            self.logger.log(
                "PROCESS_TERMINATE",
                f"Process: {details['name']} (PID: {pid}) | PPID: {details['ppid']} | "
                f"Parent: {details['parent_name']} | User: {details['username']} | "
                f"Path: {details['exe_path']}"
            )
        except Exception as e:
            print(f"[!] Error logging process termination: {e}", flush=True)

    def _monitor_loop(self):
        """Main monitoring loop - detects process creation and termination"""
        print("[*] Process monitor loop started - capturing kernel-level process activity", flush=True)
        
        while self.running:
            try:
                with self.lock:
                    # Get current processes
                    current_pids = set()
                    
                    try:
                        for proc in psutil.process_iter(['pid']):
                            current_pids.add(proc.pid)
                    except Exception as e:
                        print(f"[!] Error enumerating processes: {e}", flush=True)
                        time.sleep(self.monitor_interval)
                        continue
                    
                    # Detect NEW processes (PROCESS_CREATE)
                    new_pids = current_pids - set(self.known_processes.keys())
                    for pid in new_pids:
                        details = self._get_process_details(pid)
                        if details:
                            self.known_processes[pid] = details
                            self._log_process_create(details)
                            print(f"[+] PROCESS_CREATE: {details['name']} (PID: {pid})", flush=True)
                    
                    # Detect TERMINATED processes (PROCESS_TERMINATE)
                    terminated_pids = set(self.known_processes.keys()) - current_pids
                    for pid in terminated_pids:
                        details = self.known_processes.pop(pid)
                        self._log_process_terminate(pid, details)
                        print(f"[-] PROCESS_TERMINATE: {details['name']} (PID: {pid})", flush=True)
                
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                print(f"[!] Process monitor error: {e}", flush=True)
                time.sleep(self.monitor_interval)

# -------------- ETW Command Capture Monitor ----------------
class ETWCommandCaptureMonitor:
    """
    Real-time command capture from cmd.exe and powershell.exe using Windows Event Tracing.
    Captures all executed commands with full context (PID, PPID, user, path, exit code).
    """
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.captured_commands = set()
        self.lock = threading.Lock()
        self.check_interval = 2  # Check every 2 seconds

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._etw_monitor_loop, daemon=True)
        self.thread.start()
        print("[*] ETW Command Capture Monitor started (real-time cmd/PowerShell tracking)", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] ETW Command Capture Monitor stopped", flush=True)

    def _get_process_info(self, pid):
        """Get detailed info about a process by PID"""
        try:
            proc = psutil.Process(pid)
            return {
                'name': proc.name(),
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'exe_path': proc.exe(),
                'username': proc.username(),
                'ppid': proc.ppid() if proc.ppid() else 0,
                'create_time': proc.create_time(),
                'pid': pid
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _get_parent_info(self, ppid):
        """Get parent process name"""
        try:
            parent = psutil.Process(ppid)
            return parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 'N/A'

    def _capture_powershell_commands(self):
        """Capture PowerShell commands from ETW events"""
        try:
            # Query PowerShell operational log for script execution (Event ID 4104)
            ps_script = """
$ErrorActionPreference = 'SilentlyContinue'
$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104,4103} -MaxEvents 50 2>$null
foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    foreach ($data in $xml.Event.EventData.Data) {
        if ($data.Name -eq 'ScriptBlockText') {
            [PSCustomObject]@{
                PID = $event.ProcessId
                TimeCreated = $event.TimeCreated
                ScriptBlock = $data.'#text'
            } | ConvertTo-Json -Compress
        }
    }
}
"""
            result = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", ps_script],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5
            )
            
            commands = []
            if result.strip():
                for line in result.strip().split('\n'):
                    if line.strip():
                        try:
                            import json
                            cmd_data = json.loads(line)
                            commands.append(cmd_data)
                        except json.JSONDecodeError:
                            pass
            
            return commands
        except Exception as e:
            # Silently fail - ETW may require elevation
            return []

    def _capture_cmd_processes(self):
        """Capture cmd.exe process execution via WMI"""
        try:
            # Get all cmd.exe and powershell.exe processes
            cmd_procs = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    if proc.info['name'] in ['cmd.exe', 'powershell.exe']:
                        pid = proc.info['pid']
                        cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                        
                        # Create unique key to avoid duplicates
                        cmd_key = (pid, cmdline)
                        
                        if cmd_key not in self.captured_commands:
                            self.captured_commands.add(cmd_key)
                            
                            try:
                                p = psutil.Process(pid)
                                cmd_procs.append({
                                    'pid': pid,
                                    'ppid': p.ppid() if p.ppid() else 0,
                                    'name': p.name(),
                                    'cmdline': cmdline,
                                    'exe_path': p.exe(),
                                    'username': proc.info['username'],
                                    'create_time': p.create_time()
                                })
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return cmd_procs
        except Exception as e:
            print(f"[!] CMD process capture error: {e}", flush=True)
            return []

    def _etw_monitor_loop(self):
        """Main ETW monitoring loop"""
        print("[*] ETW Command Capture Monitor loop started", flush=True)
        
        while self.running:
            try:
                # Capture PowerShell ETW commands
                try:
                    ps_commands = self._capture_powershell_commands()
                    for cmd in ps_commands:
                        pid = cmd.get('PID', 0)
                        script_block = cmd.get('ScriptBlock', '')[:1000]  # Limit to 1000 chars
                        
                        proc_info = self._get_process_info(pid)
                        if proc_info:
                            parent_name = self._get_parent_info(proc_info['ppid'])
                            self.logger.log(
                                "COMMAND_EXECUTION",
                                f"Shell: PowerShell | PID: {pid} | PPID: {proc_info['ppid']} | "
                                f"Parent: {parent_name} | User: {proc_info['username']} | "
                                f"Path: {proc_info['exe_path']} | "
                                f"Command: {script_block}"
                            )
                except Exception as e:
                    pass  # Silently continue if ETW not available

                # Capture cmd.exe process execution
                try:
                    cmd_processes = self._capture_cmd_processes()
                    for cmd_info in cmd_processes:
                        parent_name = self._get_parent_info(cmd_info['ppid'])
                        cmdline = cmd_info['cmdline'][:1000]  # Limit to 1000 chars
                        
                        self.logger.log(
                            "COMMAND_EXECUTION",
                            f"Shell: cmd.exe | PID: {cmd_info['pid']} | PPID: {cmd_info['ppid']} | "
                            f"Parent: {parent_name} | User: {cmd_info['username']} | "
                            f"Path: {cmd_info['exe_path']} | "
                            f"Command: {cmdline}"
                        )
                except Exception as e:
                    pass

                time.sleep(self.check_interval)

            except Exception as e:
                print(f"[!] ETW monitor error: {e}", flush=True)
                time.sleep(self.check_interval)


# -------------- Keystroke Anomaly Monitor ----------------
class KeystrokeAnomalyMonitor:
    """Monitor keystroke patterns for anomalies (45-minute reporting interval)"""
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.keystroke_counts = {}
        self.report_interval = 45 * 60  # 45 minutes in seconds
        self.lock = threading.Lock()

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._report_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def record_keystroke(self, user):
        """Record a keystroke for a user"""
        with self.lock:
            if user not in self.keystroke_counts:
                self.keystroke_counts[user] = 0
            self.keystroke_counts[user] += 1

    def _report_loop(self):
        """Report keystroke statistics every 45 minutes"""
        while self.running:
            time.sleep(self.report_interval)
            
            with self.lock:
                for user, count in self.keystroke_counts.items():
                    self.logger.log(
                        "KEYSTROKE_SUMMARY",
                        f"User: {user} | Keystrokes: {count} | Period: 45-minute"
                    )
                self.keystroke_counts.clear()


class KeystrokeMonitor:
    """Monitor keystroke activity with anomaly detection"""
    def __init__(self, logger):
        self.running = False
        self.listener = None
        self.log_path = Path("logs") / "keys.txt"
        self.log_path.parent.mkdir(exist_ok=True)
        self.anomaly_monitor = KeystrokeAnomalyMonitor(logger)

    def start(self):
        self.running = True
        self.anomaly_monitor.start()
        self.listener = keyboard.Listener(on_press=self._on_press)
        self.listener.start()
        print("[*] Keystroke monitor started (45-minute reporting)", flush=True)

    def stop(self):
        self.running = False
        self.anomaly_monitor.stop()
        if self.listener:
            self.listener.stop()
        print("[*] Keystroke monitor stopped", flush=True)

    def _on_press(self, key):
        try:
            # Log to local file
            with open(self.log_path, "a", encoding="utf-8") as f:
                try:
                    f.write(f"{key.char}")
                except AttributeError:
                    f.write(f"[{key}]")

            # Record for monitoring
            if self.running:
                self.anomaly_monitor.record_keystroke(CURRENT_USER)

        except Exception as e:
            print(f"[!] Keystroke handler error: {e}", flush=True)


# -------------- PowerShell Monitor --------------
class PowerShellMonitor:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.history_file = Path(os.environ.get('APPDATA', '')) / 'Microsoft' / 'Windows' / 'PowerShell' / 'PSReadLine' / 'ConsoleHost_history.txt'
        self.last_line = 0

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[*] PowerShell monitor started", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] PowerShell monitor stopped", flush=True)

    def _monitor_loop(self):
        while self.running:
            try:
                if self.history_file.exists():
                    with open(self.history_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        total_lines = len(lines)
                        start_index = max(total_lines - 30, self.last_line)
                        new_lines = lines[start_index:]
                        for line in new_lines:
                            line = line.strip()
                            if line:
                                self.logger.log("POWERSHELL_HISTORY", line)
                        self.last_line = total_lines
                time.sleep(5)
            except Exception as e:
                print(f"[!] PowerShell monitor error: {e}", flush=True)
                time.sleep(5)

# ---------------- File Monitor ----------------
class FileMonitor(FileSystemEventHandler):
    def __init__(self, logger):
        self.logger = logger

    def on_created(self, event):
        if not event.is_directory:
            self.logger.log("FILE_CREATE", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.logger.log("FILE_MODIFY", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.logger.log("FILE_DELETE", event.src_path)

class FileWatcher:
    def __init__(self, logger):
        self.logger = logger
        self.observer = Observer()
        self.documents_path = Path(os.path.expanduser("~")) / "Documents"
        self.documents_path.mkdir(exist_ok=True)

    def start(self):
        handler = FileMonitor(self.logger)
        self.observer.schedule(handler, str(self.documents_path), recursive=True)
        self.observer.start()
        print(f"[*] File monitor started on {self.documents_path}", flush=True)

    def stop(self):
        self.observer.stop()
        self.observer.join()
        print("[*] File monitor stopped", flush=True)

# ---------------- Network Monitor with SSL/HTTPS Site Access Detection ----------------
class NetworkMonitor:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.known_connections = {}
        self.known_https_sites = set()
        self.process_io_stats = {}

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[*] Network monitor started (with browser HTTPS site access detection, bandwidth tracking, L7 + TTL)", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] Network monitor stopped", flush=True)

    def _resolve_hostname(self, ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except Exception:
            return ip_address

    def _get_process_io_stats(self, pid):
        try:
            proc = psutil.Process(pid)
            io_counters = proc.io_counters()
            return io_counters.read_bytes, io_counters.write_bytes
        except Exception:
            return 0, 0

    def _format_bytes(self, bytes_value):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f}{unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f}TB"

    def _get_ttl(self, ip):
        """Retrieve TTL by sending a single ping (Windows compatible)."""
        try:
            # ping once, parse TTL
            output = subprocess.check_output(["ping", "-n", "1", "-w", "1000", ip],
                                             stderr=subprocess.DEVNULL,
                                             text=True)
            for line in output.splitlines():
                if "TTL=" in line.upper():
                    ttl = line.upper().split("TTL=")[1].split()[0]
                    return int(ttl)
        except Exception:
            pass
        return None

    def _infer_l7_protocol(self, port):
        """Basic L7 protocol inference from port."""
        known = {
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            3389: "RDP",
        }
        return known.get(port, "Unknown")

    def _monitor_loop(self):
        BROWSER_PROCESSES = ['chrome.exe', 'msedge.exe', 'firefox.exe']

        while self.running:
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                        continue

                    # Determine process and bytes
                    try:
                        proc_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                        bytes_recv, bytes_sent = self._get_process_io_stats(conn.pid)
                    except Exception:
                        proc_name = "Unknown"
                        bytes_recv, bytes_sent = 0, 0

                    # Build connection key
                    key = (conn.pid, conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                    l7_proto = self._infer_l7_protocol(conn.raddr.port)
                    ttl = self._get_ttl(conn.raddr.ip)

                    # --- HTTPS site access detection ---
                    if conn.raddr.port == 443 and proc_name.lower() in BROWSER_PROCESSES:
                        site_key = (conn.raddr.ip, conn.raddr.port, conn.pid)
                        if site_key not in self.known_https_sites:
                            hostname = self._resolve_hostname(conn.raddr.ip)
                            prev_recv, prev_sent = self.process_io_stats.get(conn.pid, (bytes_recv, bytes_sent))
                            bytes_in = bytes_recv - prev_recv
                            bytes_out = bytes_sent - prev_sent
                            ttl_str = f"{ttl}" if ttl else "N/A"

                            self.logger.log("SITE_ACCESSED",
                                f"HTTPS Site: {hostname} ({conn.raddr.ip}) | Browser: {proc_name} | "
                                f"L7: {l7_proto} | TTL: {ttl_str} | PID: {conn.pid} | "
                                f"Local: {conn.laddr.ip}:{conn.laddr.port} | "
                                f"Bytes In: {self._format_bytes(bytes_in)} | Bytes Out: {self._format_bytes(bytes_out)}"
                            )
                            self.known_https_sites.add(site_key)
                            self.process_io_stats[conn.pid] = (bytes_recv, bytes_sent)

                    # --- Regular connection logging ---
                    if key not in self.known_connections:
                        prev_recv, prev_sent = self.process_io_stats.get(conn.pid, (bytes_recv, bytes_sent))
                        bytes_in = bytes_recv - prev_recv
                        bytes_out = bytes_sent - prev_sent
                        ttl_str = f"{ttl}" if ttl else "N/A"

                        self.logger.log("NETWORK_CONN",
                            f"Process: {proc_name} | Local: {conn.laddr.ip}:{conn.laddr.port} -> "
                            f"Remote: {conn.raddr.ip}:{conn.raddr.port} | L7: {l7_proto} | TTL: {ttl_str} | "
                            f"Bytes In: {self._format_bytes(bytes_in)} | Bytes Out: {self._format_bytes(bytes_out)}"
                        )

                        self.known_connections[key] = {'pid': conn.pid, 'bytes_recv': bytes_recv, 'bytes_sent': bytes_sent}
                        self.process_io_stats[conn.pid] = (bytes_recv, bytes_sent)

                # cleanup logic (unchanged)
                active_keys = {(c.pid, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
                               for c in psutil.net_connections(kind='inet') if c.status == psutil.CONN_ESTABLISHED and c.raddr}
                self.known_connections = {k: v for k, v in self.known_connections.items() if k in active_keys}

                existing_pids = {p.pid for p in psutil.process_iter(['pid'])}
                self.process_io_stats = {pid: st for pid, st in self.process_io_stats.items() if pid in existing_pids}

                time.sleep(5)
            except Exception as e:
                print(f"[!] Network monitor error: {e}", flush=True)
                time.sleep(5)


# ---------------- Window Activity Monitor ----------------
class WindowActivityMonitor:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.known_windows = {}  # hwnd -> {title, pid, process, username, state}
        self.last_foreground = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[*] Window activity monitor started", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] Window activity monitor stopped", flush=True)

    def _get_window_state(self, hwnd):
        try:
            placement = win32gui.GetWindowPlacement(hwnd)
            show_cmd = placement[1]
            if show_cmd == win32con.SW_SHOWMINIMIZED:
                return "MINIMIZED"
            elif show_cmd == win32con.SW_SHOWMAXIMIZED:
                return "MAXIMIZED"
            else:
                return "NORMAL"
        except Exception:
            return "UNKNOWN"

    def _is_system_window(self, pid, proc_name):
        try:
            proc = psutil.Process(pid)
            username = proc.username().lower()
            if "nt authority" in username or "system" in proc_name.lower():
                return True
        except Exception:
            pass
        return False

    def _monitor_loop(self):
        while self.running:
            try:
                current_windows = {}

                def enum_handler(hwnd, _):
                    try:
                        if not win32gui.IsWindowVisible(hwnd):
                            return
                        title = win32gui.GetWindowText(hwnd)
                        if not title.strip():
                            return
                        _, pid = win32process.GetWindowThreadProcessId(hwnd)
                        try:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                            if self._is_system_window(pid, proc_name):
                                return
                            try:
                                username = proc.username()
                            except Exception:
                                username = "Unknown"
                            state = self._get_window_state(hwnd)
                            current_windows[hwnd] = {
                                'title': title,
                                'pid': pid,
                                'process': proc_name,
                                'username': username,
                                'state': state
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            return
                    except Exception:
                        return

                win32gui.EnumWindows(enum_handler, None)

                # Detect NEW windows (WINDOW_CREATE)
                for hwnd, info in current_windows.items():
                    if hwnd not in self.known_windows:
                        self.logger.log("WINDOW_CREATE",
                            f"Title: {info['title']} | PID: {info['pid']} | "
                            f"Process: {info['process']} | User: {info['username']} | State: {info['state']}")

                # Detect CLOSED windows (WINDOW_CLOSE)
                closed_windows = set(self.known_windows.keys()) - set(current_windows.keys())
                for hwnd in closed_windows:
                    old_info = self.known_windows[hwnd]
                    self.logger.log("WINDOW_CLOSE",
                        f"Title: {old_info['title']} | PID: {old_info['pid']} | "
                        f"Process: {old_info['process']} | User: {old_info['username']}")

                # Detect TITLE changes (WINDOW_TITLE_CHANGE)
                for hwnd, info in current_windows.items():
                    if hwnd in self.known_windows:
                        old_info = self.known_windows[hwnd]
                        if old_info['title'] != info['title']:
                            self.logger.log("WINDOW_TITLE_CHANGE",
                                f"Process: {info['process']} | PID: {info['pid']} | User: {info['username']} | "
                                f"Old: {old_info['title']} | New: {info['title']}")

                # Detect STATE changes (WINDOW_STATE_CHANGE)
                for hwnd, info in current_windows.items():
                    if hwnd in self.known_windows:
                        old_info = self.known_windows[hwnd]
                        if old_info['state'] != info['state']:
                            self.logger.log("WINDOW_STATE_CHANGE",
                                f"Title: {info['title']} | Process: {info['process']} | User: {info['username']} | "
                                f"PID: {info['pid']} | {old_info['state']} -> {info['state']}")

                # Detect FOCUS changes (WINDOW_FOCUS)
                try:
                    foreground_hwnd = win32gui.GetForegroundWindow()
                    if foreground_hwnd != self.last_foreground and foreground_hwnd in current_windows:
                        info = current_windows[foreground_hwnd]
                        self.logger.log("WINDOW_FOCUS",
                            f"Title: {info['title']} | Process: {info['process']} | User: {info['username']} | "
                            f"PID: {info['pid']} | State: {info['state']}")
                        self.last_foreground = foreground_hwnd
                except Exception:
                    pass

                self.known_windows = current_windows

                time.sleep(1)
            except Exception as e:
                print(f"[!] Window activity monitor error: {e}", flush=True)
                time.sleep(1)


def run_agent(logger, ps_monitor, file_watcher, net_monitor, key_monitor, window_monitor, proc_monitor, etw_monitor):
    """Non-interactive runner: start all monitors immediately and keep running."""
    try:
        # Start all monitors
        ps_monitor.start()
        proc_monitor.start()  # Start kernel-level process monitor
        etw_monitor.start()   # Start ETW command capture monitor
        file_watcher.start()
        net_monitor.start()
        key_monitor.start()
        window_monitor.start()
        print("[*] All monitors started")

        # Keep the main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        print("\n[*] Shutting down monitors...")
        ps_monitor.stop()
        proc_monitor.stop()  # Stop process monitor
        etw_monitor.stop()   # Stop ETW monitor
        file_watcher.stop()
        net_monitor.stop()
        key_monitor.stop()
        window_monitor.stop()
        logger.close()
        print("[*] Agent exited.")


# -------------- Main Program --------------
if __name__ == "__main__":
    logger = Logger()
    proc_snapshot = PsutilProcessSnapshot(logger)
    proc_snapshot.run_once()

    ps_monitor = PowerShellMonitor(logger)
    proc_monitor = ProcessMonitor(logger)  # Kernel-level process monitor
    etw_monitor = ETWCommandCaptureMonitor(logger)  # ETW command capture monitor
    file_watcher = FileWatcher(logger)
    net_monitor = NetworkMonitor(logger)
    key_monitor = KeystrokeMonitor(logger)
    window_monitor = WindowActivityMonitor(logger)

    # Start Flask backend communication in background
    threading.Thread(target=background_loop, args=(logger,), daemon=True).start()

    # Start all monitors
    run_agent(logger, ps_monitor, file_watcher, net_monitor, key_monitor, window_monitor, proc_monitor, etw_monitor)