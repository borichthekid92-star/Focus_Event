#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
import sqlite3
import subprocess
import time
import configparser
from functools import wraps
from datetime import datetime, timedelta
import json
import uuid
import threading
import logging
import operator
import re
import queue  # For SSE event queue

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

# Session configuration
app.secret_key = config.get('session', 'secret_key', fallback='dev-secret-key-change-me')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
    seconds=config.getint('session', 'session_timeout', fallback=3600)
)

# Database Paths
DB_PATH = "SecurityEvents.db"
ENDPOINTS_DB = "Endpoints.db"
ANALYTICS_DB = "analytics.db"
RULES_DB = "Rules.db"  # New for rules

# Analytics settings (seconds)
ANALYTICS_INTERVAL = config.getint('analytics', 'interval_seconds', fallback=60)

latest_ipconfig_output = ""

# Login attempt tracking
login_attempts = {}

# ==================== CRITICAL: Endpoint Connection Tracking ====================
connected_endpoints = {}
pending_commands = {}
command_results = {}

# Lock for analytics DB writes (sqlite isn't fully threadsafe across connections in some cases)
analytics_db_lock = threading.Lock()

# Lock for SecurityEvents DB writes to transferred_events
security_events_db_lock = threading.Lock()

# SSE event queue for process events
process_event_queue = queue.Queue()

# ==================== DATA TRANSFER TRACKING ====================
# Track data transfer statistics
data_transfer_stats = {
    'total_events_received': 0,
    'last_transfer_time': None,
    'transfers_by_endpoint': {}
}
data_transfer_lock = threading.Lock()

# ==================== INITIALIZATION ====================

def init_security_events_db():
    """Initialize the main SecurityEvents database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            details TEXT
        )
    """)
    
    # New table for process events
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            pid INTEGER,
            ppid INTEGER,
            process_name TEXT,
            command_line TEXT,
            path TEXT,
            username TEXT
        )
    """)
    
    # Table to track transferred events from agents
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transferred_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id TEXT,
            agent_event_id INTEGER,
            timestamp TEXT,
            event_type TEXT,
            details TEXT,
            received_at TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    logger.info("[+] SecurityEvents.db initialized with process_events and transferred_events tables")

def init_endpoints_db():
    """Initialize endpoints database"""
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            id TEXT PRIMARY KEY,
            hostname TEXT,
            ip_address TEXT,
            os_info TEXT,
            last_seen TEXT,
            status TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command_id TEXT,
            endpoint_id TEXT,
            command TEXT,
            result TEXT,
            status TEXT,
            timestamp TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    logger.info("[+] Endpoints.db initialized")

def init_analytics_db():
    """Initialize analytics database"""
    conn = sqlite3.connect(ANALYTICS_DB)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_analytics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            process_name TEXT,
            event_count INTEGER,
            category TEXT,
            rank INTEGER
        )
    """)

    # Optional: keep a short-lived summary table if needed in future
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analytics_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            description TEXT
        )
    """)
    conn.commit()
    conn.close()
    logger.info("[+] analytics.db initialized")

def init_rules_db():
    """Initialize rules database"""
    conn = sqlite3.connect(RULES_DB)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            name TEXT,
            severity TEXT,
            tags TEXT,
            description TEXT,
            version INTEGER,
            created_at TEXT,
            updated_at TEXT,
            detection TEXT,  -- JSON string
            meta TEXT  -- JSON string
        )
    """)
    
    conn.commit()
    conn.close()
    logger.info("[+] Rules.db initialized")

# ==================== AUTHENTICATION ====================

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_login_attempts(username):
    """Check if user is locked out"""
    max_attempts = config.getint('security', 'max_login_attempts', fallback=5)
    lockout_duration = config.getint('security', 'lockout_duration', fallback=300)
    
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        
        if attempts >= max_attempts:
            time_passed = (datetime.now() - last_attempt).total_seconds()
            if time_passed < lockout_duration:
                remaining = int(lockout_duration - time_passed)
                return False, remaining
            else:
                login_attempts[username] = (0, datetime.now())
    
    return True, 0

def record_login_attempt(username, success):
    """Record login attempt"""
    if success:
        if username in login_attempts:
            del login_attempts[username]
    else:
        if username in login_attempts:
            attempts, _ = login_attempts[username]
            login_attempts[username] = (attempts + 1, datetime.now())
        else:
            login_attempts[username] = (1, datetime.now())

# ==================== DATABASE QUERIES ====================

def query_events(search="", event_type="", limit=100):
    """Query security events"""
    conn = None
    rows = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = "SELECT timestamp, event_type, details FROM transferred_events WHERE 1=1"
        params = []
        
        if search:
            query += " AND details LIKE ?"
            params.append(f"%{search}%")
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
    except sqlite3.OperationalError as e:
        logger.error(f"SQLite Error: {e}")
        rows = []
    finally:
        if conn:
            conn.close()
    return rows

def log_event(event_type, details):
    """Log an event to the database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO events (timestamp, event_type, details) VALUES (?, ?, ?)",
                   (timestamp, event_type, details))
    conn.commit()
    conn.close()

# ==================== DATA TRANSFER API ====================

@app.route("/api/data-transfer/receive", methods=["POST"])
def receive_data_transfer():
    """
    Receive data transfer from agent endpoints.
    Expects JSON with:
    {
        "endpoint_id": "xxx",
        "events": [
            {"id": 1, "timestamp": "...", "event_type": "...", "details": "..."},
            ...
        ]
    }
    """
    try:
        data = request.get_json() or {}
        endpoint_id = data.get('endpoint_id')
        events = data.get('events', [])
        
        logger.debug(f"[DEBUG] Received data-transfer request from {endpoint_id} with {len(events)} events")
        
        if not endpoint_id:
            logger.warning("[!] Data transfer request missing endpoint_id")
            return jsonify({'success': False, 'error': 'Missing endpoint_id'}), 400
        
        if not events or not isinstance(events, list):
            logger.warning(f"[!] Data transfer request from {endpoint_id} has invalid events: {events}")
            return jsonify({'success': False, 'error': 'Missing or invalid events array'}), 400
        
        # Insert events into the transferred_events table with locking
        with security_events_db_lock:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            received_at = datetime.now().isoformat()
            
            inserted_count = 0
            errors = []
            
            for event in events:
                try:
                    event_id = event.get('id')
                    timestamp = event.get('timestamp')
                    event_type = event.get('event_type')
                    details = event.get('details')
                    
                    logger.debug(f"[DEBUG] Inserting event: id={event_id}, type={event_type}, endpoint={endpoint_id}")
                    
                    cursor.execute("""
                        INSERT INTO transferred_events 
                        (endpoint_id, agent_event_id, timestamp, event_type, details, received_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        endpoint_id,
                        event_id,
                        timestamp,
                        event_type,
                        details,
                        received_at
                    ))
                    inserted_count += 1
                except Exception as e:
                    error_msg = f"Error inserting event {event.get('id')}: {str(e)}"
                    logger.error(f"[!] {error_msg}")
                    errors.append(error_msg)
                    continue
            
            conn.commit()
            conn.close()
            logger.info(f"[+] Committed {inserted_count} events from endpoint {endpoint_id} to transferred_events")
        
        # Update statistics
        with data_transfer_lock:
            data_transfer_stats['total_events_received'] += inserted_count
            data_transfer_stats['last_transfer_time'] = received_at
            
            if endpoint_id not in data_transfer_stats['transfers_by_endpoint']:
                data_transfer_stats['transfers_by_endpoint'][endpoint_id] = {
                    'total_events': 0,
                    'last_transfer': None
                }
            
            data_transfer_stats['transfers_by_endpoint'][endpoint_id]['total_events'] += inserted_count
            data_transfer_stats['transfers_by_endpoint'][endpoint_id]['last_transfer'] = received_at
        
        logger.info(f"[+] Successfully received {inserted_count} events from endpoint {endpoint_id}")
        
        response = {
            'success': True,
            'events_received': inserted_count,
            'message': f'Successfully received {inserted_count} events'
        }
        
        if errors:
            response['warnings'] = errors
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Data transfer error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/data-transfer/stats", methods=["GET"])
@login_required
def get_data_transfer_stats():
    """Get data transfer statistics"""
    with data_transfer_lock:
        return jsonify({
            'success': True,
            'stats': data_transfer_stats
        })

@app.route("/api/data-transfer/events", methods=["GET"])
@login_required
def get_transferred_events():
    """
    Query transferred events from agents.
    Query parameters:
    - endpoint_id: filter by endpoint (optional)
    - limit: number of events to return (default 100)
    """
    endpoint_id = request.args.get('endpoint_id')
    limit = int(request.args.get('limit', 100))
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        if endpoint_id:
            query = """
                SELECT id, endpoint_id, agent_event_id, timestamp, event_type, details, received_at
                FROM transferred_events
                WHERE endpoint_id = ?
                ORDER BY id DESC
                LIMIT ?
            """
            cursor.execute(query, (endpoint_id, limit))
        else:
            query = """
                SELECT id, endpoint_id, agent_event_id, timestamp, event_type, details, received_at
                FROM transferred_events
                ORDER BY id DESC
                LIMIT ?
            """
            cursor.execute(query, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            events.append({
                'id': row[0],
                'endpoint_id': row[1],
                'agent_event_id': row[2],
                'timestamp': row[3],
                'event_type': row[4],
                'details': row[5],
                'received_at': row[6]
            })
        
        return jsonify({
            'success': True,
            'events': events,
            'count': len(events)
        })
        
    except Exception as e:
        logger.error(f"Error querying transferred events: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
        
# ==================== ENDPOINT MANAGEMENT API ====================

@app.route("/api/endpoint/register", methods=["POST"])
def register_endpoint():
    """Register or update an endpoint"""
    data = request.get_json() or {}
    endpoint_id = data.get('endpoint_id')
    hostname = data.get('hostname')
    ip_address = data.get('ip_address')
    os_info = data.get('os_info')
    
    if not endpoint_id:
        return jsonify({'success': False, 'error': 'Missing endpoint_id'}), 400
    
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT OR REPLACE INTO endpoints (id, hostname, ip_address, os_info, last_seen, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (endpoint_id, hostname, ip_address, os_info, datetime.now().isoformat(), 'active'))
    
    conn.commit()
    conn.close()
    
    with data_transfer_lock:
        connected_endpoints[endpoint_id] = {
            'hostname': hostname,
            'ip': ip_address,
            'last_seen': datetime.now()
        }
    
    logger.info(f"[+] Endpoint registered: {endpoint_id} ({hostname})")
    log_event("ENDPOINT_REGISTERED", f"Endpoint {endpoint_id} ({hostname}) registered from {ip_address}")
    
    return jsonify({'success': True, 'message': 'Endpoint registered'})

@app.route("/api/endpoint/heartbeat", methods=["POST"])
def endpoint_heartbeat():
    """Update endpoint last seen timestamp"""
    data = request.get_json() or {}
    endpoint_id = data.get('endpoint_id')
    
    if not endpoint_id:
        return jsonify({'success': False, 'error': 'Missing endpoint_id'}), 400
    
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    cursor.execute("UPDATE endpoints SET last_seen = ?, status = ? WHERE id = ?",
                   (datetime.now().isoformat(), 'active', endpoint_id))
    conn.commit()
    conn.close()
    
    with data_transfer_lock:
        if endpoint_id in connected_endpoints:
            connected_endpoints[endpoint_id]['last_seen'] = datetime.now()
    
    return jsonify({'success': True})

@app.route("/api/endpoint/get-commands/<endpoint_id>", methods=["GET"])
def get_endpoint_commands(endpoint_id):
    """Get pending commands for an endpoint"""
    commands = []
    
    if endpoint_id in pending_commands:
        commands = pending_commands[endpoint_id]
        # Clear the commands after sending
        pending_commands[endpoint_id] = []
    
    return jsonify({'success': True, 'commands': commands})

@app.route("/api/endpoints/list", methods=["GET"])
@login_required
def list_endpoints():
    """List all registered endpoints"""
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT id, hostname, ip_address, os_info, last_seen, status FROM endpoints")
    rows = cursor.fetchall()
    conn.close()
    
    endpoints = []
    for row in rows:
        endpoints.append({
            'id': row[0],
            'hostname': row[1],
            'ip_address': row[2],
            'os_info': row[3],
            'last_seen': row[4],
            'status': row[5]
        })
    
    return jsonify({'success': True, 'endpoints': endpoints})

@app.route("/api/endpoint/send-command", methods=["POST"])
@login_required
def send_command_to_endpoint():
    """Queue a command for an endpoint"""
    username = session.get('username', 'unknown')
    data = request.get_json() or {}
    endpoint_id = data.get('endpoint_id')
    command = data.get('command')
    
    if not endpoint_id or not command:
        return jsonify({'success': False, 'error': 'Missing endpoint_id or command'}), 400
    
    command_id = str(uuid.uuid4())
    
    if endpoint_id not in pending_commands:
        pending_commands[endpoint_id] = []
    
    pending_commands[endpoint_id].append({
        'command_id': command_id,
        'command': command,
        'timestamp': datetime.now().isoformat()
    })
    
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO command_history (command_id, endpoint_id, command, result, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (command_id, endpoint_id, command, '', 'pending', datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    log_event("COMMAND_QUEUED", f"Command '{command}' queued by {username} for endpoint {endpoint_id}")
    logger.info(f"[+] Command {command_id} queued for {endpoint_id}: {command}")
    
    return jsonify({'success': True, 'command_id': command_id})
    


# ==================== PROCESS STATISTICS ====================

def get_process_stats():
    """Query DB and return process counts and ratios."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Example: assume table `process_events` with columns (id, timestamp, process_name)
    cur.execute("SELECT process_name, COUNT(*) FROM process_events GROUP BY process_name")
    rows = cur.fetchall()
    conn.close()

    if not rows:
        return []

    total = sum(count for _, count in rows)
    stats = []
    for proc, count in rows:
        ratio = round((count / total) * 100, 2)
        stats.append({"process": proc, "count": count, "ratio": ratio})
    return stats

@app.route("/api/risk-stats")
def risk_stats():
    stats = get_process_stats()

    # Bucket processes by ratio
    low_risk = [s for s in stats if s["ratio"] < 1]
    medium_risk = [s for s in stats if 1 <= s["ratio"] < 10]
    high_risk = [s for s in stats if 10 <= s["ratio"] < 30]

    return jsonify({
        "low_risk": sorted(low_risk, key=lambda x: x["ratio"])[:5],
        "medium_risk": sorted(medium_risk, key=lambda x: x["ratio"])[:5],
        "high_risk": sorted(high_risk, key=lambda x: x["ratio"])[:5]
    })

@app.route("/api/command-result/<command_id>", methods=["GET"])
@login_required
def get_command_result(command_id):
    """Get result of executed command"""
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT result, status FROM command_history WHERE command_id = ?
    """, (command_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return jsonify({'success': True, 'result': row[0], 'status': row[1]})
    else:
        return jsonify({'success': False, 'error': 'Command not found'}), 404

@app.route("/api/endpoint/submit-result", methods=["POST"])
def submit_command_result():
    """Endpoint submits command result"""
    data = request.get_json() or {}
    command_id = data.get('command_id')
    result = data.get('result')
    status = data.get('status', 'completed')
    
    if not command_id:
        return jsonify({'success': False, 'error': 'Missing command_id'}), 400
    
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE command_history SET result = ?, status = ? WHERE command_id = ?
    """, (result, status, command_id))
    conn.commit()
    conn.close()
    
    logger.info(f"[+] Command result received for {command_id}: {status}")
    log_event("COMMAND_RESULT", f"Command {command_id} completed with status: {status}")
    
    return jsonify({'success': True})

# ==================== ANALYTICS API ====================

@app.route("/api/analytics/processes", methods=["GET"])
@login_required
def api_get_process_analytics():
    """
    Return most recent analytics rows (optionally filtered by top N and category).
    Example: /api/analytics/processes?limit=10&category=suspicious
    """
    limit = int(request.args.get('limit', 25))
    category = request.args.get('category', None)

    conn = sqlite3.connect(ANALYTICS_DB)
    cursor = conn.cursor()
    query = "SELECT timestamp, process_name, event_count, category, rank FROM process_analytics"
    params = []
    if category:
        query += " WHERE category = ?"
        params.append(category)
    query += " ORDER BY timestamp DESC, rank ASC LIMIT ?"
    params.append(limit)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    results = []
    for ts, pname, cnt, cat, rank in rows:
        results.append({
            'timestamp': ts,
            'process_name': pname,
            'event_count': cnt,
            'category': cat,
            'rank': rank
        })
    return jsonify({'success': True, 'analytics': results})

@app.route("/api/analytics/run", methods=["POST"])
@login_required
def api_run_analytics():
    """
    Trigger analytics run on-demand. Accept JSON body with optional window_minutes and top_n.
    """
    data = request.get_json() or {}
    window_minutes = int(data.get('window_minutes', config.getint('analytics', 'window_minutes', fallback=60)))
    top_n = int(data.get('top_n', config.getint('analytics', 'top_n', fallback=25)))

    # Note: analyze_processes function would need to be defined elsewhere
    # ok, items = analyze_processes(window_minutes=window_minutes, top_n=top_n)
    # if ok:
    #     return jsonify({'success': True, 'items': [{'process': p, 'count': c} for p, c in items]})
    # else:
    #     return jsonify({'success': False, 'error': 'Analytics failed'}), 500
    return jsonify({'success': True, 'message': 'Analytics endpoint placeholder'})

# ==================== Rules ====================

def save_rule(rule, user_id):
    """Save or update a rule in Rules.db"""
    import sqlite3, json
    conn = sqlite3.connect(RULES_DB)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO rules
        (id, user_id, name, severity, tags, description, version,
         created_at, updated_at, detection, meta)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        rule['id'],
        user_id,
        rule['name'],
        rule['severity'],
        json.dumps(rule['tags']),
        rule['description'],
        rule['version'],
        rule['created_at'],
        rule['updated_at'],
        json.dumps(rule['detection']),
        json.dumps(rule['meta'])
    ))
    conn.commit()
    conn.close()
    
@app.route("/api/rules", methods=["GET"])
@login_required
def api_rules():
    user_id = session.get('username')
    data = request.get_json() or {}

    # normalize tags
    tags = data.get('tags', [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(',') if t.strip()]

    rule = {
        'id': str(uuid.uuid4()),
        'name': data.get('name'),
        'severity': data.get('severity', 'medium'),
        'tags': tags,
        'description': data.get('description', ''),
        'version': 1,
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat(),
        'detection': {
            'process_name': data.get('process_name', '.*'),
            'command_line': data.get('command_line', '.*'),
            'username': data.get('username', '.*'),
            'window_title': data.get('window_title', '.*'),
            'ip_address': data.get('ip_address', '.*'),
            'flags': 'i'
        },
        'meta': {'enabled': True, 'hit_count': 0}
    }

    save_rule(rule, user_id)   # <-- persists into Rules.db
    return jsonify(rule), 201

# ==================== LOGIN/LOGOUT ROUTES ====================

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page"""
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check lockout
        allowed, remaining = check_login_attempts(username)
        if not allowed:
            flash(f'Too many failed attempts. Try again in {remaining} seconds.', 'danger')
            return render_template('login.html')
        
        # Simple authentication (replace with proper authentication)
        # Load credentials from config.ini
        config_username = config.get('authentication', 'username', fallback='admin')
        config_password = config.get('authentication', 'password', fallback='admin')
        
        if username == config_username and password == config_password:
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            record_login_attempt(username, True)
            log_event("USER_LOGIN", f"User {username} logged in successfully")
            return redirect(url_for('dashboard'))
        else:
            record_login_attempt(username, False)
            log_event("LOGIN_FAILED", f"Failed login attempt for user {username}")
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route("/logout")
def logout():
    """Logout"""
    username = session.get('username', 'unknown')
    session.clear()
    log_event("USER_LOGOUT", f"User {username} logged out")
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# ==================== MAIN ROUTES ====================

@app.route("/")
@login_required
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')

@app.route("/events")
@login_required
def events():
    """Events page"""
    search = request.args.get('search', '')
    event_type = request.args.get('type', '')
    limit = int(request.args.get('limit', 100))
    
    rows = query_events(search, event_type, limit)
    
    return render_template('events.html', events=rows, search=search, event_type=event_type)

# ==================== ERROR HANDLER ====================

@app.errorhandler(404)
def page_not_found(e):
    """404 handler"""
    return render_template('404.html'), 404

# ==================== STARTUP ====================

def start_background_workers():
    """Start background worker threads"""
    # Add any background workers here
    logger.info("[*] Background workers initialized")
# === ADDED ROUTES FOR REMOTE EXEC PAGE ===

@app.route("/remote_exec")
@login_required
def remote_exec():
    """Render the remote command execution HTML page"""
    return render_template("remote_exec.html")
    

@app.route("/api/execute-command", methods=["POST"])
@login_required
def api_execute_command():
    """Alias route for frontend compatibility with /api/endpoint/send-command"""
    return send_command_to_endpoint()
    
# -----------------------------------------------------
# 5. Agent: Get queued commands
# -----------------------------------------------------

@app.route("/api/endpoint/get-commands/<endpoint_id>", methods=["GET"])
def get_commands(endpoint_id):
    cmds = pending_commands.get(endpoint_id, [])
    pending_commands[endpoint_id] = []  # clear after sending
    return jsonify({"success": True, "commands": cmds})

# -----------------------------------------------------
# 3. Web UI: Poll command result
# -----------------------------------------------------
@app.route("/api/command-result/<command_id>", methods=["GET"])
@login_required
def command_result(command_id):
    conn = sqlite3.connect(ENDPOINTS_DB)
    c = conn.cursor()
    c.execute("SELECT result, status FROM command_history WHERE command_id = ?", (command_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"success": True, "result": row[0], "status": row[1]})
    return jsonify({"success": False, "error": "Not found"}), 404
    
# -----------------------------------------------------
# 6. Agent: Submit command result
# -----------------------------------------------------
@app.route("/api/endpoint/submit-result", methods=["POST"])
def submit_result():
    data = request.get_json() or {}
    command_id = data.get("command_id")
    result = data.get("result")
    status = data.get("status", "completed")

    if not command_id:
        return jsonify({"success": False, "error": "Missing command_id"}), 400

    conn = sqlite3.connect(ENDPOINTS_DB)
    c = conn.cursor()
    c.execute("""
        UPDATE command_history
        SET result = ?, status = ?
        WHERE command_id = ?
    """, (result, status, command_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})
    
if __name__ == "__main__":
    logger.info("[*] Initializing databases...")
    init_security_events_db()
    init_endpoints_db()
    init_analytics_db()
    init_rules_db()

    logger.info("[+] Configuration loaded")
    # Start background workers
    start_background_workers()
    logger.info(f"[+] Starting Flask server on http://0.0.0.0:5000")
    logger.info("[+] Data transfer endpoint active at /api/data-transfer/receive")
    logger.info("[+] Connected endpoints: Use /api/endpoints/list to view")
    app.run(ssl_context=("server.crt", "server.key"), host="0.0.0.0", port=443)
