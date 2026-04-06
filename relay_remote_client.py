#!/usr/bin/env python3
"""
Relay Remote Client - Connects to Closeli relay servers and receives camera
video/audio feeds. Auto-discovers all cameras bound to the account.

Architecture (from Ghidra reverse engineering of libtcpbuffer.so):
  Connection 1 (type=6): XMPP/control session - sends LIVE_VIEW commands
  Connection 2 (type=2): Data session - receives MediaPackage video/audio

Both connections go to the same relay IP:port via raw TLS (NOT WebSocket).

Usage:
  python3 relay_remote_client.py                 # Auto-discover all cameras
  python3 relay_remote_client.py -p 8080         # HTTP port
  python3 relay_remote_client.py -d xxxxS_abc123 # Single camera only
  python3 relay_remote_client.py --discover-only  # List cameras, then exit

Endpoints:
  http://localhost:8080/                        - Index (all cameras)
  http://localhost:8080/video/<device_id>       - MJPEG video stream
  http://localhost:8080/audio/<device_id>       - WAV audio stream
  http://localhost:8080/status                  - All cameras status JSON
  http://localhost:8080/status/<device_id>      - Single camera status
"""

import argparse
import hashlib
import json
import os
import queue
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn, TCPServer


# ============================================================================
# Config
# ============================================================================
def load_dotenv():
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip(); value = value.strip()
                    if value and value[0] in ('"', "'") and value[-1] == value[0]:
                        value = value[1:-1]
                    os.environ.setdefault(key, value)

load_dotenv()

EMAIL = os.environ.get("CLOSELI_EMAIL", os.environ.get("USER_EMAIL", ""))
PASSWORD = os.environ.get("CLOSELI_PASSWORD", os.environ.get("PASSWORD", ""))
PRODUCT_KEY = os.environ.get("PRODUCT_KEY", "")
PRODUCT_SECRET = os.environ.get("PRODUCT_SECRET", "")
CAMERA_ID = os.environ.get("DEFAULT_DEVICE_ID", os.environ.get("CAMERA1_DEVICE_ID", ""))
DEVICE_UUID = f"ANDRC_{os.urandom(6).hex()}"

API_HOST = "api.icloseli.com"
ESD_HOST = "esd.icloseli.com"

# Colors
class C:
    H = '\033[95m'; B = '\033[94m'; G = '\033[92m'; Y = '\033[93m'
    R = '\033[91m'; CY = '\033[96m'; E = '\033[0m'; BD = '\033[1m'

def log(msg, cat="INFO"):
    ts = time.strftime("%H:%M:%S")
    colors = {"ERROR": C.R, "OK": C.G, "WARN": C.Y, "VIDEO": C.CY,
              "AUDIO": C.CY, "XMPP": C.B, "DATA": C.H, "API": C.Y, "RELAY": C.CY}
    cc = colors.get(cat, C.E)
    print(f"{C.H}[{ts}]{C.E} {cc}[{cat}]{C.E} {msg}")


# ============================================================================
# Protobuf encoding/decoding
# ============================================================================
def encode_varint(v):
    r = []
    while v > 0x7f:
        r.append((v & 0x7f) | 0x80)
        v >>= 7
    r.append(v & 0x7f)
    return bytes(r)

def pb_string(field_num, value):
    """Encode protobuf string field. Always sends the field (even if empty)."""
    tag = (field_num << 3) | 2
    encoded = value.encode('utf-8') if isinstance(value, str) else value
    return encode_varint(tag) + encode_varint(len(encoded)) + encoded

def pb_varint(field_num, value):
    return encode_varint((field_num << 3) | 0) + encode_varint(value)

def pb_submsg(field_num, data):
    tag = (field_num << 3) | 2
    return encode_varint(tag) + encode_varint(len(data)) + data

def decode_varint(buf, off):
    result = shift = 0
    while off < len(buf):
        b = buf[off]; off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, off
        shift += 7
    return None, off

def decode_protobuf(buf):
    """Minimal protobuf decoder → dict of field_num → value."""
    fields = {}
    off = 0
    while off < len(buf):
        tag, off = decode_varint(buf, off)
        if tag is None: break
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            val, off = decode_varint(buf, off)
        elif wt == 2:
            length, off = decode_varint(buf, off)
            val = buf[off:off+length]; off += length
        elif wt == 5:
            val = struct.unpack('<I', buf[off:off+4])[0]; off += 4
        elif wt == 1:
            val = struct.unpack('<Q', buf[off:off+8])[0]; off += 8
        else:
            break
        fields[fn] = val
    return fields


# ============================================================================
# Relay Message Builders
# ============================================================================
MSG_TYPES = {1: "REQUEST", 2: "RESPONSE", 3: "START", 4: "MEDIAPACKAGE",
             5: "PING", 6: "PONG", 7: "SERVERCMD", 9: "CLIENTCMD",
             10: "IPCAMCMD", 15: "MESSAGECMD"}

def build_type6_auth(email, device_uuid, token, product_key, room_id, unified_id):
    """Build RelayMessage Request type=6 (XMPP/control session)."""
    ts = int(time.time() * 1000)
    req = b''
    req += pb_string(1, email)
    req += pb_string(2, "")          # password (must be present)
    req += pb_string(3, device_uuid)
    req += pb_string(4, device_uuid)
    req += pb_string(5, f"{ts}_.raw")
    req += pb_string(6, "ipcamcodec01")
    req += pb_varint(7, 6)           # type = 6
    req += pb_varint(8, 1)           # use_zlib = true
    req += pb_string(9, "13.1")      # version
    req += pb_string(11, "websocket") # channel_name
    req += pb_string(13, token)       # cloud_token
    req += pb_string(15, unified_id)
    req += pb_varint(16, 4)          # head_len
    req += pb_string(20, product_key)
    req += pb_string(25, room_id)    # room_id = uid
    req += pb_varint(27, 0)          # channel_no
    return pb_varint(1, 1) + pb_submsg(2, req)


def build_type2_auth(email, device_uuid, camera_id, token, product_key,
                     product_secret, unified_id, channel_no=0):
    """Build RelayMessage Request type=2 (data session)."""
    ts = int(time.time() * 1000)
    flow_info = f"tId={device_uuid};nt=1;tt=1;nst=1;ver=13.1;did={device_uuid}"
    req = b''
    req += pb_string(1, email)
    req += pb_string(2, "")
    req += pb_string(3, device_uuid)
    req += pb_string(4, device_uuid)
    req += pb_string(5, f"{ts}_{camera_id}.raw")
    req += pb_string(6, "ipcamcodec01")
    req += pb_varint(7, 2)
    req += pb_varint(8, 1)
    req += pb_string(9, "13.1")
    req += pb_string(11, "720p")
    req += pb_string(12, camera_id)
    req += pb_string(13, token)
    req += pb_string(15, unified_id)
    req += pb_varint(16, 4)
    req += pb_varint(18, 960)
    req += pb_varint(19, 540)
    req += pb_string(20, product_key)
    req += pb_string(21, product_secret)
    req += pb_varint(22, 0)          # is_manage_event = false
    req += pb_varint(27, channel_no)
    req += pb_string(28, flow_info)
    return pb_varint(1, 1) + pb_submsg(2, req)


def build_ping():
    """Build PING message (type=5)."""
    return bytes.fromhex('080532020800')

def build_pong():
    """Build PONG message (type=6)."""
    return bytes.fromhex('080632020800')


def build_xmpp_live_view(camera_id, device_uuid, email):
    """Build XMPP 1792/222 LIVE_VIEW request.

    Uses the SERVERCMD format (type=7) with field 8 containing the inner message.
    This matches the exact format from MITM captures of the real app.

    Inner: { field1=0, field2=33, field3=client_id, field4=0, field6=JSON, field10=session }
    Outer: RelayMessage { message_type=7, field8=inner }
    """
    import random
    msg_session = random.randint(10000000, 99999999)

    payload = json.dumps({
        "msgSession": msg_session,
        "msgSequence": 0,
        "msgCategory": "camera",
        "msgTimeStamp": int(time.time() * 1000),
        "msgContent": {
            "request": 1792,
            "subRequest": 222,
            "requestParams": {},
        },
    }, separators=(',', ':')).encode('utf-8')

    client_id_bytes = device_uuid.lower().encode('utf-8')

    # Inner message (XMPP-style)
    inner = pb_varint(1, 0)                           # type = 0
    inner += pb_varint(2, 33)                          # sub-type = 33 (0x21)
    inner += pb_string(3, client_id_bytes)             # client_id
    inner += pb_varint(4, 0)                           # field4 = 0
    inner += pb_string(6, payload)                     # JSON payload
    inner += pb_varint(10, msg_session)                # msgSession

    # Outer: RelayMessage { message_type=7, field8=inner }
    msg = pb_varint(1, 7)                              # message_type = SERVERCMD(7)
    msg += pb_submsg(8, inner)                          # field 8 = inner message
    return msg


def build_xmpp_relay_count(camera_id, device_uuid):
    """Build XMPP 1793/152 relay count notification.

    Same SERVERCMD format as LIVE_VIEW.
    """
    import random
    msg_session = random.randint(10000000, 99999999)

    payload = json.dumps({
        "msgSession": msg_session,
        "msgTimeStamp": int(time.time() * 1000),
        "msgSequence": 0,
        "msgContent": {
            "subRequest": 152,
            "request": 1793,
            "requestParams": {
                "Max_count": 3,
                "Relay_max_count": 1,
                "Relay_live_count": 1,
            },
            "channelName": "720p",
        },
        "msgCategory": "camera",
    }, separators=(',', ':')).encode('utf-8')

    client_id_bytes = device_uuid.lower().encode('utf-8')

    inner = pb_varint(1, 0)
    inner += pb_varint(2, 33)
    inner += pb_string(3, client_id_bytes)
    inner += pb_varint(4, 0)
    inner += pb_string(6, payload)
    inner += pb_varint(10, msg_session)

    msg = pb_varint(1, 7)
    msg += pb_submsg(8, inner)
    return msg


def build_clientcmd_live_view(camera_id, device_uuid):
    """Build LIVE_VIEW 1792/222 as CLIENTCMD (type=9, field 10).

    Exact format from Frida capture of the real app:
    RelayMessage { message_type=9(CLIENTCMD), field10=ClientCmd }
    ClientCmd { field1=33(0x21), field2=camera_id, field5=JSON, field10=session }
    """
    import random
    msg_session = random.randint(10000000, 99999999)
    payload = json.dumps({
        "msgSession": msg_session,
        "msgSequence": 0,
        "msgCategory": "camera",
        "msgTimeStamp": int(time.time() * 1000),
        "msgContent": {
            "request": 1792,
            "subRequest": 222,
            "requestParams": {},
        },
    }, separators=(',', ':'))

    # ClientCmd sub-message (goes in field 10 of RelayMessage)
    cc = pb_varint(1, 33)                             # sub-type = 33 (0x21)
    cc += pb_string(2, camera_id)                      # destination = camera
    cc += pb_string(5, payload)                        # JSON payload
    cc += pb_varint(10, msg_session)                   # session ID

    # RelayMessage
    msg = pb_varint(1, 9)                              # message_type = CLIENTCMD(9)
    msg += pb_submsg(10, cc)                            # field 10 = ClientCmd
    return msg


def build_clientcmd_handshake(device_uuid):
    """Build handshake CLIENTCMD (type=9, sub-type=1).

    Sent on data connection after auth.
    """
    cc = pb_varint(1, 1)                              # sub-type = 1
    cc += pb_string(2, device_uuid)                    # device_uuid

    msg = pb_varint(1, 9)
    msg += pb_submsg(10, cc)
    return msg


def build_clientcmd_live_count(device_uuid):
    """Build live_count CLIENTCMD (type=9, sub-type=30).

    Sent on data connection to indicate live view active.
    """
    payload = json.dumps({"live_count": True}, separators=(',', ':'))

    cc = pb_varint(1, 30)                             # sub-type = 30 (0x1e)
    cc += pb_string(2, device_uuid)                    # device_uuid
    cc += pb_string(5, payload)                        # JSON

    msg = pb_varint(1, 9)
    msg += pb_submsg(10, cc)
    return msg


def build_p2pcmd_server_info(device_uuid, unified_id):
    """Build P2PCMD server info (type=11, field 12).

    Sent on data connection after auth to register with relay.
    """
    payload = json.dumps({
        "serverType": 3,
        "userId": "yvKrhg",  # This seems to be a fixed/derived value
    }, separators=(',', ':'))

    inner = pb_varint(1, 3)                           # type = 3
    inner += pb_varint(2, 1)                           # field2 = 1
    inner += pb_string(3, "server")                    # field3
    inner += pb_string(4, device_uuid)                 # device_uuid
    inner += pb_string(5, payload)                     # JSON
    inner += pb_string(6, unified_id)                  # unified_id
    inner += pb_varint(7, 0)                           # field7 = 0

    msg = pb_varint(1, 11)                             # P2PCMD
    msg += pb_submsg(12, inner)                         # field 12
    return msg


# ============================================================================
# API signing + login
# ============================================================================
def _sign_md5v3(secret, json_str, exclude_field="sig"):
    params = json.loads(json_str)
    keys = sorted(params.keys(), key=str.lower)
    sb = secret
    for k in keys:
        if k.lower() == exclude_field.lower():
            continue
        v = params[k]
        if isinstance(v, (list, dict)):
            v = json.dumps(v, separators=(',', ':'))
        v = str(v) if v is not None else ''
        if not v: continue
        sb += f"&{k}={v}"
    return hashlib.md5(sb.encode('utf-8')).hexdigest()


def api_login(email, password, device_uuid, product_key, product_secret):
    """Login → (token, uid, unified_id)."""
    params = {
        "client_id": product_key,
        "device_id": device_uuid,
        "device_name": device_uuid,
        "email": email,
        "login_type": "0",
        "password": password,
    }
    params["sig"] = _sign_md5v3(product_secret, json.dumps(params, separators=(',', ':')))

    data = urllib.parse.urlencode(params).encode('utf-8')
    headers = {
        'User-Agent': 'IOT CLINET 1.0',
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
        'Host': API_HOST,
    }
    log(f"Logging in as {email}...", "API")

    ctx = ssl.create_default_context()
    req = urllib.request.Request(f"https://{API_HOST}/core/v1/auth/login",
                                data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            result = json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        log(f"Login HTTP {e.code}: {e.read().decode('utf-8', errors='replace')}", "ERROR")
        return None, None, None

    token = result.get('token')
    uid = str(result.get('uid', ''))
    unified_id = result.get('unifiedId', f"{email}{int(time.time() * 1000)}")

    if not token:
        log(f"Login failed: {result}", "ERROR")
        return None, None, None

    log(f"Login OK: token={token[:16]}..., uid={uid}", "OK")
    return token, uid, unified_id


def discover_relay(camera_id, product_key, product_secret):
    """Find relay the camera is currently on → (host, port)."""
    body = {
        "device_list": [{"device_id": camera_id}],
        "productKey": product_key,
    }
    body["sig"] = _sign_md5v3(product_secret, json.dumps(body, separators=(',', ':')), "sig")
    form_data = {}
    for k, v in body.items():
        form_data[k] = json.dumps(v, separators=(',', ':')) if isinstance(v, (list, dict)) else str(v)

    url = f"https://{ESD_HOST}/lookup/v6/getRelayIPList"
    data = urllib.parse.urlencode(form_data).encode('utf-8')
    headers = {
        'User-Agent': 'IOT CLINET 1.0',
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
        'Host': ESD_HOST,
    }
    log(f"Discovering relay for {camera_id}...", "API")

    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
        result = json.loads(resp.read().decode('utf-8'))

    cam_data = result.get('data', {}).get(camera_id, [])
    if not cam_data:
        log(f"Camera not on any relay. Response: {result}", "ERROR")
        return None, None

    entry = cam_data[0]
    host = entry.get('public_ip')
    port = int(entry.get('download_port', entry.get('port', 50321)))
    log(f"Camera relay: {host}:{port} (region={entry.get('region')})", "OK")
    return host, port


# ============================================================================
# DES/ECB encryption for ESD API
# ============================================================================
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad as _pkcs5_pad

def des_ecb_encrypt(key, plaintext):
    """DES/ECB/PKCS5 encrypt, returns hex string."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(_pkcs5_pad(plaintext, DES.block_size)).hex()


_DES_KEY = b"0P7Z4VfP"

def get_device_list(token):
    """Fetch list of cameras bound to account.

    Returns list of device dicts with keys: deviceid, devicename, onlineStatus, iplist, etc.
    """
    payload = json.dumps({"token": token}, separators=(',', ':'))
    encrypted = des_ecb_encrypt(_DES_KEY, payload)
    body = urllib.parse.urlencode({"jsonObject": encrypted}).encode('utf-8')
    headers = {
        'User-Agent': 'IOT CLINET 1.0',
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
        'Host': ESD_HOST,
    }
    ctx = ssl.create_default_context()
    url = f"https://{ESD_HOST}/lecam/service/device/deviceList"
    req = urllib.request.Request(url, data=body, headers=headers, method='POST')
    log("Fetching device list...", "API")
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        result = json.loads(resp.read().decode('utf-8'))

    if result.get('failflag') != '0':
        log(f"Device list failed: {result.get('failmsg')}", "ERROR")
        return []

    devices = result.get('devicelist', [])
    log(f"Found {len(devices)} camera(s)", "OK")
    for d in devices:
        status = d.get('onlineStatus', 'unknown')
        log(f"  {d['deviceid']} \"{d.get('devicename', '?')}\" [{status}]", "OK")
    return devices


# ============================================================================
# TLS connection helper
# ============================================================================
def create_tls_connection(host, port, timeout=15):
    """Create raw TLS connection to relay."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    raw.connect((host, port))
    tls = ctx.wrap_socket(raw, server_hostname=host)
    return tls


def send_relay_msg(sock, protobuf_msg):
    """Send length-prefixed protobuf message."""
    sock.sendall(struct.pack('>I', len(protobuf_msg)) + protobuf_msg)


def recv_relay_msg(sock, timeout=10):
    """Receive one length-prefixed protobuf message. Returns (msg_type, fields, raw)."""
    sock.settimeout(timeout)
    header = b''
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None, None, None
        header += chunk

    msg_len = struct.unpack('>I', header)[0]
    if msg_len > 2 * 1024 * 1024:
        return None, None, None

    data = b''
    while len(data) < msg_len:
        chunk = sock.recv(min(msg_len - len(data), 65536))
        if not chunk:
            break
        data += chunk

    fields = decode_protobuf(data)
    msg_type = fields.get(1)
    return msg_type, fields, data


# ============================================================================
# Relay Remote Client
# ============================================================================
class RelayRemoteClient:
    def __init__(self, relay_host, relay_port, camera_id, device_uuid,
                 email, token, uid, unified_id, product_key, product_secret):
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.camera_id = camera_id
        self.device_uuid = device_uuid
        self.email = email
        self.token = token
        self.uid = uid
        self.unified_id = unified_id
        self.product_key = product_key
        self.product_secret = product_secret

        # Sockets
        self.ctrl_sock = None   # type=6 (XMPP/control)
        self.data_sock = None   # type=2 (video/audio)

        # State
        self.connected = False
        self.streaming = False
        self.frame_count = 0
        self.audio_count = 0
        self.connect_time = None

        # Video - latest_frame for snapshot, broadcaster for MJPEG streaming
        self.video_lock = threading.Lock()
        self.latest_frame = None
        self.video_broadcaster = StreamBroadcaster("video")
        self.audio_broadcaster = StreamBroadcaster("audio")

    def connect(self):
        """Establish both relay connections and trigger video."""
        log(f"Connecting to {self.relay_host}:{self.relay_port}", "RELAY")
        log(f"  Camera:  {self.camera_id}", "RELAY")
        log(f"  Client:  {self.device_uuid}", "RELAY")

        # 1. Type=6 auth (control/XMPP session)
        log("Opening type=6 control session...", "RELAY")
        self.ctrl_sock = create_tls_connection(self.relay_host, self.relay_port)
        auth6 = build_type6_auth(self.email, self.device_uuid, self.token,
                                  self.product_key, self.uid, self.unified_id)
        send_relay_msg(self.ctrl_sock, auth6)

        msg_type, fields, raw = recv_relay_msg(self.ctrl_sock)
        if msg_type != 2:  # RESPONSE
            log(f"Type=6 auth failed: msg_type={msg_type}", "ERROR")
            return False

        resp = decode_protobuf(fields.get(3, b'')) if isinstance(fields.get(3), bytes) else {}
        result = resp.get(1, -1)
        if result != 0:
            log(f"Type=6 auth rejected: result={result}", "ERROR")
            return False
        log(f"Type=6 auth OK (result=0, head_len={resp.get(7, '?')})", "OK")

        # 2. Type=2 auth (data session)
        log("Opening type=2 data session...", "RELAY")
        self.data_sock = create_tls_connection(self.relay_host, self.relay_port)
        auth2 = build_type2_auth(self.email, self.device_uuid, self.camera_id,
                                  self.token, self.product_key, self.product_secret,
                                  self.unified_id)
        send_relay_msg(self.data_sock, auth2)

        msg_type, fields, raw = recv_relay_msg(self.data_sock)
        if msg_type != 2:
            log(f"Type=2 auth failed: msg_type={msg_type}", "ERROR")
            return False

        resp2 = decode_protobuf(fields.get(3, b'')) if isinstance(fields.get(3), bytes) else {}
        result2 = resp2.get(1, -1)
        if result2 != 0:
            log(f"Type=2 auth rejected: result={result2}", "ERROR")
            return False
        log(f"Type=2 auth OK (result=0)", "OK")

        self.connected = True
        self.connect_time = time.time()

        # 3. Start background threads
        threading.Thread(target=self._ctrl_loop, daemon=True).start()
        threading.Thread(target=self._data_loop, daemon=True).start()

        # 4. Post-auth sequence + LIVE_VIEW
        time.sleep(1.0)
        self._post_auth_sequence()

        return True

    def _post_auth_sequence(self):
        """Send the full post-auth message sequence (from Frida capture).

        On data connection (type=2):
          1. P2PCMD server info
          2. CLIENTCMD handshake (sub-type=1)
          3. CLIENTCMD live_count (sub-type=30)
        On control connection (type=6):
          4. CLIENTCMD LIVE_VIEW 1792/222 (sub-type=33)
        """
        try:
            log("Sending P2PCMD server info via data...", "RELAY")
            send_relay_msg(self.data_sock,
                          build_p2pcmd_server_info(self.device_uuid, self.unified_id))
        except Exception as e:
            log(f"P2PCMD failed: {e}", "ERROR")

        try:
            log("Sending CLIENTCMD handshake via data...", "RELAY")
            send_relay_msg(self.data_sock, build_clientcmd_handshake(self.device_uuid))
        except Exception as e:
            log(f"Handshake failed: {e}", "ERROR")

        try:
            log("Sending CLIENTCMD live_count via data...", "RELAY")
            send_relay_msg(self.data_sock, build_clientcmd_live_count(self.device_uuid))
        except Exception as e:
            log(f"live_count failed: {e}", "ERROR")

        time.sleep(0.2)
        self._send_live_view()

    def _send_live_view(self):
        """Send LIVE_VIEW 1792/222 via control connection.

        Uses CLIENTCMD (type=9) format with sub-type=33, camera_id as destination.
        Exact format captured from the real Android app via Frida.
        """
        try:
            log("Sending LIVE_VIEW 1792/222 via ctrl (CLIENTCMD)...", "XMPP")
            lv = build_clientcmd_live_view(self.camera_id, self.device_uuid)
            send_relay_msg(self.ctrl_sock, lv)
        except Exception as e:
            log(f"LIVE_VIEW failed: {e}", "ERROR")

    def _ctrl_loop(self):
        """Control channel loop: ping/pong + XMPP message forwarding."""
        log("Control loop started", "XMPP")
        last_ping = time.time()

        while self.connected:
            try:
                msg_type, fields, raw = recv_relay_msg(self.ctrl_sock, timeout=5)

                if msg_type is None:
                    # Check for connection close
                    if raw is None and fields is None:
                        log("Control connection closed", "ERROR")
                        break
                    continue

                if msg_type == 5:  # PING
                    send_relay_msg(self.ctrl_sock, build_pong())
                    log(f"Ctrl PING/PONG", "XMPP")
                elif msg_type == 6:  # PONG (response to our ping)
                    pass  # expected
                elif msg_type == 15:  # MESSAGECMD
                    mc = decode_protobuf(fields.get(16, b'')) if isinstance(fields.get(16), bytes) else {}
                    msg_info = mc.get(2, b'')
                    if isinstance(msg_info, bytes):
                        try:
                            msg_info = msg_info.decode('utf-8')
                        except:
                            msg_info = msg_info.hex()[:80]
                    log(f"XMPP msg: {str(msg_info)[:200]}", "XMPP")
                elif msg_type == 7:  # SERVERCMD
                    log(f"ServerCmd: {raw[:40].hex() if raw else '?'}", "XMPP")
                else:
                    log(f"Ctrl recv type={msg_type} ({MSG_TYPES.get(msg_type, '?')}): "
                        f"{raw[:40].hex() if raw else '?'}", "XMPP")

            except socket.timeout:
                # Send our own ping periodically
                if time.time() - last_ping > 25:
                    try:
                        send_relay_msg(self.ctrl_sock, build_ping())
                        last_ping = time.time()
                    except Exception as e:
                        log(f"Ping failed: {e}", "ERROR")
                        break
            except Exception as e:
                log(f"Control error: {e}", "ERROR")
                break

        self.connected = False
        log("Control loop ended", "WARN")

    def _data_loop(self):
        """Data channel loop: receive MediaPackage and other messages."""
        log("Data loop started", "DATA")
        head_len = 4  # from type=6 auth response field 7

        while self.connected:
            try:
                msg_type, fields, raw = recv_relay_msg(self.data_sock, timeout=5)

                if msg_type is None:
                    if raw is None and fields is None:
                        log("Data connection closed", "ERROR")
                        break
                    continue

                if msg_type == 5:  # PING
                    send_relay_msg(self.data_sock, build_pong())
                elif msg_type == 6:  # PONG
                    pass  # response to our ping
                elif msg_type == 4:  # MEDIAPACKAGE
                    self._handle_media_package(fields)
                elif msg_type == 15:  # MESSAGECMD (XMPP forwarded to data)
                    mc = decode_protobuf(fields.get(16, b'')) if isinstance(fields.get(16), bytes) else {}
                    msg_info = mc.get(2, b'')
                    if isinstance(msg_info, bytes):
                        try:
                            msg_info = msg_info.decode('utf-8')
                        except:
                            msg_info = msg_info.hex()[:80]
                    log(f"Data XMPP: {str(msg_info)[:200]}", "DATA")
                elif msg_type == 7:  # SERVERCMD
                    log(f"Data ServerCmd: {raw[:40].hex() if raw else '?'}", "DATA")
                elif msg_type == 3:  # START
                    log("START message received - camera is sending!", "OK")
                    self.streaming = True
                else:
                    log(f"Data recv type={msg_type} ({MSG_TYPES.get(msg_type, '?')}): "
                        f"{len(raw) if raw else 0}B", "DATA")

            except socket.timeout:
                # Send ping on data channel too
                try:
                    send_relay_msg(self.data_sock, build_ping())
                except Exception as e:
                    log(f"Data ping failed: {e}", "ERROR")
                    break
            except Exception as e:
                log(f"Data error: {e}", "ERROR")
                break

        self.connected = False
        log("Data loop ended", "WARN")

    def _handle_media_package(self, fields):
        """Process MediaPackage message.

        RelayMessage field 5 = MediaPackage sub-message:
          package_type(1): 1=audio, 2=video, 3=header, 4=control
          control_flag(2), sync(3), time_span(4), data_size(5),
          start_time(6), seq_num(7), data(8), device_id(9), ipcam_time(10)
        """
        # MediaPackage is in field 5 of RelayMessage (tag 0x2a)
        mp_raw = fields.get(5)
        if isinstance(mp_raw, bytes) and len(mp_raw) > 4:
            mp = decode_protobuf(mp_raw)
        else:
            mp = fields  # fallback: flat message

        pkg_type = mp.get(1, 0)
        data = mp.get(8, b'')
        seq_num = mp.get(7, 0)
        sync = mp.get(3, 0)

        if not isinstance(data, bytes) or len(data) == 0:
            return

        if pkg_type == 2:  # Video (MJPEG)
            jpeg_start = data.find(b'\xff\xd8')
            if jpeg_start >= 0:
                jpeg_end = data.rfind(b'\xff\xd9')
                end_pos = jpeg_end + 2 if jpeg_end >= 0 else len(data)
                jpeg_data = data[jpeg_start:end_pos]
                with self.video_lock:
                    self.latest_frame = jpeg_data
                self.video_broadcaster.broadcast(jpeg_data)
                self.frame_count += 1
                if self.frame_count % 30 == 0:
                    log(f"Frame {self.frame_count} ({len(jpeg_data)}B, "
                        f"sync={sync})", "VIDEO")
            else:
                # Might be encrypted or H.264
                self.frame_count += 1
                if self.frame_count <= 3 or self.frame_count % 100 == 0:
                    log(f"Video #{seq_num}: {len(data)}B (first: {data[:8].hex()})",
                        "VIDEO")

        elif pkg_type == 1:  # Audio
            self.audio_broadcaster.broadcast(data)
            self.audio_count += 1
            if self.audio_count == 1:
                log(f"Audio started ({len(data)}B)", "AUDIO")

    def reconnect_loop(self):
        """Auto-reconnecting wrapper."""
        retry = 0
        while retry < 50:
            if retry > 0:
                wait = min(2 ** retry, 30)
                log(f"Reconnecting in {wait}s (attempt #{retry})...", "WARN")
                time.sleep(wait)

            try:
                success = self.connect()
                if success:
                    retry = 0
                    # Wait until disconnected
                    while self.connected:
                        time.sleep(1)
            except Exception as e:
                log(f"Connection failed: {e}", "ERROR")

            self.connected = False
            self.streaming = False
            self._close_sockets()
            retry += 1

        log("Max retries exceeded", "ERROR")

    def _close_sockets(self):
        for sock in [self.ctrl_sock, self.data_sock]:
            if sock:
                try: sock.close()
                except: pass
        self.ctrl_sock = None
        self.data_sock = None

    def get_status(self):
        return {
            "connected": self.connected,
            "streaming": self.streaming,
            "relay": f"{self.relay_host}:{self.relay_port}",
            "camera_id": self.camera_id,
            "client_id": self.device_uuid,
            "frame_count": self.frame_count,
            "audio_count": self.audio_count,
            "uptime": int(time.time() - self.connect_time) if self.connect_time else 0,
        }


# ============================================================================
# Stream Broadcaster
# ============================================================================
class StreamBroadcaster:
    def __init__(self, name="stream"):
        self.listeners = []
        self.lock = threading.Lock()
        self.name = name

    def add_listener(self):
        q = queue.Queue(maxsize=100)
        with self.lock:
            self.listeners.append(q)
        return q

    def remove_listener(self, q):
        with self.lock:
            if q in self.listeners:
                self.listeners.remove(q)

    def broadcast(self, data):
        with self.lock:
            for q in self.listeners:
                try: q.put_nowait(data)
                except queue.Full: pass


# ============================================================================
# Camera Manager (multi-camera)
# ============================================================================
class CameraManager:
    """Manages multiple RelayRemoteClient instances, one per camera."""

    def __init__(self):
        self.clients = {}   # device_id → RelayRemoteClient
        self.devices = {}   # device_id → device info dict from API
        self._threads = []

    def add_camera(self, device_info, device_uuid, email, token, uid,
                   unified_id, product_key, product_secret):
        """Discover relay and create a client for one camera. Returns True if started."""
        device_id = device_info['deviceid']
        name = device_info.get('devicename', device_id)

        relay_host, relay_port = None, None
        iplist = device_info.get('iplist', [])
        if iplist:
            relay_host = iplist[0].get('relayhost')
            relay_port = int(iplist[0].get('relayport', 50321))

        if not relay_host:
            try:
                relay_host, relay_port = discover_relay(device_id, product_key, product_secret)
            except Exception as e:
                log(f"Relay discovery failed for \"{name}\" ({device_id}): {e}", "WARN")
                return False

        if not relay_host:
            log(f"No relay for \"{name}\" ({device_id}) — camera offline?", "WARN")
            return False

        client = RelayRemoteClient(
            relay_host=relay_host, relay_port=relay_port,
            camera_id=device_id, device_uuid=device_uuid,
            email=email, token=token, uid=uid,
            unified_id=unified_id, product_key=product_key,
            product_secret=product_secret,
        )
        self.clients[device_id] = client
        self.devices[device_id] = device_info

        t = threading.Thread(target=client.reconnect_loop, daemon=True,
                             name=f"relay-{device_id}")
        t.start()
        self._threads.append(t)
        log(f"Started relay for \"{name}\" ({device_id}) → {relay_host}:{relay_port}", "OK")
        return True

    def get_client(self, device_id):
        return self.clients.get(device_id)

    def get_status(self):
        cameras = []
        for did, client in self.clients.items():
            info = self.devices.get(did, {})
            s = client.get_status()
            s['devicename'] = info.get('devicename', '')
            cameras.append(s)
        return {"cameras": cameras, "count": len(cameras)}

    def disconnect_all(self):
        for client in self.clients.values():
            client.connected = False


# ============================================================================
# HTTP Server
# ============================================================================
class ThreadingHTTPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True

class StreamHandler(BaseHTTPRequestHandler):
    manager = None  # CameraManager instance

    def log_message(self, format, *args):
        pass  # Suppress default logging

    def _parse_path(self):
        """Parse /<action>/<device_id> from path. Returns (action, device_id_or_None)."""
        parts = self.path.strip('/').split('/', 1)
        action = parts[0] if parts else ''
        device_id = parts[1] if len(parts) > 1 else None
        return action, device_id

    def _get_client(self, device_id):
        """Get client for device_id. If None and only one camera, use that."""
        mgr = self.__class__.manager
        if not mgr:
            return None
        if device_id:
            return mgr.get_client(device_id)
        if len(mgr.clients) == 1:
            return next(iter(mgr.clients.values()))
        return None

    def _send_404(self, msg="Not found"):
        self.send_response(404)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(msg.encode())

    def do_GET(self):
        action, device_id = self._parse_path()

        if action == 'video':
            cl = self._get_client(device_id)
            if not cl:
                self._send_404("Camera not found")
                return
            self._serve_mjpeg(cl)
        elif action == 'audio':
            cl = self._get_client(device_id)
            if not cl:
                self._send_404("Camera not found")
                return
            self._serve_audio(cl)
        elif action == 'status':
            if device_id:
                cl = self._get_client(device_id)
                if not cl:
                    self._send_404("Camera not found")
                    return
                self._serve_camera_status(cl)
            else:
                self._serve_status()
        elif action == 'trigger':
            cl = self._get_client(device_id)
            if not cl:
                self._send_404("Camera not found")
                return
            self._trigger_live_view(cl)
        else:
            self._serve_index()

    def _serve_index(self):
        mgr = self.__class__.manager
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()

        html = '<html><body>\n<h1>Closeli Remote Relay Client</h1>\n'
        html += '<p><a href="/status">All cameras status (JSON)</a></p>\n<hr>\n'

        if mgr:
            for did, client in mgr.clients.items():
                name = mgr.devices.get(did, {}).get('devicename', did)
                status = 'connected' if client.connected else 'disconnected'
                html += f'<h2>{name} <small>({did}) [{status}]</small></h2>\n'
                html += f'<p><a href="/video/{did}">Video</a> | '
                html += f'<a href="/audio/{did}">Audio</a> | '
                html += f'<a href="/status/{did}">Status</a> | '
                html += f'<a href="/trigger/{did}">Trigger</a></p>\n'
                html += f'<img src="/video/{did}" alt="{name}" style="max-width:640px">\n'
                html += '<hr>\n'

        html += '</body></html>'
        self.wfile.write(html.encode())

    def _serve_mjpeg(self, cl):
        self.send_response(200)
        self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=frame')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

        q = cl.video_broadcaster.add_listener()
        last_frame = None
        try:
            while True:
                try:
                    frame = q.get(timeout=2.0)
                    last_frame = frame
                except queue.Empty:
                    # Relay is reconnecting — serve the last known frame to keep
                    # go2rtc's ffmpeg alive and prevent the RTSP stream from dying.
                    frame = last_frame
                    if frame is None:
                        continue  # No frame ever received yet, just wait
                self.wfile.write(b'--frame\r\nContent-Type: image/jpeg\r\n')
                self.wfile.write(f'Content-Length: {len(frame)}\r\n\r\n'.encode())
                self.wfile.write(frame)
                self.wfile.write(b'\r\n')
        except:
            pass
        finally:
            cl.video_broadcaster.remove_listener(q)

    def _serve_audio(self, cl):
        self.send_response(200)
        self.send_header('Content-Type', 'audio/wav')
        self.end_headers()
        hdr = b'RIFF\xff\xff\xff\xffWAVE'
        hdr += b'fmt ' + struct.pack('<IHHIIHH', 18, 6, 1, 8000, 8000, 1, 8) + b'\x00\x00'
        hdr += b'data\xff\xff\xff\xff'
        self.wfile.write(hdr)
        q = cl.audio_broadcaster.add_listener()
        try:
            while True:
                self.wfile.write(q.get(timeout=5.0))
        except: pass
        finally:
            cl.audio_broadcaster.remove_listener(q)

    def _serve_camera_status(self, cl):
        body = json.dumps(cl.get_status(), indent=2).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_status(self):
        mgr = self.__class__.manager
        status = mgr.get_status() if mgr else {"error": "not initialized"}
        body = json.dumps(status, indent=2).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _trigger_live_view(self, cl):
        if cl.connected:
            cl._send_live_view()
            msg = "LIVE_VIEW triggered"
        else:
            msg = "Not connected"
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(msg.encode())


# ============================================================================
# Main
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description='Closeli Remote Relay Client')
    parser.add_argument('-d', '--device_id', default=CAMERA_ID,
                        help='Camera device ID (omit to auto-discover all)')
    parser.add_argument('-p', '--port', type=int, default=8080, help='HTTP server port')
    parser.add_argument('--discover-only', action='store_true',
                        help='Only list cameras and relays, then exit')
    parser.add_argument('--relay_host', help='Override relay host (single-camera mode)')
    parser.add_argument('--relay_port', type=int, help='Override relay port')
    args = parser.parse_args()

    print("=" * 70)
    print("  Closeli Remote Relay Client")
    print("  Multi-camera auto-discovery")
    print("=" * 70)

    # Validate config
    missing = []
    if not EMAIL: missing.append("CLOSELI_EMAIL")
    if not PASSWORD: missing.append("CLOSELI_PASSWORD")
    if not PRODUCT_KEY: missing.append("PRODUCT_KEY")
    if not PRODUCT_SECRET: missing.append("PRODUCT_SECRET")
    if missing:
        log(f"Required config missing: {', '.join(missing)}", "ERROR")
        log("Set them in .env or environment variables. See .env.example", "ERROR")
        sys.exit(1)

    # Login
    token, uid, unified_id = api_login(EMAIL, PASSWORD, DEVICE_UUID,
                                        PRODUCT_KEY, PRODUCT_SECRET)
    if not token:
        sys.exit(1)

    # Build device list: either single camera or auto-discover
    if args.device_id and args.relay_host:
        # Fully manual single-camera mode
        devices = [{"deviceid": args.device_id, "devicename": args.device_id,
                     "onlineStatus": "available",
                     "iplist": [{"relayhost": args.relay_host,
                                 "relayport": str(args.relay_port or 50321)}]}]
    elif args.device_id:
        # Single camera specified, discover its relay
        devices = [{"deviceid": args.device_id, "devicename": args.device_id,
                     "onlineStatus": "available", "iplist": []}]
    else:
        # Auto-discover all cameras
        devices = get_device_list(token)
        if not devices:
            log("No cameras found on account", "ERROR")
            sys.exit(1)

    if args.discover_only:
        for d in devices:
            did = d['deviceid']
            name = d.get('devicename', '?')
            status = d.get('onlineStatus', '?')
            iplist = d.get('iplist', [])
            relay = f"{iplist[0]['relayhost']}:{iplist[0]['relayport']}" if iplist else "no relay"
            print(f"  {did} \"{name}\" [{status}] {relay}")
        return

    # Start cameras
    manager = CameraManager()
    started = 0
    for d in devices:
        if manager.add_camera(d, DEVICE_UUID, EMAIL, token, uid,
                              unified_id, PRODUCT_KEY, PRODUCT_SECRET):
            started += 1

    if started == 0:
        log("No cameras could be started (all offline?)", "ERROR")
        sys.exit(1)

    StreamHandler.manager = manager

    print()
    print(f"  Cameras:   {started}/{len(devices)} online")
    print(f"  Port:      {args.port}")
    for did in manager.clients:
        name = manager.devices[did].get('devicename', did)
        print(f"  Video:     http://localhost:{args.port}/video/{did}  ({name})")
    print(f"  Status:    http://localhost:{args.port}/status")
    print(f"  Index:     http://localhost:{args.port}/")
    print("=" * 70)
    print()

    server = ThreadingHTTPServer(('0.0.0.0', args.port), StreamHandler)
    log(f"HTTP server on port {args.port}", "OK")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        manager.disconnect_all()
        server.shutdown()


if __name__ == '__main__':
    main()
