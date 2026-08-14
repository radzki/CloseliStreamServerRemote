# Closeli / YCC365 Plus Advanced Feature Specifications & Protocol Specs

This specification details reverse-engineered protocol specifications and reference Python implementations for advanced Closeli camera features.

---

## 1. WebCodecs (H.264 / H.265) Hardware Decoding

Serving raw H.264/H.265 Annex B NAL streams directly to browser clients eliminates the CPU and bandwidth overhead of MJPEG transcoding.

### NAL Unit Ingest & Parameter Set Caching
Cameras stream Annex B elementary NAL units over `MediaPackage` (`pkg_type=2`). To allow new browser clients to decode keyframes immediately without waiting for an in-band parameter set, the server caches `SPS`/`PPS` (H.264) or `VPS`/`SPS`/`PPS` (H.265) NAL units and prepends them before IDR keyframes.

```python
def ingest_nal_units(data, video_format, cfg_nals):
    """Scan Annex B chunk for parameter sets and keyframes."""
    key = False
    pos = 0
    n = len(data)
    while pos < n:
        # Search start codes (0x000001 or 0x00000001)
        r = _find_start_code(data, pos)
        if not r:
            break
        hdr_idx, sc_len, sc_pos = r
        hdr = data[hdr_idx]
        nxt = _find_start_code(data, hdr_idx + 1)
        nxt_pos = nxt[2] if nxt else n
        nal = data[sc_pos:nxt_pos]
        
        if video_format == "h265":
            nal_type = (hdr >> 1) & 0x3F
            if nal_type in (32, 33, 34): # VPS, SPS, PPS
                cfg_nals[nal_type] = nal
            if 16 <= nal_type <= 23:     # IRAP / IDR
                key = True
        else:
            nal_type = hdr & 0x1F
            if nal_type in (7, 8):        # SPS, PPS
                cfg_nals[nal_type] = nal
            if nal_type in (5, 7, 8):     # IDR / SPS / PPS
                key = True
        if not nxt:
            break
        pos = nxt[2]
    return key
```

### Browser HTML5 WebCodecs Integration
```js
const decoder = new VideoDecoder({
  output: (frame) => {
    ctx.drawImage(frame, 0, 0, canvas.width, canvas.height);
    frame.close();
  },
  error: (e) => console.error("WebCodecs error:", e)
});

decoder.configure({
  codec: "avc1.42E01E", // H.264 Constrained Baseline @ L3.0
  optimizeForLatency: true
});
```

---

## 2. SD Card Event Timeline & Remote Playback (`api.mossfast.com`)

### Timeline REST API (HMAC-SHA256 Signed)
Requesting recorded timeline events from `https://api.mossfast.com/v1/open/timeline`:

```python
import hmac, hashlib, time, json, requests

def fetch_timeline_events(device_id, access_token, start_ts, end_ts, master_key):
    """Fetch motion/recording event timeline segments."""
    ts = int(time.time() * 1000)
    params = {
        "deviceId": device_id,
        "startTime": start_ts,
        "endTime": end_ts,
        "timestamp": ts,
    }
    # Sign request params with DES master key via HMAC-SHA256
    query_str = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    sig = hmac.new(master_key.encode(), query_str.encode(), hashlib.sha256).hexdigest()
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Signature": sig
    }
    res = requests.get("https://api.mossfast.com/v1/open/timeline", params=params, headers=headers)
    return res.json()
```

### Relay SD Playback Command
Requesting SD card playback sections over the Control TLS Relay socket (`AM_Tcp_Buffer_Get_Timeline_Section_List`):

```python
def build_sd_timeline_request(camera_id, start_time, end_time):
    """Request recorded SD playback segment over relay."""
    payload = json.dumps({
        "msgSession": random.randint(10000000, 99999999),
        "msgSequence": 0,
        "msgCategory": "camera",
        "msgTimeStamp": int(time.time() * 1000),
        "msgContent": {
            "request": 1793,
            "subRequest": 150,  # Timeline section list
            "requestParams": {
                "startTime": start_time,
                "endTime": end_time
            }
        }
    })
    return build_clientcmd(camera_id, payload)
```

---

## 3. Two-Way Audio (Push-To-Talk / PTT / Talkback)

### Audio Package Encoding (`pkg_type=1`)
To talk to the camera, raw microphone audio encoded as 8kHz mono G.711 A-law PCM is sent over the **Data TLS Socket** wrapped in `MediaPackage` (`pkg_type=1`).

```python
def build_media_audio_package(alaw_pcm_bytes, seq_num, timestamp_ms):
    """Build MediaPackage for microphone talkback stream."""
    mp = pb_varint(1, 1)                      # package_type = 1 (audio)
    mp += pb_varint(2, 0)                     # control_flag
    mp += pb_varint(3, 1)                     # sync
    mp += pb_varint(4, timestamp_ms)          # timestamp
    mp += pb_varint(5, len(alaw_pcm_bytes))   # data_size
    mp += pb_varint(7, seq_num)               # sequence number
    mp += pb_string(8, alaw_pcm_bytes)        # G.711 A-law audio data
    
    # Outer RelayMessage (message_type=4)
    msg = pb_varint(1, 4)                     # MEDIAPACKAGE
    msg += pb_submsg(5, mp)
    return msg
```

---

## 4. Remote Cloud Device Settings (`/loki/setting/data/list`)

Reading and toggling camera configuration parameters remotely via the Cloud REST API:

```python
def set_camera_setting(device_id, access_token, key, value):
    """Set camera setting (e.g. flip 180°, night vision, motion sensitivity)."""
    url = f"https://api.icloseli.com/loki/setting/data/list?deviceId={device_id}"
    body = {
        "deviceId": device_id,
        "settings": [
            {
                "schema": f"ipc://{device_id}",
                "key": key,
                "value": str(value)
            }
        ]
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }
    res = requests.post(url, json=body, headers=headers)
    return res.json()
```

### Supported Setting Keys:
- `flip_status`: `"0"` (Normal) / `"1"` (Flipped 180°)
- `night_vision_mode`: `"auto"` / `"on"` / `"off"`
- `motion_sensitivity`: `"low"` / `"medium"` / `"high"`
- `status_led`: `"0"` (Disabled) / `"1"` (Enabled)
- `alarm_siren`: `"0"` (Off) / `"1"` (Buzz)
