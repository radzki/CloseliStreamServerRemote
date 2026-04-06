# Closeli Remote Stream Server

Standalone client that connects to Closeli (Eoolii/Taismart) cloud relay servers to receive camera MJPEG video and audio streams. No LAN access to the camera required — works from anywhere with internet.

All cameras on your account are **auto-discovered** and served through a **single HTTP port** (default `8080`), with each camera's feed accessible by its device ID.

## How It Works

The client reverse-engineers the Closeli relay protocol:

1. **API Login** — authenticates with the Closeli cloud
2. **Auto-Discovery** — fetches all cameras bound to your account
3. **Relay Discovery** — finds which relay server each camera is connected to
4. **Dual TLS Auth** — opens two raw TLS connections per camera to the relay:
   - **Type=6** (control) — sends LIVE_VIEW commands to the camera
   - **Type=2** (data) — receives MJPEG video and audio
5. **HTTP Server** — exposes all camera streams on a single port, identified by device ID

## Quick Start

```bash
cp .env.example .env
# Edit .env with your credentials

docker compose up -d
```

Open `http://localhost:8080/` for an index page listing all discovered cameras with live previews.

## Configuration

Copy `.env.example` to `.env` and fill in:

| Variable | Description |
|---|---|
| `CLOSELI_EMAIL` | Your Eoolii app login email |
| `CLOSELI_PASSWORD` | Your Eoolii app password |
| `PRODUCT_KEY` | Product key (see [Extracting Product Key & Secret](#extracting-product-key--secret-from-the-apk)) |
| `PRODUCT_SECRET` | Product secret (see [Extracting Product Key & Secret](#extracting-product-key--secret-from-the-apk)) |

No per-camera configuration is needed — all cameras on the account are discovered automatically.

## Endpoints

All cameras are served on a single port (default `8080`). Each camera's feed is accessed by its device ID:

| Path | Description |
|---|---|
| `/` | Index page — lists all cameras with live previews |
| `/video/<device_id>` | MJPEG video stream for a specific camera |
| `/audio/<device_id>` | WAV audio stream (G.711 A-law, 8kHz mono) |
| `/status` | JSON status for all cameras |
| `/status/<device_id>` | JSON status for a specific camera |
| `/trigger/<device_id>` | Re-send LIVE_VIEW command to a specific camera |

If only one camera is connected, `/video` and `/audio` (without a device ID) also work.

## Multiple Cameras

No extra configuration needed. The client auto-discovers all cameras on your account at startup:

```bash
docker compose up -d
```

All cameras share the same port (`8080`). Access individual feeds via their device ID in the URL path (e.g. `http://localhost:8080/video/xxxxS_aabbccddeeff`).

To list all cameras without starting streams:

```bash
python3 relay_remote_client.py --discover-only
```

## Frigate / go2rtc Integration

Add to your go2rtc config:

```yaml
streams:
  closeli_cam1:
    - http://localhost:8080/video/<device_id>
```

The MJPEG stream is delivered at the camera's native framerate (~8fps) with proper frame pacing.

## Running Without Docker

```bash
pip install -r requirements.txt

# Set environment variables or create .env
export CLOSELI_EMAIL=user@example.com
export CLOSELI_PASSWORD=password
export PRODUCT_KEY=your_key
export PRODUCT_SECRET=your_secret

# Auto-discover all cameras
python3 relay_remote_client.py

# Or target a single camera
python3 relay_remote_client.py -d xxxxS_aabbccddeeff

# Custom port
python3 relay_remote_client.py -p 9090
```

## Architecture

```
               TLS (type=6,2)    ┌──────────────┐     ┌──────────┐
               ┌────────────────►│              │◄───►│ Camera 1 │
┌──────────┐   │                 │   Closeli    │     └──────────┘
│          │◄──┤                 │   Relay      │
│  Client  │   │ TLS (type=6,2)  │   Server(s)  │     ┌──────────┐
│          │◄──┼────────────────►│              │◄───►│ Camera 2 │
│          │   │                 │              │     └──────────┘
└────┬─────┘   │  ...            └──────────────┘
     │         │
     │ HTTP :8080
     │  /video/<device_id>
     ▼
┌──────────┐
│ Frigate  │
│ go2rtc   │
│ Browser  │
└──────────┘
```

## Extracting Product Key & Secret from the APK

The product key and secret are not user credentials — they are app-level constants embedded in the Eoolii APK (`com.taismart.global`). All users share the same values. The app hides them using **LSB steganography** in PNG images and **BuildConfig** string constants.

There are two sets (the app auto-selects based on region):

| Region | Product Key | Product Secret |
|---|---|---|
| International (abroad) | `c90466a2-6ea` | `PzEIWxPeAwuNF8sWRzc9` |
| Domestic (China) | `115fe14d-b9f` | `YmVthdCug6q8xYkHeWNa` |

If you need to re-extract these (e.g. after an app update), here's the process:

### 1. Decompile the APK

```bash
# Install jadx (Java decompiler)
wget https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip
unzip jadx-1.5.1.zip -d jadx

# Decompile (skip resources to speed things up)
jadx/bin/jadx --no-res --no-debug-info -d jadx_out eoolii.apk
```

### 2. Find the Product Key in BuildConfig

The product key (`client_id` for API login) is in plain text:

```bash
cat jadx_out/sources/com/arcsoft/closeli/BuildConfig.java | grep "Key"
```

Look for:
```java
public static final String Key = "115fe14d-b9f";
public static final String Key_abroad = "c90466a2-6ea";
public static final String Key_domestic = "115fe14d-b9f";
```

### 3. Extract the Product Secret via Steganography

The product secret is hidden in PNG images using **Least Significant Bit (LSB)** encoding in the red channel. The relevant source is `gg/r.java` (originally `LeastSignificantBit.java`).

The secret is embedded in these asset files:

| File | Region |
|---|---|
| `assets/app_sct.png` | Default (same as domestic) |
| `assets/app_sct_abroad.png` | International |
| `assets/app_sct_domestic.png` | Domestic (China) |

Extract the PNGs from the APK:

```bash
unzip eoolii.apk "assets/app_sct*.png" -d /tmp
```

Decode with Python:

```python
from PIL import Image

def lsb_decode(path):
    img = Image.open(path)
    w = img.width
    px = img.load()

    # First 2 bytes encode the payload length (big-endian, 7-bit shifted)
    length_bytes = []
    for byte_idx in range(2):
        bits = [0] * 8
        for bit in range(7, -1, -1):
            px_idx = byte_idx * 8 + (7 - bit)
            bits[bit] = ((px[px_idx % w, px_idx // w][0] & 1) << bit)
        length_bytes.append(
            bits[7]|bits[6]|bits[5]|bits[4]|bits[3]|bits[2]|bits[1]|bits[0])

    length = (length_bytes[0] << 7) | length_bytes[1]

    # Read payload bytes
    result = bytearray(length)
    for byte_idx in range(2, length + 2):
        bits = [0] * 8
        for bit in range(7, -1, -1):
            px_idx = byte_idx * 8 + (7 - bit)
            bits[bit] = ((px[px_idx % w, px_idx // w][0] & 1) << bit)
        result[byte_idx - 2] = (
            bits[0]|bits[7]|bits[6]|bits[5]|bits[4]|bits[3]|bits[2]|bits[1])

    return result.decode('utf-8')

print(lsb_decode("/tmp/assets/app_sct_abroad.png"))
# => PzEIWxPeAwuNF8sWRzc9
```

### 4. Bonus: AES Key for Additional Encryption

There's also an AES key/IV pair hidden in `assets/pic_k_i.png` via the same LSB method:

```json
{"key": "a9m0d3enckEy$k3y", "iv": "aPm0dE3nc1v$##Iv"}
```

This is used by the app for encrypting certain API request payloads (the `uDesKey` field in `cloud_pro.ini`), not for login.
