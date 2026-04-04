# Closeli Remote Stream Server

Standalone client that connects to Closeli (Eoolii/Taismart) cloud relay servers to receive camera MJPEG video and audio streams. No LAN access to the camera required — works from anywhere with internet.

## How It Works

The client reverse-engineers the Closeli relay protocol:

1. **API Login** — authenticates with the Closeli cloud
2. **Relay Discovery** — finds which relay server the camera is connected to
3. **Dual TLS Auth** — opens two raw TLS connections to the relay:
   - **Type=6** (control) — sends LIVE_VIEW commands to the camera
   - **Type=2** (data) — receives MJPEG video and audio
4. **HTTP Server** — exposes the stream as standard MJPEG over HTTP

## Quick Start

```bash
cp .env.example .env
# Edit .env with your credentials and camera device ID

docker compose up -d
```

Video stream available at `http://localhost:8081/video`

## Configuration

Copy `.env.example` to `.env` and fill in:

| Variable | Description |
|---|---|
| `CLOSELI_EMAIL` | Your Eoolii app login email |
| `CLOSELI_PASSWORD` | Your Eoolii app password |
| `PRODUCT_KEY` | Product key (extract from APK) |
| `PRODUCT_SECRET` | Product secret (extract from APK) |
| `CAMERA1_DEVICE_ID` | Camera device ID (`xxxxS_<mac_no_colons>`) |

Find your camera's device ID in the Eoolii app under device settings, or derive it from the camera's MAC address: `xxxxS_` + MAC without colons, lowercase.

## Endpoints

| Path | Description |
|---|---|
| `/video` | MJPEG video stream |
| `/audio` | WAV audio stream (G.711 A-law, 8kHz mono) |
| `/status` | JSON connection status |
| `/trigger` | Re-send LIVE_VIEW command |

## Multiple Cameras

```bash
# Camera 1 only (default)
docker compose up -d

# Add camera 2
docker compose --profile camera2 up -d

# All configured cameras
docker compose --profile all up -d
```

Each camera gets its own port: camera1=8081, camera2=8082, etc.

## Frigate / go2rtc Integration

Add to your go2rtc config:

```yaml
streams:
  closeli_cam1:
    - http://localhost:8081/video
```

The MJPEG stream is delivered at the camera's native framerate (~8fps) with proper frame pacing.

## Running Without Docker

```bash
pip install -r /dev/null  # No dependencies — stdlib only

# Set environment variables or create .env
export CLOSELI_EMAIL=user@example.com
export CLOSELI_PASSWORD=password
export PRODUCT_KEY=your_key
export PRODUCT_SECRET=your_secret

python3 relay_remote_client.py -d xxxxS_aabbccddeeff -p 8081
```

## Architecture

```
┌──────────┐    TLS (type=6)     ┌──────────────┐
│          │◄───────────────────►│              │
│  Client  │    TLS (type=2)     │ Closeli      │     ┌────────┐
│          │◄───────────────────►│ Relay Server │◄───►│ Camera │
│          │                     │              │     └────────┘
└────┬─────┘                     └──────────────┘
     │
     │ HTTP :8081
     ▼
┌──────────┐
│ Frigate  │
│ go2rtc   │
│ Browser  │
└──────────┘
```

# Work In Progress
I am working on a way to automate camera parameters fetching just using the credentials. So, instead of populating the .env file with other variables, we would just need the username and password.
