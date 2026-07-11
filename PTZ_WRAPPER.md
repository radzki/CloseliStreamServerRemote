# PTZ control — protocol notes and usage

Adds pan/tilt control to the relay client:

```
GET /ptz/<device_id>?dir=left|right|up|down|stop[&ms=<n>][&continuous=1]
```

## The command (recovered from the app)

PTZ is an XMPP **settings** command sent with the same CLIENTCMD (type=9, sub-type=33)
envelope as LIVE_VIEW — only `msgContent` differs. Ground truth is the real app's on-wire
frame (Frida capture) cross-checked against the decompiled model classes
(`XmppDef`, `XmppRequest`, `XmppSettingsRequest`):

```json
{"msgSession":<rand>,"msgSequence":0,"msgCategory":"camera","msgTimeStamp":<epoch_ms>,
 "msgContent":{"request":1793,"subRequest":82,"channelName":"720p",
               "requestParams":{"value":<dir>}}}
```

| field | value | source |
|-------|-------|--------|
| `request` | **1793** = `Request_Set` | `XmppDef` |
| `subRequest` | **82** — a PTZ subrequest in `XmppRequest.isPtzRequest()` | `XmppRequest` |
| `channelName` | `"720p"` (present on PTZ; absent on LIVE_VIEW) | capture |
| `requestParams.value` | direction code | capture + `XmppDef.PtzValue_LensPan*` |

Direction codes (`value`), from `XmppDef.PtzValue_LensPan*`:

| dir | value |
|-----|-------|
| left  | 1 |
| right | 2 |
| up    | 3 |
| down  | 4 |
| stop  | 0 |

**Movement is continuous.** In the capture, `value:0` (stop) is the most frequent PTZ
frame — the app sends a direction on button-press and `value:0` on release. A directional
command with no stop will pan the camera until it hits its limit.

## How it's wired

- `PTZ_VALUES` — the direction→value map above.
- `build_clientcmd_ptz(camera_id, device_uuid, value)` — byte-for-byte mirror of
  `build_clientcmd_live_view`, emitting the frame above.
- `RelayRemoteClient._send_ptz(value)` — sends one frame via `_ctrl_send` (so it is
  serialized against ping/pong and live-view writes on the control socket).
- `StreamHandler._ptz` + the `/ptz` route — parses `dir`, maps it, and by default performs
  a discrete **nudge**: send the move, sleep `ms` (default 500, clamped 0–3000), send stop.
  - `?continuous=1` — send the move only (you must then call `?dir=stop`).
  - `?dir=stop` — send a bare stop.
  Responses are JSON: `200` ok, `400` bad/missing `dir`, `404` unknown camera, `503` not connected.
- The browser UI (`index.html`) exposes a per-camera d-pad; the arrows are press-and-hold
  (hold = continuous move, release = stop, with a safety auto-stop).

## Validation

Validated against a live camera over the cloud relay: each direction physically moves the
camera and auto-stops after the nudge; `/ptz?dir=stop` is the safety button; the relay's
ack comes back as a `SERVERCMD` (type=7) on the control loop. A camera you only *receive*
(shared) may have PTZ denied server-side.

## Not implemented (needs more RE if wanted)

- **Zoom** — `XmppDef` has `PtzValue_LensZoomIn=1 / ZoomOut=-1`, but no zoom frame appeared
  in the capture and the subRequest is unconfirmed; these cameras may be pan/tilt only.
- **Presets / auto-cruise** — `Subrequest_PTZ_Auto_Cruise_Pos=163` with a `pos` list of
  `{id,pan,tilt}`, and absolute go-to via `requestParams={"pan":<n>,"tilt":<n>}`
  (both in `XmppSettingsRequest`).
