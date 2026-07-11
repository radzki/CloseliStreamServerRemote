#!/usr/bin/env python3
"""
ONVIF PTZ shim for the Closeli relay client.

Frigate controls PTZ ONLY over ONVIF; our camera has no native ONVIF and exposes
pan/tilt only through the relay client's HTTP endpoint:

    GET <relay>/ptz/<device_id>?dir=left|right|up|down|stop[&continuous=1]

This process presents a minimal ONVIF Device+Media+PTZ service to Frigate and
translates the two operations Frigate's manual d-pad uses onto that endpoint:

    ONVIF ContinuousMove(pan,tilt)  ->  /ptz/<id>?dir=<dominant>&continuous=1
    ONVIF Stop                      ->  /ptz/<id>?dir=stop

It deliberately advertises ONLY a continuous pan/tilt velocity space (no relative/
FOV, no absolute, no zoom, no presets, no MoveStatus/position feedback). That is
exactly what manual PTZ needs, and it keeps Frigate from offering autotracking or
click-to-move — both require FOV RelativeMove + real position telemetry this
position-blind camera cannot provide.

Point Frigate's per-camera `onvif:` block at this shim:

    cameras:
      patio:
        onvif:
          host: <shim-host>
          port: 8081            # this shim's --listen-port
          user: frigate         # any value; the shim does not authenticate
          password: frigate

Video still flows to Frigate via the existing MJPEG restream (go2rtc) — the shim
handles PTZ only.

SOAP response shapes adapted from rgregg/reolink-enhanced-onvif-proxy (MIT).
"""

import argparse
import os
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, TCPServer

from lxml import etree

# ---------------------------------------------------------------------------
# ONVIF namespaces + the single PTZ space we support (continuous pan/tilt).
# ---------------------------------------------------------------------------
NS = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "tds": "http://www.onvif.org/ver10/device/wsdl",
    "tptz": "http://www.onvif.org/ver20/ptz/wsdl",
    "tt": "http://www.onvif.org/ver10/schema",
    "trt": "http://www.onvif.org/ver10/media/wsdl",
}
SOAP_NS = NS["s"]
CONTINUOUS_PT_SPACE = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/VelocityGenericSpace"
PT_SPEED_SPACE = "http://www.onvif.org/ver10/tptz/PanTiltSpaces/GenericSpeedSpace"

PROFILE_TOKEN = "000"
PTZ_CONFIG_TOKEN = "PTZConfig_000"
PTZ_NODE_TOKEN = "PTZNode_000"
VIDEO_SOURCE_TOKEN = "VideoSource_000"
VIDEO_ENCODER_TOKEN = "VideoEncoder_000"


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [SHIM] {msg}", flush=True)


# ---------------------------------------------------------------------------
# SOAP response builders (lxml). Only what Frigate's onvif-zeep client calls.
# ---------------------------------------------------------------------------
def _envelope(body_content):
    env = etree.Element(f"{{{SOAP_NS}}}Envelope", nsmap=NS)
    etree.SubElement(env, f"{{{SOAP_NS}}}Header")
    body = etree.SubElement(env, f"{{{SOAP_NS}}}Body")
    body.append(body_content)
    return etree.tostring(env, xml_declaration=True, encoding="UTF-8")


def _fault(code, reason, detail=""):
    env = etree.Element(f"{{{SOAP_NS}}}Envelope", nsmap=NS)
    etree.SubElement(env, f"{{{SOAP_NS}}}Header")
    body = etree.SubElement(env, f"{{{SOAP_NS}}}Body")
    fault = etree.SubElement(body, f"{{{SOAP_NS}}}Fault")
    code_el = etree.SubElement(fault, f"{{{SOAP_NS}}}Code")
    etree.SubElement(code_el, f"{{{SOAP_NS}}}Value").text = f"s:{code}"
    reason_el = etree.SubElement(fault, f"{{{SOAP_NS}}}Reason")
    text = etree.SubElement(reason_el, f"{{{SOAP_NS}}}Text")
    text.set("{http://www.w3.org/XML/1998/namespace}lang", "en")
    text.text = reason
    if detail:
        etree.SubElement(fault, f"{{{SOAP_NS}}}Detail").text = detail
    return etree.tostring(env, xml_declaration=True, encoding="UTF-8")


def fault_action_not_supported(action):
    return _fault("Sender", "ActionNotSupported", f"'{action}' is not supported")


def fault_device_error(message):
    return _fault("Receiver", "Device error", message)


def _range(parent, tag, uri, x_min, x_max, y_min=None, y_max=None):
    space = etree.SubElement(parent, f"{{{NS['tt']}}}{tag}")
    etree.SubElement(space, f"{{{NS['tt']}}}URI").text = uri
    xr = etree.SubElement(space, f"{{{NS['tt']}}}XRange")
    etree.SubElement(xr, f"{{{NS['tt']}}}Min").text = str(x_min)
    etree.SubElement(xr, f"{{{NS['tt']}}}Max").text = str(x_max)
    if y_min is not None:
        yr = etree.SubElement(space, f"{{{NS['tt']}}}YRange")
        etree.SubElement(yr, f"{{{NS['tt']}}}Min").text = str(y_min)
        etree.SubElement(yr, f"{{{NS['tt']}}}Max").text = str(y_max)
    return space


def get_capabilities(base_url):
    resp = etree.Element(f"{{{NS['tds']}}}GetCapabilitiesResponse")
    caps = etree.SubElement(resp, f"{{{NS['tds']}}}Capabilities")
    for tag, path in (("Device", "device_service"), ("Media", "media_service"),
                      ("PTZ", "ptz_service")):
        el = etree.SubElement(caps, f"{{{NS['tt']}}}{tag}")
        etree.SubElement(el, f"{{{NS['tt']}}}XAddr").text = f"{base_url}/onvif/{path}"
    return _envelope(resp)


def get_services(base_url):
    resp = etree.Element(f"{{{NS['tds']}}}GetServicesResponse")
    for namespace, path in (
        ("http://www.onvif.org/ver10/device/wsdl", "device_service"),
        ("http://www.onvif.org/ver10/media/wsdl", "media_service"),
        ("http://www.onvif.org/ver20/ptz/wsdl", "ptz_service"),
    ):
        svc = etree.SubElement(resp, f"{{{NS['tds']}}}Service")
        etree.SubElement(svc, f"{{{NS['tds']}}}Namespace").text = namespace
        etree.SubElement(svc, f"{{{NS['tds']}}}XAddr").text = f"{base_url}/onvif/{path}"
        ver = etree.SubElement(svc, f"{{{NS['tds']}}}Version")
        etree.SubElement(ver, f"{{{NS['tt']}}}Major").text = "2"
        etree.SubElement(ver, f"{{{NS['tt']}}}Minor").text = "0"
    return _envelope(resp)


def get_device_information():
    resp = etree.Element(f"{{{NS['tds']}}}GetDeviceInformationResponse")
    for tag, val in (("Manufacturer", "Closeli"), ("Model", "PTZ Shim"),
                     ("FirmwareVersion", "0.1.0"), ("SerialNumber", "SHIM-001"),
                     ("HardwareId", "SHIM")):
        etree.SubElement(resp, f"{{{NS['tds']}}}{tag}").text = val
    return _envelope(resp)


def get_system_date_and_time():
    now = datetime.now(timezone.utc)
    resp = etree.Element(f"{{{NS['tds']}}}GetSystemDateAndTimeResponse")
    sdt = etree.SubElement(resp, f"{{{NS['tds']}}}SystemDateAndTime")
    etree.SubElement(sdt, f"{{{NS['tt']}}}DateTimeType").text = "Manual"
    etree.SubElement(sdt, f"{{{NS['tt']}}}DaylightSavings").text = "false"
    utc = etree.SubElement(sdt, f"{{{NS['tt']}}}UTCDateTime")
    t = etree.SubElement(utc, f"{{{NS['tt']}}}Time")
    etree.SubElement(t, f"{{{NS['tt']}}}Hour").text = str(now.hour)
    etree.SubElement(t, f"{{{NS['tt']}}}Minute").text = str(now.minute)
    etree.SubElement(t, f"{{{NS['tt']}}}Second").text = str(now.second)
    d = etree.SubElement(utc, f"{{{NS['tt']}}}Date")
    etree.SubElement(d, f"{{{NS['tt']}}}Year").text = str(now.year)
    etree.SubElement(d, f"{{{NS['tt']}}}Month").text = str(now.month)
    etree.SubElement(d, f"{{{NS['tt']}}}Day").text = str(now.day)
    return _envelope(resp)


def get_video_sources():
    resp = etree.Element(f"{{{NS['trt']}}}GetVideoSourcesResponse")
    src = etree.SubElement(resp, f"{{{NS['trt']}}}VideoSources", token=VIDEO_SOURCE_TOKEN)
    etree.SubElement(src, f"{{{NS['tt']}}}Framerate").text = "15"
    res = etree.SubElement(src, f"{{{NS['tt']}}}Resolution")
    etree.SubElement(res, f"{{{NS['tt']}}}Width").text = "960"
    etree.SubElement(res, f"{{{NS['tt']}}}Height").text = "540"
    return _envelope(resp)


def _build_ptz_config(parent, ns="tt"):
    """PTZConfiguration advertising ONLY continuous pan/tilt velocity.

    `ns` selects the element namespace: 'tt' inside a media profile (GetProfiles),
    'tptz' inside GetConfigurationsResponse. Children are always tt-typed.
    """
    ptz = etree.SubElement(parent, f"{{{NS[ns]}}}PTZConfiguration", token=PTZ_CONFIG_TOKEN)
    etree.SubElement(ptz, f"{{{NS['tt']}}}Name").text = "PTZConfig"
    etree.SubElement(ptz, f"{{{NS['tt']}}}UseCount").text = "1"
    etree.SubElement(ptz, f"{{{NS['tt']}}}NodeToken").text = PTZ_NODE_TOKEN
    etree.SubElement(ptz, f"{{{NS['tt']}}}DefaultContinuousPanTiltVelocitySpace").text = CONTINUOUS_PT_SPACE
    speed = etree.SubElement(ptz, f"{{{NS['tt']}}}DefaultPTZSpeed")
    pt = etree.SubElement(speed, f"{{{NS['tt']}}}PanTilt", x="0.5", y="0.5")
    pt.set("space", PT_SPEED_SPACE)
    etree.SubElement(ptz, f"{{{NS['tt']}}}DefaultPTZTimeout").text = "PT5S"
    return ptz


def get_profiles():
    resp = etree.Element(f"{{{NS['trt']}}}GetProfilesResponse")
    profile = etree.SubElement(resp, f"{{{NS['trt']}}}Profiles", token=PROFILE_TOKEN, fixed="true")
    etree.SubElement(profile, f"{{{NS['tt']}}}Name").text = "MainStream"
    vsc = etree.SubElement(profile, f"{{{NS['tt']}}}VideoSourceConfiguration", token=VIDEO_SOURCE_TOKEN)
    etree.SubElement(vsc, f"{{{NS['tt']}}}Name").text = "VideoSource"
    etree.SubElement(vsc, f"{{{NS['tt']}}}UseCount").text = "1"
    etree.SubElement(vsc, f"{{{NS['tt']}}}SourceToken").text = VIDEO_SOURCE_TOKEN
    bounds = etree.SubElement(vsc, f"{{{NS['tt']}}}Bounds")
    for k, v in (("x", "0"), ("y", "0"), ("width", "960"), ("height", "540")):
        bounds.set(k, v)
    # Frigate only treats a profile as PTZ-capable if it ALSO has a
    # VideoEncoderConfiguration (frigate/ptz/onvif.py valid_profiles filter).
    vec = etree.SubElement(profile, f"{{{NS['tt']}}}VideoEncoderConfiguration", token=VIDEO_ENCODER_TOKEN)
    etree.SubElement(vec, f"{{{NS['tt']}}}Name").text = "VideoEncoder"
    etree.SubElement(vec, f"{{{NS['tt']}}}UseCount").text = "1"
    etree.SubElement(vec, f"{{{NS['tt']}}}Encoding").text = "H264"
    res = etree.SubElement(vec, f"{{{NS['tt']}}}Resolution")
    etree.SubElement(res, f"{{{NS['tt']}}}Width").text = "960"
    etree.SubElement(res, f"{{{NS['tt']}}}Height").text = "540"
    _build_ptz_config(profile)
    return _envelope(resp)


def get_configurations():
    resp = etree.Element(f"{{{NS['tptz']}}}GetConfigurationsResponse")
    _build_ptz_config(resp, ns="tptz")
    return _envelope(resp)


def get_configuration_options():
    resp = etree.Element(f"{{{NS['tptz']}}}GetConfigurationOptionsResponse")
    opts = etree.SubElement(resp, f"{{{NS['tptz']}}}PTZConfigurationOptions")
    spaces = etree.SubElement(opts, f"{{{NS['tt']}}}Spaces")
    _range(spaces, "ContinuousPanTiltVelocitySpace", CONTINUOUS_PT_SPACE, -1.0, 1.0, -1.0, 1.0)
    _range(spaces, "PanTiltSpeedSpace", PT_SPEED_SPACE, 0.0, 1.0)
    timeout = etree.SubElement(opts, f"{{{NS['tt']}}}PTZTimeout")
    etree.SubElement(timeout, f"{{{NS['tt']}}}Min").text = "PT1S"
    etree.SubElement(timeout, f"{{{NS['tt']}}}Max").text = "PT10S"
    return _envelope(resp)


def get_nodes():
    resp = etree.Element(f"{{{NS['tptz']}}}GetNodesResponse")
    node = etree.SubElement(resp, f"{{{NS['tptz']}}}PTZNode", token=PTZ_NODE_TOKEN)
    etree.SubElement(node, f"{{{NS['tt']}}}Name").text = "PTZ Node"
    spaces = etree.SubElement(node, f"{{{NS['tt']}}}SupportedPTZSpaces")
    _range(spaces, "ContinuousPanTiltVelocitySpace", CONTINUOUS_PT_SPACE, -1.0, 1.0, -1.0, 1.0)
    _range(spaces, "PanTiltSpeedSpace", PT_SPEED_SPACE, 0.0, 1.0)
    etree.SubElement(node, f"{{{NS['tt']}}}MaximumNumberOfPresets").text = "0"
    etree.SubElement(node, f"{{{NS['tt']}}}HomeSupported").text = "false"
    return _envelope(resp)


def get_service_capabilities():
    resp = etree.Element(f"{{{NS['tptz']}}}GetServiceCapabilitiesResponse")
    caps = etree.SubElement(resp, f"{{{NS['tptz']}}}Capabilities")
    # No position feedback: MoveStatus/StatusPosition false so Frigate treats this
    # as manual-only and never attempts autotracking/click-to-move.
    for k, v in (("EFlip", "false"), ("Reverse", "false"),
                 ("GetCompatibleConfigurations", "false"),
                 ("MoveStatus", "false"), ("StatusPosition", "false")):
        caps.set(k, v)
    return _envelope(resp)


def get_status():
    """Minimal status: no position (we have none), motion idle."""
    resp = etree.Element(f"{{{NS['tptz']}}}GetStatusResponse")
    status = etree.SubElement(resp, f"{{{NS['tptz']}}}PTZStatus")
    ms = etree.SubElement(status, f"{{{NS['tt']}}}MoveStatus")
    etree.SubElement(ms, f"{{{NS['tt']}}}PanTilt").text = "IDLE"
    etree.SubElement(status, f"{{{NS['tt']}}}UtcTime").text = \
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return _envelope(resp)


def simple_response(operation):
    return _envelope(etree.Element(f"{{{NS['tptz']}}}{operation}Response"))


# ---------------------------------------------------------------------------
# ContinuousMove velocity -> our direction word.
# ---------------------------------------------------------------------------
def velocity_to_dir(pan_v, tilt_v):
    """Map an ONVIF ContinuousMove pan/tilt velocity to left/right/up/down/stop.

    Frigate's manual d-pad sends pure single-axis moves; for a diagonal we pick
    the dominant axis (our camera only moves one axis at a time). ONVIF tilt +y
    is up.
    """
    if abs(pan_v) < 0.01 and abs(tilt_v) < 0.01:
        return "stop"
    if abs(pan_v) >= abs(tilt_v):
        return "right" if pan_v > 0 else "left"
    return "up" if tilt_v > 0 else "down"


# ---------------------------------------------------------------------------
# HTTP request handler.
# ---------------------------------------------------------------------------
def _local(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _soap_username(root):
    """WS-Security UsernameToken username (cleartext), or '' if absent.

    Frigate sends the camera's configured ONVIF `user` here on authenticated
    requests (ContinuousMove/Stop). We use it as the target device id, so ONE
    ONVIF port can serve every camera — set Frigate's onvif.user to the device id.
    """
    for el in root.iter():
        if _local(el.tag) == "Username" and el.text:
            return el.text.strip()
    return ""


class OnvifHandler(BaseHTTPRequestHandler):
    """Per-camera ONVIF handler.

    Config comes from the owning server instance (CloseliOnvifServer), so one
    handler class serves many cameras — each on its own server/port.
    """

    def log_message(self, *a):
        pass

    @property
    def relay_base(self):
        return self.server.relay_base

    @property
    def name(self):
        return self.server.name

    def _send(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/soap+xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _call_ptz(self, device_id, direction, continuous):
        """Fire the relay client's PTZ endpoint. Returns True on HTTP 200."""
        if not device_id:
            log(f"{self.name}: PTZ {direction} with no device id — set Frigate's "
                f"onvif.user to the camera device id; ignored")
            return False
        qs = f"dir={direction}" + ("&continuous=1" if continuous else "")
        url = f"{self.relay_base}/ptz/{urllib.parse.quote(device_id)}?{qs}"
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.status == 200
        except Exception as e:
            log(f"{self.name}: /ptz call failed ({device_id} {direction}): {e}")
            return False

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            root = etree.fromstring(raw)
        except Exception as e:
            self._send(fault_device_error(f"bad SOAP: {e}"), 400)
            return
        body = root.find(f"{{{SOAP_NS}}}Body")
        if body is None or len(body) == 0:
            self._send(fault_device_error("no SOAP body"), 400)
            return
        action_el = body[0]
        action = _local(action_el.tag)
        base_url = f"http://{self.headers.get('Host', 'localhost')}"
        # Route by the WS-Security username (= camera device id); fall back to the
        # server's configured device_id for single-camera/standalone use.
        device_id = _soap_username(root) or self.server.device_id

        try:
            self._send(self._dispatch(action, action_el, base_url, device_id))
        except Exception as e:
            log(f"{self.name}: error handling {action}: {e}")
            self._send(fault_device_error(str(e)), 500)

    def do_GET(self):
        # Some clients probe with GET; nudge them to POST SOAP.
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ONVIF PTZ shim: POST SOAP to /onvif/{device,media,ptz}_service")

    def _dispatch(self, action, action_el, base_url, device_id):
        # Device service
        if action == "GetSystemDateAndTime":
            return get_system_date_and_time()
        if action == "GetCapabilities":
            return get_capabilities(base_url)
        if action == "GetServices":
            return get_services(base_url)
        if action == "GetDeviceInformation":
            return get_device_information()
        # Media service
        if action == "GetProfiles":
            return get_profiles()
        if action == "GetVideoSources":
            return get_video_sources()
        # PTZ service — capability advertisement
        if action in ("GetConfigurations", "GetConfiguration"):
            return get_configurations()
        if action == "GetConfigurationOptions":
            return get_configuration_options()
        if action == "GetNodes" or action == "GetNode":
            return get_nodes()
        if action == "GetServiceCapabilities":
            return get_service_capabilities()
        if action == "GetStatus":
            return get_status()
        # PTZ service — movement
        if action == "ContinuousMove":
            pan_v, tilt_v = self._parse_pantilt(action_el)
            direction = velocity_to_dir(pan_v, tilt_v)
            log(f"{self.name}: {device_id or '?'} ContinuousMove "
                f"pan={pan_v:+.2f} tilt={tilt_v:+.2f} -> {direction}")
            self._call_ptz(device_id, direction, continuous=(direction != "stop"))
            return simple_response("ContinuousMove")
        if action == "Stop":
            log(f"{self.name}: {device_id or '?'} Stop")
            self._call_ptz(device_id, "stop", continuous=False)
            return simple_response("Stop")
        if action in ("RelativeMove", "AbsoluteMove", "GotoPreset", "GotoHomePosition"):
            # Not supported for a position-blind, continuous-only camera. Reply OK
            # so Frigate doesn't error, but do nothing.
            log(f"{self.name}: {action} ignored (unsupported by camera)")
            return simple_response(action)
        return fault_action_not_supported(action)

    def _parse_pantilt(self, action_el):
        """Extract PanTilt x/y velocity from a ContinuousMove body (namespace-agnostic)."""
        for el in action_el.iter():
            if _local(el.tag) == "PanTilt":
                try:
                    return float(el.get("x", "0")), float(el.get("y", "0"))
                except (TypeError, ValueError):
                    return 0.0, 0.0
        return 0.0, 0.0


class CloseliOnvifServer(ThreadingMixIn, TCPServer):
    """Threaded ONVIF PTZ server. ONE instance serves EVERY camera: each request
    is routed to a camera by its WS-Security username (Frigate onvif.user = the
    camera device id). `device_id` is only a fallback for single-camera use."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, relay_base, name="onvif", device_id=""):
        super().__init__(addr, OnvifHandler)
        self.relay_base = relay_base.rstrip("/")
        self.name = name
        self.device_id = device_id


def start_onvif_server(port, relay_base, name="onvif", device_id=""):
    """Start the shared ONVIF PTZ listener in a daemon thread.

    Returns the running server (call .shutdown() to stop). One port serves all
    cameras: each PTZ command is routed to <relay_base>/ptz/<device id from the
    ONVIF username>. `device_id` is only used as a fallback when no username is
    sent (single-camera/standalone).
    """
    server = CloseliOnvifServer(("0.0.0.0", port), relay_base, name, device_id)
    threading.Thread(target=server.serve_forever, name=f"onvif-{name}",
                     daemon=True).start()
    log(f"{name}: ONVIF PTZ on 0.0.0.0:{port} -> {server.relay_base}/ptz/<onvif.user>")
    return server


def main():
    ap = argparse.ArgumentParser(description="ONVIF PTZ shim -> relay client /ptz endpoint")
    ap.add_argument("--listen-port", type=int,
                    default=int(os.environ.get("SHIM_LISTEN_PORT", "8091")),
                    help="Port Frigate's onvif: block connects to")
    ap.add_argument("--relay-base",
                    default=os.environ.get("SHIM_RELAY_BASE", "http://localhost:8080"),
                    help="Base URL of the relay client (serves /ptz/<id>)")
    ap.add_argument("--device-id",
                    default=os.environ.get("SHIM_DEVICE_ID", ""),
                    help="Fallback device id when a request carries no ONVIF "
                         "username (single-camera use)")
    ap.add_argument("--name", default=os.environ.get("SHIM_NAME", "onvif"),
                    help="Label for logs")
    args = ap.parse_args()

    server = CloseliOnvifServer(("0.0.0.0", args.listen_port), args.relay_base,
                                args.name, args.device_id)
    print("=" * 66)
    print("  ONVIF PTZ shim (standalone)")
    print(f"  Listen:     0.0.0.0:{args.listen_port}  (Frigate onvif.host/port)")
    print(f"  Relay:      {server.relay_base}/ptz/<onvif.user>?dir=...")
    print(f"  Routing:    set Frigate onvif.user to the camera device id"
          + (f" (fallback: {args.device_id})" if args.device_id else ""))
    print("=" * 66)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
