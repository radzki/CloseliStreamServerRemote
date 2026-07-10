#!/usr/bin/env python3
"""
ping_probe.py — test whether a periodic keepalive PING on the DATA channel
stops the relay from closing the connection at ~60s.

This opens an INDEPENDENT session (its own device_uuid) and does NOT touch the
running container's connection. It answers one protocol question:

    "Does sending build_ping() on the data socket every N seconds keep the
     relay from reaping it at ~60s?"

Run it twice and compare:
    python3 ping_probe.py --device-id <ID>                     # ping every 20s
    python3 ping_probe.py --device-id <ID> --ping-interval 0   # baseline, no ping

If the ping run survives well past 60s and the baseline dies at ~60s, a periodic
data-channel ping is the fix and it's worth rebuilding the container with it.

Credentials come from .env (the same file the client uses). The device id and
relay come from `docker compose logs` (e.g. xxxxS_189e2d438ea9 -> 101.44.196.224:50821).

NOTE: this opens a *second* live-view on the chosen camera. If the relay allows
only one viewer, the probe (or the container) may get kicked and you'll see
immediate/repeated disconnects — in that case the probe can't isolate the
behavior and we should just rebuild the container with the change instead.
"""
import argparse
import os
import socket
import sys
import threading
import time
import types

# Stub pycryptodome so we can import the client even if it isn't installed on
# the host. The probe never touches the DES path (get_device_list).
for _name, _attrs in [("Crypto", {}), ("Crypto.Cipher", {"DES": object()}),
                      ("Crypto.Util", {}), ("Crypto.Util.Padding", {"pad": (lambda b, s: b)})]:
    if _name not in sys.modules:
        _m = types.ModuleType(_name)
        for _k, _v in _attrs.items():
            setattr(_m, _k, _v)
        sys.modules[_name] = _m

import importlib.util
_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "relayclient", os.path.join(_here, "relay_remote_client.py"))
R = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R)


def ts(start):
    return f"{time.time() - start:6.1f}s"


def _auth_ok(fields):
    resp = R.decode_protobuf(fields.get(3, b'')) if isinstance(fields.get(3), bytes) else {}
    return resp.get(1, -1) == 0, resp.get(1)


def main():
    ap = argparse.ArgumentParser(description="Data-channel keepalive-ping probe")
    ap.add_argument("--device-id", required=True, help="camera device id (from the logs)")
    ap.add_argument("--relay-host", default=None, help="override relay host (else auto-discover)")
    ap.add_argument("--relay-port", type=int, default=None, help="override relay port")
    ap.add_argument("--ping-interval", type=float, default=20.0,
                    help="seconds between DATA-channel pings (0 = never = baseline)")
    ap.add_argument("--duration", type=float, default=180.0,
                    help="stop after this many seconds if not disconnected first")
    args = ap.parse_args()

    email, password, pk, ps = R.EMAIL, R.PASSWORD, R.PRODUCT_KEY, R.PRODUCT_SECRET
    if not all([email, password, pk, ps]):
        print("[probe] missing credentials — run from the project dir with a filled .env "
              "(or inside the container where the env vars are set)")
        sys.exit(1)

    print(f"[probe] logging in as {email} ...")
    token, uid, unified_id = R.api_login(email, password, R.DEVICE_UUID, pk, ps)
    if not token:
        print("[probe] login failed")
        sys.exit(1)

    host, port = args.relay_host, args.relay_port
    if not host:
        host, port = R.discover_relay(args.device_id, pk, ps)
        if not host:
            print("[probe] could not discover relay (camera offline?)")
            sys.exit(1)
    port = int(port or 50321)
    print(f"[probe] relay = {host}:{port}")

    device_uuid = f"ANDRC_{os.urandom(6).hex()}"

    # type=6 control session
    ctrl = R.create_tls_connection(host, port)
    R.send_relay_msg(ctrl, R.build_type6_auth(email, device_uuid, token, pk, uid, unified_id))
    mt, fields, raw = R.recv_relay_msg(ctrl)
    if mt != 2:
        print(f"[probe] type=6 auth failed (msg_type={mt})")
        sys.exit(1)
    ok, code = _auth_ok(fields)
    if not ok:
        print(f"[probe] type=6 auth rejected (result={code})")
        sys.exit(1)
    print("[probe] type=6 (control) auth OK")

    # type=2 data session
    data = R.create_tls_connection(host, port)
    R.send_relay_msg(data, R.build_type2_auth(email, device_uuid, args.device_id,
                                              token, pk, ps, unified_id))
    mt, fields, raw = R.recv_relay_msg(data)
    if mt != 2:
        print(f"[probe] type=2 auth failed (msg_type={mt})")
        sys.exit(1)
    ok, code = _auth_ok(fields)
    if not ok:
        print(f"[probe] type=2 auth rejected (result={code})")
        sys.exit(1)
    print("[probe] type=2 (data) auth OK")

    # post-auth sequence + LIVE_VIEW — exactly like the client's connect()
    R.send_relay_msg(data, R.build_p2pcmd_server_info(device_uuid, unified_id))
    R.send_relay_msg(data, R.build_clientcmd_handshake(device_uuid))
    R.send_relay_msg(data, R.build_clientcmd_live_count(device_uuid))
    time.sleep(0.2)
    R.send_relay_msg(ctrl, R.build_clientcmd_live_view(args.device_id, device_uuid))

    interval = args.ping_interval
    mode = f"PING every {interval:g}s" if interval > 0 else "NO ping (baseline)"
    print(f"[probe] live-view started — mode: {mode}; running up to {args.duration:g}s")
    print("[probe] watching the DATA channel; a healthy camera should log frames.\n")

    running = {"on": True}
    start = time.time()

    # Keep the control channel healthy in the background (pong + 25s self-ping),
    # so that only the DATA channel's fate is under test.
    def ctrl_loop():
        last = time.time()
        while running["on"]:
            try:
                m, f, r = R.recv_relay_msg(ctrl, timeout=5)
                if m is None and f is None and r is None:
                    break
                if m == 5:
                    R.send_relay_msg(ctrl, R.build_pong())
            except socket.timeout:
                if time.time() - last > 25:
                    try:
                        R.send_relay_msg(ctrl, R.build_ping())
                        last = time.time()
                    except Exception:
                        break
            except Exception:
                break

    threading.Thread(target=ctrl_loop, daemon=True).start()

    # DATA channel: drain messages, ping on schedule, report when it closes.
    frames = 0
    last_ping = time.time()
    last_status = time.time()
    result = None
    try:
        while running["on"] and (time.time() - start) < args.duration:
            try:
                m, f, r = R.recv_relay_msg(data, timeout=2)
                if m is None and f is None and r is None:
                    result = f"DATA CLOSED after {time.time() - start:.0f}s"
                    break
                if m == 5:
                    R.send_relay_msg(data, R.build_pong())
                elif m == 4:
                    frames += 1
            except socket.timeout:
                pass

            now = time.time()
            if interval > 0 and now - last_ping >= interval:
                try:
                    R.send_relay_msg(data, R.build_ping())
                    print(f"[probe] {ts(start)}  sent DATA ping   frames={frames}")
                except Exception as e:
                    result = f"DATA ping send failed after {now - start:.0f}s: {e}"
                    break
                last_ping = now
            if now - last_status >= 15:
                print(f"[probe] {ts(start)}  alive            frames={frames}")
                last_status = now
    except KeyboardInterrupt:
        result = "interrupted by user"

    running["on"] = False
    elapsed = time.time() - start
    print()
    if result and result.startswith("DATA CLOSED"):
        print(f"[probe] *** {result}   (mode: {mode}, frames={frames}) ***")
        if interval > 0 and elapsed < 90:
            print("[probe] => the ping did NOT keep it alive. The ~60s cut is more likely a "
                  "live-view *duration* limit than an idle timeout;")
            print("[probe]    next experiment would be to re-send LIVE_VIEW periodically instead.")
    elif result:
        print(f"[probe] stopped: {result}  (frames={frames})")
    else:
        print(f"[probe] *** SURVIVED {elapsed:.0f}s   (mode: {mode}, frames={frames}) ***")
        if interval > 0:
            print("[probe] => a periodic DATA-channel ping keeps the connection alive. "
                  "Worth wiring into the client and rebuilding once.")
        else:
            print("[probe] => baseline survived too?! the ~60s cut may not be a plain idle timeout.")

    for s in (ctrl, data):
        try:
            s.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
