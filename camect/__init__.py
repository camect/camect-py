"""Client API for Camect."""

import asyncio
import base64
import json
import logging
import ssl
import sys
from threading import Thread
import time
from typing import Callable, Dict, List
import urllib3

import requests
import websockets

EMBEDDED_BUNDLE_JS = "js/embedded_bundle.min.js"

_LOGGER = logging.getLogger(__name__)

def set_log_level(level: int):
    _LOGGER.setLevel(level)

def get_log_level() -> int:
    return _LOGGER.getEffectiveLevel()

def log_to_console():
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s [%(name)s %(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    _LOGGER.addHandler(handler)

EventListener = Callable[[Dict[str, str]], None]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Error(Exception):
    pass


class Hub:
    """Client talking to Camect home server.

    Usage:
        import camect
        home = camect.Hub("camect.local:9443", "admin", "xxx")
        home.get_name()
        home.add_event_listener(lambda evt: print(evt))
    """
    def __init__(self, server_addr: str, user: str, password: str) -> None:
        self._server_addr = server_addr
        self._api_prefix = f"https://{server_addr}/api/"
        self._ws_uri = f"wss://{server_addr}/api/event_ws"
        self._user = user
        self._password = password
        # Make sure it connects.
        self.get_info()
        self._evt_listeners_ = []
        self._evt_loop = asyncio.new_event_loop()
        evt_thread = Thread(
            target=self._evt_loop.run_until_complete, args=(self._event_handler(),))
        evt_thread.daemon = True
        evt_thread.start()


    def get_id(self) -> str:
        info = self.get_info()
        if info:
            return info["id"]
        return ""

    def get_name(self) -> str:
        info = self.get_info()
        if info:
            return info["name"]
        return ""

    # Returns the operation mode. Currently, "HOME" or "DEFAULT".
    def get_mode(self) -> str:
        info = self.get_info()
        if info:
            return info["mode"]
        return ""

    def get_cloud_url(self, path) -> str:
        info = self.get_info()
        if info:
            return info["cloud_url"] + path
        return ""

    # The returned URL needs internet and may not work in certain network environment.
    def get_local_https_url(self, path: str) -> str:
        info = self.get_info()
        if info:
            return info["local_https_url"] + path + "?X-AUTHORIZATION=" + self._authorization()
        return ""

    # The returned URL needs internet and may not work in certain network environment.
    def get_local_websocket_url(self) -> str:
        return self.get_local_https_url("webrtc/ws").replace("https://", "wss://")

    # The returned URL has invalid TLS certificate.
    def get_unsecure_https_url(self, path: str) -> str:
        return f"https://{self._server_addr}/{path}?X-AUTHORIZATION=" + self._authorization()

    # The returned URL has invalid TLS certificate.
    def get_unsecure_websocket_url(self) -> str:
        return self.get_unsecure_https_url("webrtc/ws").replace("https://", "wss://")

    def get_info(self) -> Dict[str, str]:
        resp = requests.get(
            self._api_prefix + "GetHomeInfo", verify=False, auth=(self._user, self._password))
        json = resp.json()
        if resp.status_code != 200:
            raise Error("Failed to get home info: [%d](%s)" % (resp.status_code, json["err_msg"]))
        return json

    def set_name(self, name: str) -> None:
        resp = requests.get(
            self._api_prefix + "SetHomeName", verify=False, auth=(self._user, self._password),
            params={"Name": name})
        if resp.status_code != 200:
            raise Error("Failed to set home name to '%s': [%d](%s)" % (name,
                resp.status_code, resp.json()["err_msg"]))

    # Sets the operation mode. Currently, only "HOME" or "DEFAULT".
    def set_mode(self, mode: str, reason: str = '') -> None:
        params = {"Mode": mode}
        if reason:
            params["Reason"] = reason
        resp = requests.get(
            self._api_prefix + "SetOperationMode", verify=False, auth=(self._user, self._password),
            params=params)
        if resp.status_code != 200:
            raise Error("Failed to set operation mode to '%s': [%d](%s)" % (mode,
                resp.status_code, resp.json()["err_msg"]))

    def list_cameras(self) -> List[Dict[str, str]]:
        resp = requests.get(
            self._api_prefix + "ListCameras", verify=False, auth=(self._user, self._password))
        json = resp.json()
        if resp.status_code != 200:
            raise Error("Failed to get home info: [%d](%s)" % (resp.status_code, json["err_msg"]))
        return json["camera"]

    def snapshot_camera(self, cam_id: str, width: int = 0, height: int = 0,
                        ts_ms: int = 0) -> bytes:
        params = {
            "CamId": cam_id,
            "Width": str(width),
            "Height": str(height),
            "TimestampMs": str(ts_ms)
        }
        resp = requests.get(
            self._api_prefix + "SnapshotCamera", verify=False, auth=(self._user, self._password),
            params=params)
        json = resp.json()
        if resp.status_code != 200:
            raise Error("Failed to snapshot camera: [%d](%s)" % (resp.status_code, json["err_msg"]))
        return base64.b64decode(json["jpeg_data"])

    def disable_alert(self, cam_ids: List[str], reason: str):
        """ Disable alerts for camera(s) or the home if "cam_ids" is empty.
        """
        self._enable_alert(cam_ids, False, reason)

    def enable_alert(self, cam_ids: List[str], reason: str):
        """ Enable alerts for camera(s) or the home if "cam_ids" is empty.

        NOTE: This method can only undo disable_alert. It has no effect if disable_alert was not
        called before.
        Please make sure that "reason" is same as you called disable_alert.
        """
        self._enable_alert(cam_ids, True, reason)

    def _enable_alert(self, cam_ids: List[str], enable: bool, reason: str):
        params = { "Reason": reason }
        if enable:
            params["Enable"] = "1"
        for i in range(len(cam_ids)):
            key = "CamId[%d]" % (i)
            params[key] = cam_ids[i]
        resp = requests.get(
            self._api_prefix + "EnableAlert", verify=False, auth=(self._user, self._password),
            params=params)
        json = resp.json()
        if resp.status_code != 200:
            _LOGGER.error(
                "Failed to enable/disable alert: [%d](%s)", resp.status_code, json["err_msg"])

    def start_hls(self, cam_id: str, ts_ms: int = 0, duration_ms: int = 0) -> str:
        """ Start HLS the camera. Returns the HLS URL.

        The URL expires after it's been idle for 1 minute.
        NOTE: This is an experimental feature, only available for pro units now.
        """
        params = { "Type": "1", "CamId": cam_id, "StreamingHost": self._server_addr }
        if ts_ms > 0:
            params['Cmd'] = '1'
            params['TimestampMs'] = str(ts_ms)
            if duration_ms > 0:
                params['DurationMs'] = str(duration_ms)
        resp = requests.get(
            self._api_prefix + "StartStreaming", verify=False, auth=(self._user, self._password),
            params = params)
        json = resp.json()
        if resp.status_code != 200:
            _LOGGER.error(
                "Failed to start HLS: [%d](%s)", resp.status_code, json["err_msg"])
        return json["hls_url"]

    def ptz(self, cam_id: str, action: int):
        """ Pan / tilt / zoom.

        Args:
            action: 1 => pan left
                    2 => pan right
                    3 => tilt up
                    4 => tilt down
                    7 => zoom in
                    8 => zoom out
        """
        params = { "CamId": cam_id, "Action": action }
        resp = requests.get(
            self._api_prefix + "PTZ", verify=False, auth=(self._user, self._password),
            params=params)
        if resp.status_code != 200:
            json = resp.json()
            _LOGGER.error(
                "Failed to ptz camera %s: [%d](%s)", cam_id, resp.status_code, json["err_msg"])

    def add_event_listener(self, cb: EventListener) -> None:
        self._evt_loop.call_soon_threadsafe(self._evt_listeners_.append, cb)

    def del_event_listener(self, cb: EventListener) -> None:
        self._evt_loop.call_soon_threadsafe(self._evt_listeners_.remove, cb)

    def _authorization(self) -> str:
        return base64.b64encode(f"{self._user}:{self._password}".encode()).decode()

    async def _event_handler(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_NONE
        authorization = "Basic " + self._authorization()
        while(True):
            try:
                _LOGGER.info("Connecting to Camect hub at '%s' ...", self._ws_uri)
                websocket = await websockets.connect(self._ws_uri, ssl=context,
                    extra_headers={"Authorization": authorization})
                try:
                    async for msg in websocket:
                        _LOGGER.debug("Received event: %s", msg)
                        try:
                            evt = json.loads(msg)
                            for cb in self._evt_listeners_:
                                cb(evt)
                        except json.decoder.JSONDecodeError as err:
                            _LOGGER.error("Invalid JSON '%s': %s", msg, err)
                except (websockets.exceptions.ConnectionClosed, OSError):
                    _LOGGER.warning("Websocket to Camect hub was closed.")
                    await asyncio.sleep(5)
                except (ConnectionRefusedError, ConnectionError):
                    _LOGGER.warning("Cannot connect Camect hub.")
                    await asyncio.sleep(10)
                except:
                    e = sys.exc_info()[0]
                    _LOGGER.warning("Unexpected exception: %s", e)
                    await asyncio.sleep(10)
            except (OSError, ConnectionError):
                _LOGGER.warning("Cannot connect Camect hub.")
                await asyncio.sleep(10)
            except:
                e = sys.exc_info()[0]
                _LOGGER.warning("Unexpected exception: %s", e)
                await asyncio.sleep(10)

Home = Hub
