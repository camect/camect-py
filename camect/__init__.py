"""Client API for Camect."""

import asyncio
import base64
import json
import logging
import ssl
from threading import Thread
from typing import Callable, Dict, List
import urllib3

import requests
import websockets

_LOGGER = logging.getLogger(__name__)

EventListener = Callable[[Dict[str, str]], None]

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Home:
    """Client talking to Camect home server.

    Usage:
        import camect
        home = camect.Home("camect.local:9443", "admin", "xxx")
        home.get_name()
        home.add_event_listener(lambda evt: print(evt))
    """
    def __init__(self, server_addr, user, password) -> None:
        self._api_prefix: str = f"https://{server_addr}/api/"
        self._ws_uri: str = f"wss://{server_addr}/api/event_ws"
        self._host: str = server_addr.split(":")[0]
        self._user: str = user
        self._password: str = password
        self._evt_listeners_: List[EventListener] = []
        self._evt_loop = asyncio.new_event_loop()
        evt_thread = Thread(
            target=self._evt_loop.run_until_complete, args=(self._event_handler(),))
        evt_thread.daemon = True
        evt_thread.start()

    def get_embedded_bundle_js(self) -> str:
        info = self.get_info()
        if info:
            http_port = info["http_port"]
            return f"http://{self._host}:{http_port}/js/embedded_bundle.min.js"
        return ""

    def get_fontface_css(self) -> str:
        info = self.get_info()
        if info:
            http_port = info["http_port"]
            return f"http://{self._host}:{http_port}/font/fontface.css"
        return ""

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

    def get_mode(self) -> str:
        info = self.get_info()
        if info:
            return info["mode"]
        return ""

    def get_cloud_url(self) -> str:
        info = self.get_info()
        if info:
            return info["cloud_url"]
        return ""

    def get_cloud_ws_url(self) -> str:
        info = self.get_info()
        if info:
            return info["cloud_ws_url"]
        return ""

    def get_local_https_url(self) -> str:
        info = self.get_info()
        if info:
            return info["local_https_url"]
        return ""

    def get_local_ws_url(self) -> str:
        info = self.get_info()
        if info:
            return info["local_ws_url"] + "?X-AUTHORIZATION=" + self._authorization()
        return ""

    def get_info(self) -> Dict[str, str]:
        resp = requests.get(
            self._api_prefix + "GetHomeInfo", verify=False, auth=(self._user, self._password))
        json = resp.json()
        if resp.status_code != 200:
            _LOGGER.error(
                "Failed to get home info: [%d](%s)", resp.status_code, json["err_msg"])
            return None
        return json

    def set_name(self, name: str) -> None:
        resp = requests.get(
            self._api_prefix + "SetHomeName", verify=False, auth=(self._user, self._password),
            params={"name": name})
        if resp.status_code != 200:
            _LOGGER.error(
                "Failed to set home name to '%s': [%d](%s)", name,
                resp.status_code, resp.json()["err_msg"])

    def set_mode(self, mode: str) -> None:
        resp = requests.get(
            self._api_prefix + "SetOperationMode", verify=False, auth=(self._user, self._password),
            params={"mode": mode})
        if resp.status_code != 200:
            _LOGGER.error(
                "Failed to set operation mode to '%s': [%d](%s)", mode,
                resp.status_code, resp.json()["err_msg"])

    def list_cameras(self) -> List[Dict[str, str]]:
        resp = requests.get(
            self._api_prefix + "ListCameras", verify=False, auth=(self._user, self._password))
        json = resp.json()
        if resp.status_code != 200:
            _LOGGER.error(
                "Failed to get home info: [%d](%s)", resp.status_code, json["err_msg"])
            return None
        return json["camera"]

    def add_event_listener(self, cb: EventListener) -> None:
        self._evt_loop.call_soon_threadsafe(self._evt_listeners_.append, cb)

    def del_event_listener(self, cb: EventListener) -> None:
        self._evt_loop.call_soon_threadsafe(self._evt_listeners_.remove, cb)

    def _authorization(self) -> str:
        return base64.b64encode(f"{self._user}:{self._password}".encode()).decode()

    async def _event_handler(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.verify_mode = ssl.CERT_NONE
        authorization = "Basic " + self._authorization()
        while True:
            _LOGGER.info("Connecting to Camect Home at '%s' ...", self._ws_uri)
            try:
                async with websockets.connect(
                        self._ws_uri, ssl=context,
                        extra_headers={"Authorization": authorization}) as websocket:
                    async for msg in websocket:
                        _LOGGER.debug("Received event: %s", msg)
                        try:
                            evt = json.loads(msg)
                            for cb in self._evt_listeners_:
                                cb(evt)
                        except json.decoder.JSONDecodeError as err:
                            _LOGGER.error("Invalid JSON '%s': %s", msg, err)
            except websockets.exceptions.ConnectionClosed:
                _LOGGER.warning("Websocket to Camect Home was closed.")
                await asyncio.sleep(5)
            except ConnectionRefusedError:
                _LOGGER.warning("Cannot connect Camect Home.")
                await asyncio.sleep(10)
            except:
                e = sys.exc_info()[0]
                _LOGGER.warning("Unexpected exception: %s", e)
                await asyncio.sleep(10)
