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
        self._user: str = user
        self._password: str = password
        self._evt_listeners_: List[EventListener] = []
        self._evt_loop = asyncio.new_event_loop()
        evt_thread = Thread(
            target=self._evt_loop.run_until_complete, args=(self._event_handler(),))
        evt_thread.daemon = True
        evt_thread.start()

    def get_name(self) -> str:
        resp = requests.get(
            self._api_prefix + "GetHomeName", verify=False, auth=(self._user, self._password))
        json = resp.json()
        if resp.status_code != 200:
            _LOGGER.error(
                "Failed to get home name: [%d](%s)", resp.status_code,
                json["err_msg"])
            return ""
        return json["name"]

    def set_name(self, name: str) -> None:
        resp = requests.get(
            self._api_prefix + "SetHomeName", verify=False, auth=(self._user, self._password),
            params={"name": name})
        if resp.status_code != 200:
            _LOGGER.error(
                "Failed to set home name to '%s': [%d](%s)", name,
                resp.status_code, resp.json()["err_msg"])

    def get_mode(self) -> str:
        resp = requests.get(
            self._api_prefix + "GetOperationMode", verify=False, auth=(self._user, self._password))
        json = resp.json()
        if resp.status_code != 200:
            _LOGGER.error(
                "Failed to get operation mode: [%d](%s)", resp.status_code,
                json["err_msg"])
            return ""
        return json["mode"]

    def set_mode(self, mode: str) -> None:
        resp = requests.get(
            self._api_prefix + "SetOperationMode", verify=False, auth=(self._user, self._password),
            params={"mode": mode})
        if resp.status_code != 200:
            _LOGGER.error(
                "Failed to set operation mode to '%s': [%d](%s)", mode,
                resp.status_code, resp.json()["err_msg"])

    def add_event_listener(self, cb: EventListener) -> None:
        self._evt_loop.call_soon_threadsafe(self._evt_listeners_.append, cb)

    def del_event_listener(self, cb: EventListener) -> None:
        self._evt_loop.call_soon_threadsafe(self._evt_listeners_.remove, cb)


    async def _event_handler(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.verify_mode = ssl.CERT_NONE
        authorization = ("Basic " +
            base64.b64encode(f"{self._user}:{self._password}".encode()).decode())
        async with websockets.connect(self._ws_uri, ssl=context,
                                      extra_headers={'Authorization': authorization}) as websocket:
            async for msg in websocket:
                _LOGGER.debug("Received event: %s", msg)
                try:
                    evt = json.loads(msg)
                    for cb in self._evt_listeners_:
                        cb(evt)
                except json.decoder.JSONDecodeError as err:
                    _LOGGER.error("Invalid JSON '%s': %s", msg, err)
