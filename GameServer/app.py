"""
Broker Application Implementation
This will connect to the Core server and retrieve configuration.
"""
import logging
import threading
import json
import websocket

from time import sleep

from GameServer.gs import GameServer
from GameServer.settings import ApplicationSettings


logger = logging.getLogger("Application")


class Application:
    server: GameServer = None
    server_settings: dict = None

    def __init__(self, settings: ApplicationSettings, map_data):
        self.running: bool = False
        self.keep_running: bool = True

        self.server_thread = None
        self.server_world_session = []
        self.server_world_room = []

        self.map_data = map_data

        self.incoming_actions = []
        self.user_results = {}

        self.ws_url = settings.websocket_url
        self.uuid = settings.uuid
        self.token = settings.token

        websocket.enableTrace(True)
        self.ws = websocket.WebSocketApp(
            self.ws_url,
            header=[
                'AUTH-UUID: {}'.format(self.uuid),
                'AUTH-TOKEN: {}'.format(self.token),
                'AUTH-TYPE: server',
            ],
            on_close=self._on_close,
            on_message=self._on_message,
            on_error=self._on_error,
        )
        self.ws.on_open = self._on_open

        logger.info("Application Init Completed")

    @property
    def callbacks(self):
        return {
            'get_user': self.get_user,
            'user_update': self.user_update,
            'item_gift': self.item_gift
        }

    def _on_open(self):
        if self.server_thread and self.server_thread.is_alive():
            logger.error("Cannot Start Server Thread over a Running Instance")
            return False

        self.server_thread = threading.Thread(name='ServerTCP', target=self._server_thread)
        self.server_thread.start()

    def _on_message(self, event):
        data = json.loads(event)
        logger.debug("Message Received {}".format(data))
        if data.get('type') and hasattr(self, "recv_{}".format(data['type'])):
            getattr(self, "recv_{}".format(data['type']))(data)
        elif data.get('type'):
            logger.error("Invalid Action {}".format(data['type']))
        else:
            logger.error("Unparsed Message")

    def _on_error(self, event):
        logger.error("Websocket Error {}".format(event))

    def _on_close(self):
        logger.info("WebSocket Closed")

    def start(self, *args, **kwargs):
        logger.info("Running Websocket Main Loop")
        self.ws.run_forever(*args, **kwargs)
        logger.info("Stop Signal Received, or WS Run End Unexpected")
        self.stop()

    def stop(self):
        self.keep_running = False
        self.server.stop()

    def _server_thread(self):
        logger.info("Server Thread Started")
        logger.info("Waiting Settings from Websocket Server")

        while not self.server_settings and self.keep_running:
            sleep(0.5)

        if not self.keep_running:
            logger.error("Cannot Start Server because Keep running was set to False")
            return None

        self.server = GameServer(
            self.server_settings,
            self.server_world_session,
            self.server_world_room,
            self.map_data,
            self.callbacks
        )

        self.server.start()

    def get_user(self, username):
        return self._get_user(username)

    def user_login(self, username):
        return self._user_login(username)

    def user_logout(self, username):
        ...

    def user_update(self, user):
        ...

    def item_buy(self, user, item):
        ...

    def item_sale(self, user, item):
        ...

    def item_gift(self, user, recipient, item, message):
        ...

    def _get_user(self, username):
        logging.info("Trying to get user data for {}".format(username))

        self.ws.send(data=json.dumps({
            'type': 'get_user',
            'username': username,
        }))

        while username not in self.user_results and self.keep_running:
            sleep(1)
            logging.debug(self.user_results)

        if not self.keep_running:
            logging.error("Cannot Finish User Login due to System Exit")
            return False

        results = self.user_results.pop(username)

        return results

    def _user_login(self, username):
        self.ws.send(data=json.dumps({
            'type': 'user_login',
            'username': username
        }))

    def _user_logout(self, username):
        self.ws.send(data=json.dumps({
            'type': 'user_logout',
            'username': username
        }))

    def _user_update(self, user):
        ...

    def recv_update_info(self, event):
        if event.get('server'):
            self.server_settings = event['server']
        else:
            logger.error("Update Info Not Related")

    def recv_user_info(self, event):
        self.user_results.update(event.get('user_info'))



