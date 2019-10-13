import os
from typing import Union, Dict


class ApplicationSettings:
    """
    Application Settings. Init them with a dict of settings.
    Main.py will try to import settings.json.
    Missing variables in json file (or if no file present) will be loaded from ENV.
    """
    websocket_url: str = None
    uuid: str = None
    token: str = None

    def __init__(self, data: Union[Dict[str, str], None] = None):
        if data and type(data) is dict:
            for k, v in data.items():
                setattr(self, k, v)
        for attr in self.__attrs__():
            if not getattr(self, attr):
                v = os.environ.get(attr)
                if not v:
                    raise EnvironmentError("Failed to Load \"{}\" Value from Environment".format(attr))
                setattr(self, attr, v)

    @staticmethod
    def __attrs__():
        """
        Required Settings to Work
        :return: Required Settings Sequence
        """
        return 'websocket_url', 'uuid', 'token'


# Base on original FunctionRestrict Class. TODO:ADD LINK
# On init, a options dict will initialize effect_flags list and get the *result_function_out* in options_result
class ServerOptions:
    AVATAR_ENABLED: int = 1 << 4
    EFFECT_FORCE: int = 1 << 13
    EFFECT_TORNADO: int = 1 << 14
    EFFECT_LIGHTNING: int = 1 << 15
    EFFECT_WIND: int = 1 << 16
    EFFECT_THOR: int = 1 << 17
    EFFECT_MOON: int = 1 << 18
    EFFECT_ECLIPSE: int = 1 << 19
    EVENT1_ENABLE: int = 1 << 20
    EVENT2_ENABLE: int = 1 << 21
    EVENT3_ENABLE: int = 1 << 22
    EVENT4_ENABLE: int = 1 << 23

    effect_flags: list = []

    options_result: int = None

    def __init__(self, options: dict):
        self.effect_flags = []
        self.options_result = 0

        for key, val in options.items():
            if val and hasattr(self, key.upper()):
                self.effect_flags.append(getattr(self, key.upper()))

        for effect_flag in self.effect_flags:
            self.options_result |= effect_flag

    def __call__(self):
        """
        Return the options result inited by effect flags
        :return:int Options Result
        """
        return self.options_result


class ServerSettings:
    def __init__(self, server: dict):
        self.host: str = server['address']
        self.port: str = server['port']
        self.options: ServerOptions = ServerOptions(server['options'])
        self.socket_timeout = server.get('socket_timeout')


