# StandAlone Run for Testings and Develop

import sys
import logging
import threading

from GameServer.models import User, FunctionRestrict
from GameServer.gs import GameServer

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG
)

bind_address = '127.0.0.1'

world_session = []
world_room = []
world_user = User.get_users()

enabled_server_functions = [FunctionRestrict.EFFECT_THOR, FunctionRestrict.EFFECT_FORCE,
                            FunctionRestrict.EFFECT_MOON, FunctionRestrict.EFFECT_LIGHTNING,
                            FunctionRestrict.AVATAR_ENABLED]

game_server = GameServer(bind_address, 8370, world_session, world_room, world_user)

game_server.gs_funcrestrict = FunctionRestrict.get_function_value(enabled_server_functions)

threading.Thread(target=game_server.listen).start()



