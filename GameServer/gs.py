# This file is based on gunbound-server-link gameserver.py
# Modified to fit with OpenGB

import socket
import threading
import random
import datetime

import logging
from typing import Dict

from GameServer import cryptography

from GameServer.models import User, Session, Room
from GameServer.utils import *
from GameServer.settings import ServerSettings


logger = logging.getLogger("GameServer")
udp_logger = logging.getLogger("UDP Server")


class GameUDPServer:
    keep_running = True

    def __init__(self, host, port, timeout=10):
        self.keep_running = True
        self.host = host
        self.port = port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)
        self.sock.bind((self.host, self.port))

        udp_logger.info("UDP Bound")

    def listen(self):
        while self.keep_running:
            try:
                udp_payload, udp_client_address = self.sock.recvfrom(1024)
                udp_logger.debug("UDP: Echoing data back to {} {}".format(
                    str(udp_client_address), bytes_to_hex(udp_payload)))
                self.sock.sendto(udp_payload, udp_client_address)
                udp_logger.debug("UDP Done")
            except socket.timeout:
                pass
            except:
                udp_logger.exception("Uncaught Exception on UDP Server", exc_info=True)
        else:
            udp_logger.info("Exiting UDP Server")


class CommandProcessor:
    world_session = []
    world_room = []
    parent_instance = None

    def __init__(self, in_world_session, in_world_room, in_parent_instance):
        self.world_session = in_world_session
        self.world_room = in_world_room
        self.parent_instance = in_parent_instance

    def join_channel(self, data, client_session, motd_channel):
        # check where the player was previously from - if from game/room, clean up
        if client_session.room_slot != -1:
            logger.info("Room cleanup requested")
            previous_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
            new_keybearer_session: Session = None
            for session_item in previous_room.player_sessions:
                if session_item.user.username != client_session.user.username:
                    new_keybearer_session = session_item
                    break

            migration_packet = bytearray()
            if new_keybearer_session is not None:
                # if host leaves the room, the packet is never built or sent
                # team A/B data seems to get messy after this
                migration_packet.append(new_keybearer_session.room_slot)
                migration_packet.append(len(previous_room.room_name))
                migration_packet.extend(previous_room.room_name.encode("ascii"))
                migration_packet.append(previous_room.map_id)
                migration_packet.extend(previous_room.game_settings)
                migration_packet.extend(bytes.fromhex("FF FF FF FF FF FF FF FF"))  # unknown
                migration_packet.append(previous_room.occupants_max)  # guessed

            for session_item in previous_room.player_sessions:
                if session_item.user.username != client_session.user.username:
                    logger.info("Sending migration packet")
                    session_item.send(0x3020, int_to_bytes(client_session.room_slot, 2))
                    # assuming 3040 is a broadcast since everyone needs to know of key migration
                    session_item.send(0x3400, migration_packet)

            if Room.remove_session(self.world_room, client_session.user.username):
                Room.remove_empty_rooms(self.world_room)
                logger.info("Room cleanup completed successfully")
            else:
                logger.info("Room cleanup requested but failed")

            client_session.room_slot = -1
            client_session.is_room_key = False

        # last 2 bytes indicate desired channel LSB MSB end
        desired_channel = bytes_to_int(data[-2:], 2)
        if desired_channel == 0xFFFF:
            # fresh login requesting for a free channel. In this case we will default to channel 1
            logger.info("Fresh login, routing to channel 1 [{}]".format(hex(desired_channel)))
            desired_channel = 0
        extended_channel_motd = motd_channel + "\r\nRequesting SVC_CHANNEL_JOIN " + \
                                str(desired_channel) + " at " + \
                                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\r\n" + \
                                "Client Version: " + str(client_session.client_version)

        # find all ACTIVE channel participants (!= sessions). room_slot must be -1
        active_channel_users = []
        for session_item in self.world_session:
            if session_item.room_slot == -1:
                active_channel_users.append(session_item)

        channel_join_packet_new = bytearray()
        channel_join_packet_new.extend(bytes.fromhex("00 00"))
        channel_join_packet_new.extend(int_to_bytes(desired_channel, 2))
        channel_join_packet_new.append(Session.find_highest_channel_position(active_channel_users))
        channel_join_packet_new.append(len(active_channel_users))

        # channel participants are sessions with a room slot of -1 (aka not in a room)
        for session_item in active_channel_users:
            channel_player = bytearray()
            channel_player.append(session_item.channel_position)
            channel_player.extend(resize_bytes(session_item.user.username.encode("ascii"), 12))
            channel_player.extend(session_item.user.avatar_equipped)  # gender determined from avatar?
            channel_player.extend(resize_bytes(session_item.user.guild.encode("ascii"), 8))
            channel_player.extend(int_to_bytes(session_item.user.rank_current, 2))
            channel_player.extend(int_to_bytes(session_item.user.rank_season, 2))
            channel_join_packet_new.extend(channel_player)

        channel_join_packet_new.extend(extended_channel_motd.encode("ascii"))

        client_session.send(0x2001, channel_join_packet_new)

        # channel data DOES affect room state - whether tunnel will be used bc user cannot be found

        # advertise channel join to existing clients
        join_notification = bytearray()
        join_notification.append(client_session.channel_position)
        join_notification.extend(resize_bytes(client_session.user.username.encode("ascii"), 0xC))
        join_notification.extend(client_session.user.avatar_equipped)  # avatar
        join_notification.extend(resize_bytes(client_session.user.guild.encode("ascii"), 8))
        join_notification.extend(int_to_bytes(client_session.user.rank_current, 2))  # current rank
        join_notification.extend(int_to_bytes(client_session.user.rank_season, 2))  # season rank

        for session_item in active_channel_users:
            if session_item.user.username != client_session.user.username:
                logger.debug("Sending Join Notification")
                session_item.send(0x200E, join_notification)

    def cash_update(self, client_session):
        # 1032: cash update
        # unknown dword in the middle, all zeroes
        # some sort of dword at the end of 0x1032
        # could be "crap" padding bytes to fit encryption's 12-byte block
        client_session.send_encrypted(0x1032, int_to_bytes(client_session.user.cash, 4))

    def print_to_client(self, client_session, in_message):
        client_session.send(0x5101, in_message.encode("ascii"))

    def room_update(self, client_session):
        client_session.send(0x3105, bytes.fromhex(""), rtc=0)

    def start_game_serv2(self, data, client_session):
        unknown_data = data[6:]  # A2 89 CB 01 / seems different every time, longer for multiplayer
        selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
        selected_room.room_state = 1  # waiting -> playing
        start_data = bytearray()

        # set the game's map
        if selected_room.map_id == 0:
            logger.info("Rolling random map with {}%".format(self.parent_instance.cave_map_chance_percentage))
            if random.randint(0, 100) <= self.parent_instance.cave_map_chance_percentage:
                selected_room.map_id = 0  # special map (cave), assigning it for readability
            else:
                selected_room.map_id = random.randint(1, 10)
            start_data.append(selected_room.map_id)  # random, normal map
        else:
            start_data.append(selected_room.map_id)  # user-selected map

        current_map_data = None
        spawn_points = []  # can be overwritten in the future to support Mix / EvsW
        for map_row in self.parent_instance.map_data:
            if map_row["map_id"] == selected_room.map_id:
                current_map_data = map_row
                map_side_ab = selected_room.game_settings[2] & 1
                logger.debug("Map Side (A=0, B=1): {}".format(map_side_ab))
                if map_side_ab == 0:
                    spawn_points = current_map_data["positions_a_side"]
                else:
                    spawn_points = current_map_data["positions_b_side"]
        # In Serv2, if ( numberOfPlayers <= 6 ), "Small Mode" is internally activated.
        # I am not sure what it does yet. Probably to prevent spawning players too far from each other

        logger.debug(current_map_data)
        logger.debug(spawn_points)

        # randomized spawn order list (8 possible spawn points)
        spawn_order = list(range(8))
        random.shuffle(spawn_order)
        logger.debug("Spawn order / slot: {}".format(spawn_order))

        # randomized turn order list
        turn_order = list(range(len(selected_room.player_sessions)))
        random.shuffle(turn_order)
        logger.debug("Turn order / slot: {}".format(turn_order))

        # below size of WORD seems excessive, value is guessed
        start_data.extend(int_to_bytes(len(selected_room.player_sessions), 2))
        for session_item in selected_room.player_sessions:
            # random bot selection
            # turns out that dragon and knight are 17/18 respectively, differing from Serv2's 14/15. Thanks @phnx
            if session_item.room_tank_primary == 0xFF:
                logger.debug("Rolling primary random with {}%".format(
                    self.parent_instance.special_bot_chance_percentage))
                if random.randint(0, 100) <= self.parent_instance.special_bot_chance_percentage:
                    session_item.room_tank_primary = random.randint(17, 18)
                else:
                    session_item.room_tank_primary = random.randint(0, 13)
            if session_item.room_tank_secondary == 0xFF:
                logger.debug("Rolling secondary random with {}%".format(
                    self.parent_instance.special_bot_chance_percentage))
                if random.randint(0, 100) <= self.parent_instance.special_bot_chance_percentage:
                    session_item.room_tank_secondary = random.randint(17, 18)
                else:
                    session_item.room_tank_secondary = random.randint(0, 13)

            start_data.append(session_item.room_slot)
            start_data.extend(resize_bytes(session_item.user.username.encode("ascii"), 0xC))
            start_data.append(session_item.room_team)
            start_data.append(session_item.room_tank_primary)
            start_data.append(session_item.room_tank_secondary)
            # Positional data: x (2 bytes), y (2 bytes). thanks @phnx
            player_spawn_point = spawn_points[spawn_order[session_item.room_slot]]  # default randomized spawn
            # player_spawn_point = spawn_points[7]  # override spawn position. use either this or the above line
            player_x = random.randint(player_spawn_point["x_min"], player_spawn_point["x_max"])
            player_y = 0 if player_spawn_point["y"] is None else player_spawn_point["y"]
            logger.debug("Player spawn point: {} x: {} y: {}".format(player_spawn_point, player_x, player_y))
            start_data.extend(int_to_bytes(player_x, 2))  # x position
            start_data.extend(int_to_bytes(player_y, 2))  # y position

            start_data.extend(int_to_bytes(turn_order[session_item.room_slot], 2))  # turn position. thanks @phnx
        # unknown: would guess FuncRestrict but it's short of a byte
        # default FFFF, setting 0000 activates event
        start_data.extend(bytes.fromhex("00 FF"))
        start_data.extend(unknown_data)  # echo the stuff sent by game host

        for session_item in selected_room.player_sessions:
            session_item.send_encrypted(0x3432, start_data)

    def start_game_gis(self, data, client_session):
        # GIS experiment
        unknown_data = data[6:]  # see start_game_serv2
        selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
        selected_room.room_state = 1  # waiting -> playing
        start_data = bytearray()
        # start_data.extend(selected_room.game_settings)
        # start_data.extend(bytes.fromhex("00 00 00 00"))

        start_data.extend(bytes.fromhex("00 00 00 00"))
        # start_data.extend(unknown_data)  # echo the stuff sent by game host

        start_data.append(selected_room.map_id)  # map
        # below size of WORD seems excessive, value is guessed
        start_data.extend(int_to_bytes(len(selected_room.player_sessions), 2))
        for session_item in selected_room.player_sessions:
            # random bot selection
            if session_item.room_tank_primary == 0xFF:
                session_item.room_tank_primary = random.randint(0, 13)
            if session_item.room_tank_secondary == 0xFF:
                session_item.room_tank_secondary = random.randint(0, 13)

            start_data.append(session_item.room_slot)
            start_data.extend(resize_bytes(session_item.user.username.encode("ascii"), 0xC))
            start_data.append(session_item.room_team)  # guessed
            start_data.append(session_item.room_tank_primary)  # comsik.txt: looks correct
            start_data.append(session_item.room_tank_secondary)
            # unknown positional data. looks nothing like the *_stage_pos.txt content
            # map position's theory:
            # grab the 8 possible slots from *_stage_pos.txt
            # if player count is below (?), enter "small mode", selecting denser slot positions
            # assign player's slot position (prefer alternating)
            # set the position below
            # right now i have no idea how this value works, so everyone uses the same value
            # as a consequence, everyone spawns on the same spot
            start_data.extend(bytes.fromhex("36 02 00 00"))
            start_data.append(session_item.room_slot)  # hack - this value needs incrementing
            start_data.append(0)  # hack
        # current event
        # default FFFF, setting 0000 activates event
        start_data.extend(bytes.fromhex("12 34"))
        # start_data.extend(unknown_data)  # echo the stuff sent by game host

        for session_item in selected_room.player_sessions:
            session_item.send_encrypted(0x3432, start_data)
        logger.info("GIS: sending structured data")

    def start_game_anyhowly(self, data, client_session):
        # GIS experiments
        # this gets into game: cozy tower, bottom left (no foothold), solo, 1 other opponent
        # 0x3432,
        # 01010101 6A000101 01010101 01010101 01010101 01010101 01010101 01010101 01010101
        # position 4 (0-indexed): map
        # position 5, non-zero value
        # this gets into game: nirvana left side, 3 players
        # position 7: first player channel index
        # pos 24, 26 set first player x, y
        # 21, 22 = mobile 1, 2 (0B 0A)
        gamesession_data = bytearray()
        gamesession_data.extend(bytearray.fromhex("44 44 44 44 04 01 00 00 44 44 44 44"))
        gamesession_data.extend(bytearray.fromhex("44 44 11 22 33 44 55 66 77 0B 0A 00"))
        gamesession_data.extend(bytearray.fromhex("02 ff 02 55 55 55 55 55 55 55 55 55"))
        logger.info("GIS: sending fuzzed data")
        client_session.send_encrypted(0x3432, gamesession_data)


class GameServer(object):
    motd_channel: str = "$Channel MOTD"
    motd_room: str = "$Room MOTD"
    special_bot_chance_percentage: str = 2  # normally 2% (2)
    cave_map_chance_percentage: str = 100  # normally 20% (20)
    map_data: list = []
    gs_funcrestrict = 0xFFFFF
    command_processor: CommandProcessor = None
    default_socket_timeout: int = 10
    login_results = None

    callbacks = dict()

    # def __init__(self, host, port, in_world_session, in_world_room, in_world_user):
    def __init__(
            self,
            settings: dict,
            world_session: list,
            world_room: list,
            map_data: list,
            callbacks: Dict[str, callable]):

        self.settings = ServerSettings(settings)
        self.socket_timeout = self.settings.socket_timeout or self.default_socket_timeout
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(self.socket_timeout)
        self.sock.bind((self.settings.host, self.settings.port))

        self.world_session = world_session
        self.world_room = world_room
        logger.info("TCP Bound")

        self.map_data = map_data

        self.callbacks.update(callbacks)

        self.keep_running = True
        self.udp_server = GameUDPServer(self.settings.host, self.settings.port, self.socket_timeout)
        self.udp_thread = None

        self.command_processor = CommandProcessor(self.world_session, self.world_room, self)

        self.gs_funcrestrict = self.settings.options()

    def start(self):
        self._start_udp()
        self.listen()

    def _start_udp(self):
        if self.udp_thread and self.udp_thread.is_alive():
            logger.error("UDP Server is already running")
        else:
            self.udp_thread = threading.Thread(target=self.udp_server.listen)
            self.udp_thread.start()

    def listen(self):
        self.sock.listen(5)
        logger.info("Listening on {}:{}".format(self.settings.host, self.settings.port))
        while self.keep_running:
            try:
                client, address = self.sock.accept()
                client.settimeout(6000)
                threading.Thread(target=self.client_connection, args=(client, address)).start()
            except socket.timeout:
                pass

    def stop(self):
        self.udp_server.keep_running = False
        self.keep_running = False

    def client_connection(self, client, address):
        logger.info("New connection from {}".format(address))
        socket_rx_size = 1024
        client_session = Session(client, address)
        socket_rx_sum = 0

        while self.keep_running:
            try:
                data = client.recv(socket_rx_size)
                if data:
                    if len(data) < 6:
                        logger.debug("RECV BROKEN PACKET>>")
                        logger.debug(bytes_to_hex(data))
                    else:
                        # Try parse basic packet information
                        payload_size = bytes_to_int(data[0: 2], 2)
                        # sequence = bytes_to_int(data[2:4], 2)
                        client_command = bytes_to_int(data[4:6], 2)

                        logger.debug("RECV>> {} {}".format(hex(client_command), bytes_to_hex(data[6:])))

                        socket_rx_sum += payload_size

                        # Reply client if the service request is recognized
                        if client_command == 0x1000:
                            # uncomment below for debug token override - INSECURE
                            # client_session.auth_token = bytes.fromhex("00 98 6B C4")
                            logger.info("Generated token: {}".format(bytes_to_hex(client_session.auth_token)))
                            client_session.send(0x1001, client_session.auth_token)

                        elif client_command == 0x0000:
                            logger.debug("RECV> KEEPALIVE")

                        elif client_command == 0x1010:
                            logger.debug("RECV> SVC_LOGIN/ADMIN")

                            """
                            Mango: Changing the login method.
                            Originally, username was searched by name in a list of all the users (crazy if you have
                            a lot of users), and then the password was validated.
                            Making it login the user with the username/token combination.
                            The launcher should login the user first, and obtain the corresponding login token
                            """
                            username_bytes = cryptography.gunbound_static_decrypt(data[6:6 + 0x10])
                            user_object = self.callbacks['get_user'](string_decode(username_bytes))

                            if user_object is None:
                                # User not found, send disconnection packet
                                logger.error("Queried user could not be found, disconnecting socket")
                                client_session.send(0x1012, bytes.fromhex("10 00"))
                                return False

                            else:
                                # future: check user if already logged in, *across worlds*
                                client_session.user = User(user_object)

                                dynamic_payload = client_session.decrypt(data[6 + 0x20:], client_command)

                                received_token = string_decode(dynamic_payload[0:0xC])

                                if received_token != client_session.user.token:
                                    client_session.send(0x1012, bytes.fromhex("11 00"))
                                    return False

                                logger.info("User [{}] logged in".format(client_session.user.username))
                                client_session.client_version = dynamic_payload[0x14] | (dynamic_payload[0x15] << 8)
                                logger.info("Client version [{}]".format(client_session.client_version))
                                client_session.channel_position = Session.find_channel_position(self.world_session)
                                # client_session.channel_position = 0x0a
                                self.world_session.append(client_session)

                                login_packet = bytearray()
                                login_packet.extend(bytearray.fromhex("00 00"))  # maybe gender?
                                login_packet.extend(client_session.session_unique)  # "seems unused
                                login_packet.extend(resize_bytes(client_session.user.username.encode("ascii"), 0xC))
                                login_packet.extend(client_session.user.avatar_equipped)  # currently worn avatar
                                login_packet.extend(resize_bytes(client_session.user.guild.encode("ascii"), 8))
                                login_packet.extend(int_to_bytes(client_session.user.rank_current, 2))
                                login_packet.extend(int_to_bytes(client_session.user.rank_season, 2))
                                login_packet.extend(int_to_bytes(3333, 2))  # guild member count
                                login_packet.extend(int_to_bytes(1337, 2))  # rank position, current
                                login_packet.extend(int_to_bytes(0, 2))  # ?
                                login_packet.extend(int_to_bytes(1337, 2))  # rank position, season
                                login_packet.extend(int_to_bytes(0, 2))  # ?
                                login_packet.extend(int_to_bytes(3332, 2))  # individual's guild rank
                                # most likely shot history, vs mobile etc.
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.extend(bytearray.fromhex("00000000 00000000 0000"))

                                login_packet.extend(int_to_bytes(888888, 4))  # gp, current
                                login_packet.extend(int_to_bytes(888888, 4))  # gp, season
                                login_packet.extend(int_to_bytes(client_session.user.gold, 4))  # gold
                                # unknown
                                login_packet.extend(bytearray.fromhex("00000000 00000000 00000000 00000000"))
                                login_packet.append(0)  # still unknown
                                login_packet.extend(int_to_bytes(self.gs_funcrestrict, 4))  # weather, event etc

                                if client_session.client_version == 313 or client_session.client_version == 376:
                                    # GIS protocol - throwing in cash state to appease client
                                    # this is an odd packet combining both encrypted and plain data
                                    login_packet.extend(client_session.encrypt(
                                        int_to_bytes(client_session.user.cash, 4), 0x1012))

                                client_session.send(0x1012, login_packet)

                                self.command_processor.cash_update(client_session)

                            if client_session.client_version == 313 or client_session.client_version == 376:
                                # force GIS to change state; reply from channel join does that
                                self.command_processor.join_channel(data, client_session, self.motd_channel)

                        elif client_command == 0x1020:
                            logger.debug("RECV> SVC_USER_ID")
                            payload_data = client_session.decrypt(data[6:], 0x1020)
                            requested_username = string_decode(payload_data[0:0xC])
                            logger.info("Querying for {}".format(requested_username))
                            found_id = self.callbacks['get_user'](requested_username)
                            if found_id is None:
                                logger.error("No user found: {}".format(requested_username))
                            else:
                                logger.info("Found id: {}".format(found_id.username))
                            # if an id is not found, everything below should be automatically 0
                            # we don't distinguish between login/game id, so echo the request back
                            # 1020 is unusual as it requires a user to be authenticated before use (for crypto)
                            # Mango adding None check and sending empty values if not found
                            id_crypted_response = bytearray()
                            id_crypted_response.extend(resize_bytes(
                                "".encode("ascii") if not found_id else found_id.username.encode("ascii"), 0xC))
                            id_crypted_response.extend(resize_bytes(
                                "".encode("ascii") if not found_id else found_id.username.encode("ascii"), 0xC))
                            # guild (8 bytes)
                            id_crypted_response.extend(resize_bytes(
                                "".encode("ascii")  if not found_id else found_id.guild.encode("ascii"), 8))
                            # current rank (2 bytes), season rank (2 bytes)
                            id_crypted_response.extend(int_to_bytes(
                                0 if not found_id else found_id.rank_current, 2))
                            id_crypted_response.extend(int_to_bytes(
                                0 if not found_id else found_id.rank_season, 2))
                            client_session.send_encrypted(0x1021, id_crypted_response, rtc=0)

                        elif client_command == 0x2000:
                            logger.debug("RECV> SVC_CHANNEL_JOIN")
                            self.command_processor.join_channel(data, client_session, self.motd_channel)

                        elif client_command == 0x2100:
                            logger.debug("RECV> SVC_ROOM_SORTED_LIST")
                            # first byte: room filter type, 1 = all, 2 = waiting
                            # direct room join is technically under filter: ALL (longer payload)
                            room_filter_mode = data[6]
                            if room_filter_mode == 1:
                                logger.debug("Filter: ALL")
                            elif room_filter_mode == 2:
                                logger.debug("Filter: WAITING")
                            else:
                                logger.debug("Filter: UNKNOWN")

                            # FIXME: room directory pagination is done on server
                            # where is the "next/previous page is available" indicator?
                            # client does strange things if more than 6 rooms are sent
                            # Mango: TODO: Find directory paginators with a serv2 client/server debug?
                            room_reply = bytearray()
                            room_reply.extend(int_to_bytes(len(self.world_room), 2))
                            # room_reply.append(len(self.world_room))
                            # room_reply.append(0xFF)  # was hoping that this is the indicator for multiple pages..

                            for room_item in self.world_room:
                                room_entry = bytearray()
                                room_entry.extend(int_to_bytes(room_item.room_id, 2))  # 0-indexed room number, as WORD
                                room_entry.append(len(room_item.room_name))
                                room_entry.extend(room_item.room_name.encode("ascii"))
                                room_entry.append(room_item.map_id)  # map: 0 = random, 1 = miramo ..
                                room_entry.extend(room_item.game_settings)  # example bytes: B2620C00
                                room_entry.append(len(room_item.player_sessions))  # occupant count
                                room_entry.append(room_item.occupants_max)  # max occupants
                                room_entry.append(room_item.room_state)  # play state or ready (play = 1, waiting = 0)
                                if len(room_item.password) > 0:
                                    room_entry.append(1)  # room locked: 1 = password required
                                else:
                                    room_entry.append(0)  # room locked: 0 = default open
                                room_reply.extend(room_entry)

                            client_session.send(0x2103, room_reply, rtc=0)

                        elif client_command == 0x2104:
                            logger.debug("RECV> SVC_ROOM_DETAIL")
                            requested_room_id = bytes_to_int(data[6:], 2)
                            requested_room = Room
                            for room_item in self.world_room:
                                if room_item.room_id == requested_room_id:
                                    requested_room = room_item
                                    logger.debug("Room found")
                                    break
                            else:
                                logger.error("Room Not Found. WIll Send Invalid Room Data")
                            response = bytearray()
                            # see command 0x2100 - same stuff with user details appended
                            response.append(len(requested_room.room_name))
                            response.extend(requested_room.room_name.encode("ascii"))
                            response.append(requested_room.map_id)  # map: 0 = random, 1 = miramo ..
                            response.extend(requested_room.game_settings)
                            response.append(len(requested_room.player_sessions))  # occupant count
                            response.append(requested_room.occupants_max)  # max occupants
                            response.append(requested_room.room_state)  # play state
                            if len(requested_room.password) > 0:
                                response.append(1)  # room locked: 1 = password required
                            else:
                                response.append(0)  # room locked: 0 = default open

                            for room_player in requested_room.player_sessions:
                                response.extend(resize_bytes(room_player.user.username.encode("ascii"), 0xC))
                                response.extend(room_player.user.avatar_equipped)  # currently worn avatar
                                response.extend(resize_bytes(room_player.user.guild.encode("ascii"), 8))
                                response.extend(int_to_bytes(room_player.user.rank_current, 2))
                                response.extend(int_to_bytes(room_player.user.rank_season, 2))

                            # decent chunk copied from 0x2100
                            client_session.send(0x2105, response, rtc=0)

                        elif client_command == 0x2110:
                            logger.debug("RECV> SVC_ROOM_JOIN")
                            # first 2 bytes are requested room number, subsequent: join password
                            requested_room_id = bytes_to_int(data[6:8], 2)
                            requested_room_password = string_decode(data[8:])
                            # future: check if room id actually exists, and verify password
                            requested_room: Room = Room.find_room_by_id(self.world_room, requested_room_id)

                            if requested_room is None:
                                logger.error("Requested an invalid room. things are going to break")
                            else:
                                client_session.room_team = Room.find_room_team(requested_room)
                                client_session.room_slot = Room.find_room_slot(requested_room)
                                client_session.room_tank_primary = 0xFF
                                client_session.room_tank_secondary = 0xFF
                                requested_room.player_sessions.append(client_session)

                            client_ip = ip_to_bytes(client_session.address[0])
                            client_port = bytes.fromhex("20 AB")  # 8363 seems to be hardcoded
                            logger.info("{} - {}:{}".format(
                                client_session.user.username, requested_room_id, requested_room_password))

                            # decent chunk copied from 0x2100
                            # 20AB = port 8363, client listens there for UDP

                            # respond to the client first
                            # the start of the client_join_request are room-specific details
                            # how does the client know who the host is?
                            client_session.send(0x21F5, bytes.fromhex("03"), rtc=0)  # unknown - why 3?
                            client_join_request = bytearray()
                            client_join_request.extend(int_to_bytes(0, 2))  # probably RTC but not sure
                            client_join_request.extend(int_to_bytes(0x0100, 2))  # unknown
                            client_join_request.extend(int_to_bytes(requested_room.room_id, 2))  # probably room id
                            client_join_request.append(len(requested_room.room_name))
                            client_join_request.extend(requested_room.room_name.encode("ascii"))
                            client_join_request.append(requested_room.map_id)
                            client_join_request.extend(requested_room.game_settings)
                            client_join_request.extend(bytes.fromhex("FF FF FF FF FF FF FF FF"))  # 4x WORDs?
                            # a bit unusual that occupants_max comes before number of players, normally swapped
                            # unless everything else is wrong..
                            client_join_request.append(requested_room.occupants_max)
                            client_join_request.append(len(requested_room.player_sessions))

                            for session_item in requested_room.player_sessions:
                                session_ip = ip_to_bytes(session_item.address[0])
                                client_join_request.append(session_item.room_slot)
                                client_join_request.extend(resize_bytes(session_item.user.username.encode("ascii"), 0xC))
                                client_join_request.extend(session_ip)
                                client_join_request.extend(client_port)
                                client_join_request.extend(session_ip)
                                client_join_request.extend(client_port)
                                client_join_request.append(session_item.room_tank_primary)  # primary tank
                                client_join_request.append(session_item.room_tank_secondary)  # secondary tank
                                client_join_request.append(session_item.room_team)  # team side (0 = A, 1 = B)
                                client_join_request.append(0x01)  # unknown, stays at 1
                                client_join_request.extend(session_item.user.avatar_equipped)  # currently worn avatar
                                client_join_request.extend(resize_bytes(session_item.user.guild.encode("ascii"), 8))
                                client_join_request.extend(int_to_bytes(session_item.user.rank_current, 2))
                                client_join_request.extend(int_to_bytes(session_item.user.rank_season, 2))

                            client_join_request.extend(self.motd_room.encode("ascii"))
                            client_session.send(0x2111, client_join_request)

                            # notify room host of new join (3010)
                            for session_item in requested_room.player_sessions:
                                if session_item.is_room_key:
                                    logger.debug("Sending join request to room host {}".format(
                                        session_item.user.username))
                                    join_request = bytearray()
                                    join_request.append(client_session.room_slot)
                                    join_request.extend(resize_bytes(client_session.user.username.encode("ascii"), 0xC))
                                    join_request.extend(client_ip)
                                    join_request.extend(client_port)
                                    join_request.extend(client_ip)
                                    join_request.extend(client_port)
                                    join_request.append(client_session.room_tank_primary)  # primary tank
                                    join_request.append(client_session.room_tank_secondary)  # secondary tank
                                    join_request.append(client_session.room_team)  # team side
                                    join_request.extend(client_session.user.avatar_equipped)  # currently worn avatar
                                    join_request.extend(resize_bytes(client_session.user.guild.encode("ascii"), 8))
                                    join_request.extend(int_to_bytes(client_session.user.rank_current, 2))
                                    join_request.extend(int_to_bytes(client_session.user.rank_season, 2))
                                    session_item.send(0x3010, join_request)

                        elif client_command == 0x2010:
                            logger.debug("RECV> SVC_CHANNEL_CHAT")
                            dynamic_payload = client_session.decrypt(data[6:], client_command)
                            chat_message = string_decode(dynamic_payload[1:dynamic_payload[0] + 1])
                            logger.debug("Channel Chat from {}: {}".format(client_session.user.username, chat_message))

                            padded_username = resize_bytes(client_session.user.username.encode("ascii"), 0xC)
                            chat_broadcast_packet = bytearray()
                            chat_broadcast_packet.append(client_session.channel_position)  # user's channel position
                            chat_broadcast_packet.extend(padded_username)
                            chat_broadcast_packet.append(len(chat_message))
                            chat_broadcast_packet.extend(chat_message.encode("ascii"))

                            # broadcast to all open sockets
                            for session_item in self.world_session:
                                session_item.send_encrypted(0x201F, chat_broadcast_packet)

                        elif client_command == 0x2120:
                            logger.debug("RECV> SVC_ROOM_CREATE")
                            received_data = data[6:]
                            room_title = string_decode(received_data[1:received_data[0] + 1])
                            # [0:3] game configuration - see 3101, [4:7] pass, [8] room capacity
                            room_other_data = received_data[received_data[0] + 1:]
                            room_playmode = bytes_to_int(room_other_data[2:4], 2)
                            room_playmode_string = "UNKNOWN"
                            if room_playmode == 0:
                                room_playmode_string = "SOLO"
                            elif room_playmode == 0x44:
                                room_playmode_string = "SCORE"
                            elif room_playmode == 0x08:
                                room_playmode_string = "TAG"
                            elif room_playmode == 0x0C:
                                room_playmode_string = "JEWEL"
                            room_password = string_decode(room_other_data[4:8])
                            room_capacity = room_other_data[8]
                            created_room = Room(Room.find_room_position(self.world_room), room_title, room_password, 0,
                                                room_other_data[0:4], room_capacity)
                            client_session.room_slot = 0  # host room slot
                            client_session.is_room_key = True  # indicates host

                            # reset the client's internal tank values
                            client_session.room_tank_primary = 0xFF
                            client_session.room_tank_secondary = 0xFF

                            created_room.player_sessions.append(client_session)
                            self.world_room.append(created_room)
                            logger.info("Creating room {} with password {} playing {} for {} players".format(
                                room_title, room_password, room_playmode_string, room_capacity))

                            room_join_reply = bytearray()
                            room_join_reply.extend(bytes.fromhex("00 00 00"))  # unknown
                            room_join_reply.extend(int_to_bytes(created_room.room_id, 2))
                            room_join_reply.extend(self.motd_room.encode("ascii"))
                            client_session.send(0x2121, room_join_reply)

                        elif client_command == 0x3102:
                            logger.debug("RECV> SVC_ROOM_CHANGE_USEITEM")
                            prop_state_data = data[6:]
                            prop_state = bytes_to_int(prop_state_data[0:2], 2)
                            logger.debug("Room use item changed: {} {}".format(hex(prop_state), bin(prop_state)))
                            self.command_processor.room_update(client_session)

                        elif client_command == 0x3100:
                            logger.debug("RECV> SVC_ROOM_CHANGE_STAGE")
                            new_map_id = data[6]  # map 0 = random
                            selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            if selected_room is not None:
                                selected_room.map_id = new_map_id
                                logger.debug("RoomID: {} map set to {}".format(
                                    selected_room.room_id, "map set to", new_map_id))
                            else:
                                logger.debug("Selected room is None - ignoring")
                            self.command_processor.room_update(client_session)

                        elif client_command == 0x3101:
                            logger.debug("RECV> SVC_ROOM_CHANGE_OPTION")
                            map_properties = data[6:]
                            # game config is stored in a bitwise manner, but the details don't matter on the server
                            selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            if selected_room is not None:
                                selected_room.game_settings = map_properties
                            self.command_processor.room_update(client_session)

                        elif client_command == 0x3104:
                            logger.debug("RECV> SET_ROOM_TITLE")
                            new_title_raw = data[6:]
                            new_title_string = string_decode(new_title_raw)
                            print("SET_ROOM_TITLE", new_title_string)
                            selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            if selected_room is not None:
                                selected_room.room_name = new_title_string
                            self.command_processor.room_update(client_session)

                        elif client_command == 0x3103:
                            logger.debug("RECV> SVC_ROOM_CHANGE_MAXMEN")
                            room_capacity = data[6]  # map 0 = random
                            selected_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            if selected_room is not None:
                                selected_room.occupants_max = room_capacity
                                logger.debug("{} new room capacity: {}".format(selected_room.room_id, room_capacity))
                            self.command_processor.room_update(client_session)

                        elif client_command == 0x3210:
                            logger.debug("RECV> SVC_ROOM_SELECT_TEAM")
                            new_team_position = data[6]
                            logger.debug("Changing team to {}".format(new_team_position))
                            client_session.room_team = new_team_position
                            # probably "RTC" command in IDA
                            client_session.send(0x3211, bytes.fromhex(""), rtc=0)

                        elif client_command == 0x3200:
                            logger.debug("RECV> SVC_ROOM_SELECT_TANK")
                            mobile_string = {0: "Armor",
                                             1: "Mage",
                                             2: "Nak",
                                             3: "Trico",
                                             4: "Bigfoot",
                                             5: "Boomer",
                                             6: "Raon",
                                             7: "Lightning",
                                             8: "J.D.",
                                             9: "A.Sate",
                                             10: "Ice",
                                             11: "Turtle",
                                             12: "Grub",
                                             13: "Aduka",
                                             17: "Dragon",  # technically 14 (from disassembly), actually 17 (phnx)
                                             18: "Knight",  # technically 15, actually 18 (phnx).
                                             255: "Random"}

                            tank_primary = data[6]
                            tank_secondary = data[7]
                            client_session.room_tank_primary = tank_primary
                            client_session.room_tank_secondary = tank_secondary
                            logger.debug("{} selected {}/{}".format(
                                client_session.user.username, tank_primary, tank_secondary))
                            client_session.send(0x3201, bytes.fromhex(""), rtc=0)

                        elif client_command == 0x3230:
                            logger.debug("RECV> SVC_ROOM_USER_READY")
                            ready_state = data[6]
                            logger.debug("SVC_ROOM_USER_READY {}".format(ready_state))
                            # technically the server should know about this too but we aren't going to check yet
                            client_session.send(0x3231, bytes.fromhex(""), rtc=0)

                        elif client_command == 0x3232:
                            logger.debug("RECV> SVC_ROOM_RETURN_RESULT")
                            client_room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            if client_room is not None:
                                client_room.room_state = 0  # switch room state back to "waiting"
                            client_session.send(0x3233, bytes.fromhex(""), rtc=0)

                        elif client_command == 0x3430:
                            logger.debug("RECV> SVC_START_GAME")
                            if client_session.client_version == 314:  # actually 313, but swapped below when debugging
                                self.command_processor.start_game_anyhowly(data, client_session)
                            elif client_session.client_version == 313 or client_session.client_version == 342:
                                self.command_processor.start_game_gis(data, client_session)
                            else:  # serv2 protocol
                                self.command_processor.start_game_serv2(data, client_session)

                        elif client_command == 0x4200:
                            logger.debug("RECV> SVC_PLAY_END_JEWEL")
                            # probably rebroadcast to all clients (authoritative)
                            message_to_rebroadcast = client_session.decrypt(data[6:], 0x4200)
                            client_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            for session_item in client_room.player_sessions:
                                session_item.send_encrypted(0x4410, message_to_rebroadcast)

                        elif client_command == 0x4100:
                            logger.debug("RECV> SVC_PLAY_USER_DEAD")
                            # input data looks something like 13 00 00 00 00
                            # 4100 is responded with 4102, 4410, 4101
                            # 4102 -> 00130000 00000000 44344700 (broadcast)
                            # 4410 -> FF130000 4BD80DF4 4BD80DF4 (broadcast)
                            client_session.send(0x4101, bytes.fromhex(""))  # reply to origin
                            # 

                        elif client_command == 0x4412:
                            logger.debug("RECV> SVC_PLAY_RESULT")
                            # host requests 4412, but everyone receives a 4413
                            client_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                            for session_item in client_room.player_sessions:
                                session_item.send(0x4413, bytes.fromhex(""))

                        elif client_command == 0x4500:
                            logger.debug("RECV> SVC_TUNNEL")
                            # first 0xC bytes: metadata? next 0xC bytes: origin, next 0xC bytes: dest
                            # i would have assumed first 0xC bytes were the payload, but sometimes data comes AFTER dest
                            # edit 2: when blocking the client's udp listen port, the client makes a tunnel request
                            # server then forwards the client its own data without the first 2 bytes (wtf?)
                            # normally tunnel activates when something broke somewhere
                            tunnel_bytes = data[6:]
                            # unknown_prefix = tunnel_bytes[0:0xC]
                            requester_id = tunnel_bytes[0xC: 0x18]
                            destination_id = tunnel_bytes[0x18: 0x24]
                            logger.debug("Tunnel requested: {} to {}".format(
                                string_decode(requester_id), string_decode(destination_id)))

                        elif client_command == 0x6000:
                            logger.debug("RECV> SVC_PROP_GET")
                            flag_send_extended = data[6]
                            user_extended_avatar = client_session.user.avatar_inventory
                            prop_reply = bytearray()
                            prop_reply.extend(client_session.user.avatar_equipped)  # 8 bytes of equipped "short" avatar
                            prop_reply.extend(int_to_bytes(client_session.user.gold, 4))  # user's gold as DWORD
                            if flag_send_extended == 1:
                                prop_reply.extend(int_to_bytes(len(user_extended_avatar), 2))  # avatar count as WORD
                                for avatar_item in user_extended_avatar:
                                    prop_reply.extend(avatar_item)  # add "long" avatar codes (DWORDs)
                            client_session.send_encrypted(0x6001, prop_reply, rtc=0)
                            # send a 1032 cash update too
                            self.command_processor.cash_update(client_session)

                        elif client_command == 0x6004:
                            logger.debug("RECV> SVC_PROP_SET")
                            plain_avatar_equipped = client_session.decrypt(data[6:], 0x6004)
                            avatar_equipped = plain_avatar_equipped[0:8]  # 8 bytes of equipped avatar
                            # should verify if user owns these avatars
                            client_session.user.avatar_equipped = bytes(avatar_equipped)
                            logger.debug("{} equipping {}".format(
                                client_session.user.username, bytes_to_hex(bytes(avatar_equipped))))
                            client_session.send(0x6005, bytes.fromhex(""), rtc=0)
                            self.callbacks['user_update'](client_session.user)

                        elif client_command == 0x6011:
                            logger.debug("RECV> SVC_PROP_BUY_PP")
                            plain_bought_avatar = client_session.decrypt(data[6:], 0x6011)
                            extended_avatar = plain_bought_avatar[0:4]  # DWORD avatar
                            # normally this is the part where we check the item's price (serverside),
                            # check if player has the cash to purchase, deduct accordingly, send a 1032 update
                            # and store new purchase. for now we're skipping everything
                            logger.info("{} bought (cash) {}".format(
                                client_session.user.username, bytes_to_hex(bytes(extended_avatar))))
                            client_session.user.avatar_inventory.append(extended_avatar)
                            client_session.send(0x6017, bytes.fromhex(""), rtc=0)
                            self.command_processor.cash_update(client_session)
                            self.callbacks['user_update'](client_session.user)

                        elif client_command == 0x6010:
                            logger.debug("RECV> SVC_PROP_BUY")
                            plain_bought_avatar = client_session.decrypt(data[6:], 0x6010)
                            extended_avatar = plain_bought_avatar[0:4]  # DWORD avatar
                            # this is 6011 but with gold instead
                            logger.info("{} bougth (gold) {}".format(
                                client_session.user.username, bytes_to_hex(bytes(extended_avatar))))
                            client_session.user.avatar_inventory.append(extended_avatar)
                            client_session.send(0x6017, bytes.fromhex(""), rtc=0)
                            self.callbacks['user_update'](client_session.user)

                        elif client_command == 0x6020:
                            logger.debug("RECV> SVC_PROP_SELL")
                            plain_bought_avatar = client_session.decrypt(data[6:], 0x6020)
                            # item_position = plain_bought_avatar[0]  # item position in inventory
                            extended_avatar = plain_bought_avatar[1:5]  # DWORD avatar
                            # we'll acknowledge with OK but not do anything internally
                            logger.info("{} sold {}".format(
                                client_session.user.username, bytes_to_hex(bytes(extended_avatar))))
                            client_session.send(0x6027, bytes.fromhex(""), rtc=0)
                            self.callbacks['user_update'](client_session.user)

                        elif client_command == 0x6030:
                            logger.debug("RECV> SVC_PROP_GIFT")
                            gift_plain_packet = client_session.decrypt(data[6:], 0x6030)
                            gift_recipient = string_decode(gift_plain_packet[0:0xC])
                            # unknown_four_bytes = gift_plain_packet[0xC:0x10]
                            # item_position = gift_plain_packet[0x10]  # item position in inventory
                            extended_avatar = gift_plain_packet[0x11:0x15]  # DWORD avatar
                            gift_message = resize_bytes(gift_plain_packet[0x16:], gift_plain_packet[0x15])
                            gift_message = string_decode(gift_message)
                            # we'll acknowledge with OK but not do anything internally
                            logger.info("{} gifting {} to {} with message: {}".format(
                                client_session.user.username,
                                bytes_to_hex(bytes(extended_avatar)),
                                gift_recipient,
                                gift_message))
                            # 6037 might *not* actually be the OK. I can't remember how gifts worked
                            client_session.send(0x6037, bytes.fromhex(""), rtc=0x6005)
                            self.callbacks['item_gift'](
                                client_session.user,
                                gift_recipient,
                                bytes_to_hex(bytes(extended_avatar)),
                                gift_message)

                        elif client_command == 0x5100:
                            logger.debug("RECV> GENERIC_COMMAND")
                            # acknowledgement is optional
                            command_received_raw = string_decode(data[7:]).split(" ")
                            command_received = command_received_raw.pop(0)
                            command_parameters = " ".join(command_received_raw)

                            if command_received == "q":
                                client_session.send(0x3FFF, bytes.fromhex(""))
                                self.command_processor.print_to_client(client_session, "Room closed")

                            if command_received == "close":
                                client_room: Room = Room.find_room_by_user(self.world_room, client_session.user.username)
                                if client_room is not None:
                                    for room_player in client_room.player_sessions:
                                        room_player.send(0x3FFF, bytes.fromhex(""))
                                        self.command_processor.print_to_client(room_player, "Room closed")

                            elif command_received == "test":
                                client_session.send(0x5101, "Connection still alive".encode("ascii"))

                            elif command_received == "bcm":
                                for session_item in self.world_session:
                                    self.command_processor.print_to_client(session_item, command_parameters)

                            elif command_received == "tankset":
                                tank_value = int(command_parameters)
                                client_session.room_tank_primary = tank_value
                                response_message = "Your primary tank will be set as " + str(tank_value)
                                response_message += "\r\n" + "This takes effect after joining a room"
                                self.command_processor.print_to_client(client_session, response_message)

                            elif command_received == "gender":
                                if command_parameters == "m":
                                    client_session.user.avatar_equipped = bytes.fromhex("00 80 00 80 00 80 00 00")
                                else:
                                    client_session.user.avatar_equipped = bytes.fromhex("00 00 00 00 00 00 00 00")
                                response_message = "Re-login required for changes to take effect"
                                self.command_processor.print_to_client(client_session, response_message)

                            elif command_received == "sessions":
                                for session_item in self.world_session:
                                    if session_item.client is not None:
                                        message_row = session_item.user.username + " : " + session_item.address[0]
                                        self.command_processor.print_to_client(client_session, message_row)

                            elif command_received == "save":
                                self.command_processor.print_to_client(client_session, "Saving - check python console.")
                                self.callbacks['user_update'](client_session.user)
                                self.command_processor.print_to_client(client_session, "World user state saved")

                            elif command_received == "special_bot_chance":
                                self.special_bot_chance_percentage = int(command_parameters)
                                response_message = "Dragon/knight chance: " + str(self.special_bot_chance_percentage)
                                response_message += "%"
                                response_message += "\r\n" + "This value is specific to this server instance"
                                response_message += "\r\n" + "This value is non-persistent (resets on restart)"
                                self.command_processor.print_to_client(client_session, response_message)

                            elif command_received == "cave_map_chance":
                                self.cave_map_chance_percentage = int(command_parameters)
                                response_message = "Cave map chance: " + str(self.cave_map_chance_percentage) + "%"
                                response_message += "\r\n" + "This value is specific to this server instance"
                                response_message += "\r\n" + "This value is non-persistent (resets on restart)"
                                self.command_processor.print_to_client(client_session, response_message)

                            elif command_received == "json":
                                self.command_processor.print_to_client(client_session, client_session.user.as_dict)

                            elif command_received == "credits":
                                credits = "CREDITS"

                                credits += "\r\n\r\n" + "SOFTNYX: ethera knights blash45 pirania chuko scjang " \
                                                        "loserii johnny5 designer reddragon jchlee75 yaong2 " \
                                                        "jaeyong yesoori enddream cozy comsik"
                                credits += "\r\n" + "RZ: phnx, Kimberly, LeoTheFox - Clients, GunBound theory"
                                credits += "\r\n" + "UC: vkiko2 - IDAPython GameGuard string decryption"
                                credits += "\r\n" + "InsideGB (XFSGAMES)"
                                self.command_processor.print_to_client(client_session, credits)

                        else:
                            logger.exception("Unknown response to client command: {}".format(client_command))
                else:
                    logger.info("Client disconnected")
                    if client_session is not None:
                        if client_session.channel_position != -1:
                            for session_item in self.world_session:
                                if session_item.user.username != client_session.user.username:
                                    user_channel = bytearray()
                                    user_channel.append(client_session.channel_position)
                                    session_item.send(0x200F, user_channel)
                        if client_session.room_slot != -1:
                            Room.remove_session(self.world_room, client_session.user.username)
                            Room.remove_empty_rooms(self.world_room)
                        Session.remove_session(self.world_session, client_session.user.username)
                    return True
            except:
                client.close()
                logger.exception("Client forcibly closed without cleanup", exc_info=True)
                return False

