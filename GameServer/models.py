# This file is based on gunbound-server-link gameserver.py
# Modified to fit with OpenGB

import json

import secrets
from GameServer import cryptography
from GameServer.utils import *

import logging

logger = logging.getLogger("Models")


class FunctionRestrict:
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

    @staticmethod
    def get_function_value(effect_flags):
        result_function_out: int = 0
        for effect_flag in effect_flags:
            result_function_out |= effect_flag
        return result_function_out


# class Avatar:
#     @staticmethod
#     def get_avatar_by_user(in_username):
#         user_extended_avatar = []
#         if in_username == "saneusername":
#             user_extended_avatar.append(bytes.fromhex("0100 0100"))  # space marine (H)
#             user_extended_avatar.append(bytes.fromhex("0100 0000"))  # space marine (B)
#             user_extended_avatar.append(bytes.fromhex("0100 0200"))  # battle goggles (E)
#             user_extended_avatar.append(bytes.fromhex("0180 0300"))  # blue flag (F)
#             user_extended_avatar.append(bytes.fromhex("8F80 0100"))  # love cupid M (F)
#             user_extended_avatar.append(bytes.fromhex("0380 0300"))  # violet flag (F)
#         if in_username == "amigos":
#             user_extended_avatar.append(bytes.fromhex("A5800100"))
#             user_extended_avatar.append(bytes.fromhex("4B800000"))
#             user_extended_avatar.append(bytes.fromhex("3D800200"))
#             user_extended_avatar.append(bytes.fromhex("3D800300"))
#         return user_extended_avatar


class Room:
    """
    Mango: For now i guess Room can be a GameServer instance.
    But i will check if it's necessary to post and validate rooms with the Control Center
    """
    room_id: int = -1
    room_name = ""
    password = ""
    map_id = 0
    game_settings = bytes.fromhex("00 00 00 00")
    occupants_max = 0
    room_state = 0  # waiting: 0, play: 1
    player_sessions = []

    def __init__(self, in_id, in_room_name, in_password, in_map_id, in_game_settings, in_occupants_max):
        self.room_id = in_id
        self.room_name = in_room_name
        self.password = in_password
        self.map_id = in_map_id
        self.game_settings = in_game_settings
        self.occupants_max = in_occupants_max
        self.player_sessions = []

    @staticmethod
    def find_room_position(in_world_room):
        # find a free room id
        for index in range(0xFF):
            index_is_occupied = False
            for room_item in in_world_room:
                if room_item.room_id == index:
                    index_is_occupied = True
                    break
            if not index_is_occupied:
                return index
        logger.error("No room ids available")
        return 0

    @staticmethod
    def find_room_slot(in_room):
        # find a free room id
        for index in range(0x10):
            index_is_occupied = False
            for session_item in in_room.player_sessions:
                if session_item.room_slot == index:
                    index_is_occupied = True
                    break
            if not index_is_occupied:
                return index
        logger.error("No room slots available")
        return 0

    @staticmethod
    def find_room_team(in_room):
        # find a team to insert a new player
        team_a_size = 0
        team_b_size = 0
        for session_item in in_room.player_sessions:
            if session_item.room_team == 0:
                team_a_size += 1
            else:
                team_b_size += 1

        if team_a_size > team_b_size:
            return 1
        else:
            return 0

    @staticmethod
    def find_room_by_id(in_world_room, room_id):
        for room_item in in_world_room:
            if room_item.room_id == room_id:
                return room_item
        return None

    @staticmethod
    def find_room_by_user(in_world_room, in_username):
        for room_item in in_world_room:
            for player in room_item.player_sessions:
                if player.user.username == in_username:
                    return room_item
        return None

    @staticmethod
    def remove_session(in_world_room, in_username):
        for room_item in in_world_room:
            for player_index in range(len(room_item.player_sessions)):
                if room_item.player_sessions[player_index].user.username == in_username:
                    room_item.player_sessions.pop(player_index)
                    # destroy room if last player has quit
                    return True
        return False

    @staticmethod
    def remove_empty_rooms(in_world_room):
        cleanup_still_required = True

        while cleanup_still_required:
            for in_room_index in range(len(in_world_room)):
                if len(in_world_room[in_room_index].player_sessions) == 0:
                    in_world_room.pop(in_room_index)
                    break
            else:
                cleanup_still_required = False


class User:
    """
    Mango: This model should be loaded from Control Center and validated.
    """
    username = ""
    token = ""
    """
    Mango: Instead of using the user password in plain, we will do login on the launcher
    and we will use and auth token here.
    """
    guild: str = ""
    rank_current: int = 19
    rank_season: int = 19
    cash: int = 0
    gold: int = 0

    # 2 types of avatars - equipped (WORD) and extended (DWORD)
    # extended:
    # first (LSB) and second byte are the shortened avatar code
    # shortened avatar code's LSB is 0 when no avatar is worn
    # second byte's most significant bit determines gender (1=male)
    # third byte describes the slot (body: 0, head: 1, eye: 2, flag: 3)
    # fourth byte (MSB) is unknown, maybe upper byte of slot (3rd byte)
    # equipped:
    # truncate extended avatar from DWORD to WORD. 4x for head, body, eye and flag
    avatar_equipped = bytes.fromhex("00 80 00 80 00 80 00 00")
    avatar_inventory = []  # list of DWORD-sized bytes

    def __init__(self, user: dict):
        self.username = user['username']
        self.token = user['token']
        self.guild = user.get('guild', '')
        # self.gender = in_gender  # gender is not used for now - see avatar bytes
        self.rank_current = user['rank_current']
        self.rank_season = user['rank_season']
        self.avatar_equipped = bytes.fromhex(user.get('avatar_current') or "00 80 00 80 00 80 00 00")  # default: male
        self.avatar_inventory = user.get('avatar_inventory', [])

        self.cash = user['cash']
        self.gold = user['gold']

    @property
    def as_dict(self):
        return {
            'username': self.username,
            'token': self.token,
            'guild': self.guild,
            'rank_current': self.rank_current,
            'rank_season': self.rank_season,
            'avatar_current': bytes_to_hex(self.avatar_equipped),
            'avatar_inventory': self.avatar_inventory,
            'cash': self.cash,
            'gold': self.gold,
        }


class Session:
    auth_token = bytearray()
    session_unique = bytearray()
    user: User = None
    channel_position = -1
    client_version = 0
    socket_tx_sum = 0
    client = None
    address = None

    # room stuff
    is_room_key = False
    room_slot = -1
    room_team = 0
    room_tank_primary = 0xFF
    room_tank_secondary = 0xFF

    def __init__(self, client_socket, in_address):
        self.auth_token = secrets.token_bytes(4)
        self.session_unique = secrets.token_bytes(4)
        self.client = client_socket
        self.address = in_address
        self.room_slot = -1
        self.is_room_key = False
        logger.info("New session initialized")
        if self.client is not None:
            logger.info("Session IP: {} | Port: {}".format(self.address[0], self.address[1]))

    def decrypt(self, encrypted_bytes, client_command):
        return cryptography.gunbound_dynamic_decrypt(
            encrypted_bytes, self.user.username, self.user.token, self.auth_token, client_command)

    def encrypt(self, plain_bytes, client_command):
        # align to encryption block size
        mutable_plain_bytes = bytearray()
        mutable_plain_bytes.extend(plain_bytes)
        for unused_pad_byte in range(12 - (len(plain_bytes) % 12)):
            mutable_plain_bytes.append(0x00)

        return cryptography.gunbound_dynamic_encrypt(
            mutable_plain_bytes, self.user.username, self.user.token, self.auth_token, client_command)

    def send(self, command, bytes_to_send, rtc=None):
        payload = None
        if rtc is None:
            payload = Session.generate_packet(self.socket_tx_sum, command, bytes_to_send)
        else:
            mutable_bytes_to_send = bytearray()
            mutable_bytes_to_send.extend(int_to_bytes(rtc, 2))
            mutable_bytes_to_send.extend(bytes_to_send)
            payload = Session.generate_packet(self.socket_tx_sum, command, mutable_bytes_to_send)

        if self.client is None:
            logger.debug("SEND requested on bot, ignoring")
            return
        self.client.send(payload)
        logger.debug("SEND>> {} {}".format(hex(command), bytes_to_hex(payload)))
        self.socket_tx_sum += len(payload)

    def send_encrypted(self, command, bytes_to_send, rtc=None):
        self.send(command, self.encrypt(bytes_to_send, command), rtc=rtc)

    # Generate a valid packet (header with length, sequence, command) with a given payload
    @staticmethod
    def generate_packet(sent_packet_length, command, data_bytes):
        packet_expected_length = len(data_bytes) + 6
        packet_sequence = Session.get_sequence(sent_packet_length + packet_expected_length)

        response = bytearray()
        response.extend(int_to_bytes(packet_expected_length, 2))
        response.extend(int_to_bytes(packet_sequence, 2))
        response.extend(int_to_bytes(command, 2))

        response.extend(data_bytes)
        return response

    # Gunbound packet sequence, generated from sum of packet lengths
    @staticmethod
    def get_sequence(sum_packet_length):
        return (((sum_packet_length * 0x43FD) & 0xFFFF) - 0x53FD) & 0xFFFF

    @staticmethod
    def get_session(in_world_session, in_username):
        for session_item in in_world_session:
            if session_item.user.username == in_username:
                return session_item
        return None

    @staticmethod
    def remove_session(in_world_session, in_username):
        for index in range(len(in_world_session)):
            if in_world_session[index].user.username == in_username:
                in_world_session.pop(index)

    @staticmethod
    def find_channel_position(in_world_session):
        # find a new channel position
        for index in range(0xFF):
            index_is_occupied = False
            for session_item in in_world_session:
                if session_item.channel_position == index:
                    index_is_occupied = True
                    break
            if not index_is_occupied:
                return index
        logger.debug("No channel slots available")
        return 0

    @staticmethod
    def find_highest_channel_position(in_world_session):
        highest_position = 0
        for session_item in in_world_session:
            if session_item.channel_position > highest_position:
                highest_position = session_item.channel_position
        return highest_position

    @staticmethod
    def sendall(in_world_session, in_command, in_data):
        for session_item in in_world_session:
            session_item.send(in_command, in_data)

