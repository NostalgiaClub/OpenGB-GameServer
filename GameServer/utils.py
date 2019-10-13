# This file is based on gunbound-server-link gameserver.py
# Modified to fit with OpenGB


# convert a bytes-like input into a hex-string
def bytes_to_hex(input_bytes):
    return "".join("{:02X}".format(b) for b in input_bytes)


# convert an integer into a series of little-endian bytes
def int_to_bytes(input_integer, size):
    # LSB on left (little endian)
    output_bytes = bytearray()
    for i in range(size):
        output_bytes.append(input_integer & 0xff)
        input_integer = input_integer >> 8
    return output_bytes


# convert a series of bytes into a little-endian integer given a size
def bytes_to_int(input_bytes, size):
    # parsed as little endian
    if len(input_bytes) < size:
        print("bytes_to_int: requested size is smaller than input bytes")
        return 0
    output_int = 0
    for i in range(size):
        output_int |= input_bytes[i] << (i * 8)
    return output_int


# internally used in resize_bytes
def pad_bytes(input_bytes, desired_size):
    output = bytearray()
    output.extend(input_bytes)
    output.extend(bytearray.fromhex("00" * (desired_size - len(output))))
    return output


# internally used in resize_bytes
def truncate_bytes(input_bytes, desired_size):
    if len(input_bytes) > desired_size:
        return input_bytes[:desired_size]


# extends (pad: 00) or clips a bytes-like input to fit the desired size
def resize_bytes(input_bytes, desired_size):
    if len(input_bytes) > desired_size:
        return input_bytes[:desired_size]
    else:
        return pad_bytes(input_bytes, desired_size)


# goes through as many bytes as possible and creates a string, stopping at the first null terminator
def string_decode(input_bytes):
    result = ""
    for input_byte in input_bytes:
        if input_byte != 0:
            result += chr(input_byte)
        else:
            return result
    return result


# converts a string IP into a bytes representation
def ip_to_bytes(in_ip):
    ip_bytes = bytearray()
    ip_bytes.extend(map(int, in_ip.split('.')))
    return ip_bytes
