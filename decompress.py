import ctypes
import zlib
import zstandard
import lz4.block
import os

from rotor import Rotor

# Precompute the rotor key and instantiate the rotor once
ROT_A = 'j2h56ogodh3se'
ROT_B = '=dziaq.'
ROT_C = '|os=5v7!"-234'
ROT_KEY = ROT_A * 4 + (ROT_B + ROT_A + ROT_C) * 5 + '!' + '#' + ROT_B * 7 + ROT_C * 2 + '*' + '&' + "'"

ROT = Rotor(ROT_KEY)

# Load libraries once to reuse later
if os.name == "posix":
    lib = ctypes.CDLL("./libs/libpubdecrypt.so")
elif os.name == "nt":
    lib = ctypes.CDLL("./libs/libpubdecrypt.dll")
else:
    lib = None  # In case the platform is unsupported

def _reverse_bytes(byte_arr: bytearray) -> bytearray:
    
    for i in range(128):
        byte_arr[i] ^= 154
    
    byte_arr.reverse()

    return bytes(byte_arr)

def nxs_unpack(data: bytearray):
    if not lib:
        raise RuntimeError("No supported library found")

    wrapped_key = ctypes.create_string_buffer(4)
    data_in = ctypes.create_string_buffer(data[20:])
    
    lib.public_decrypt(data_in, wrapped_key)

    ephemeral_key = int.from_bytes(wrapped_key.raw, "little")
    decrypted = bytearray()

    for i, x in enumerate(data[20 + 128:]):
        val = x ^ ((ephemeral_key >> (i % 4 * 8)) & 0xff)
        if i % 4 == 3:
            ror = (ephemeral_key >> 19) | ((ephemeral_key << (32 - 19)) & 0xFFFFFFFF)
            ephemeral_key = (ror + ((ror << 2) & 0xFFFFFFFF) + 0xE6546B64) & 0xFFFFFFFF
        decrypted.append(val)

    return bytes(decrypted)

def zflag_decompress(flag: int, data: bytearray, original_size: int=0):
    if flag == 1:
        return zlib.decompress(data, bufsize=original_size)
    elif flag == 2:
        return lz4.block.decompress(data, uncompressed_size=0x0FFFFFFE)
    elif flag == 3:
        return zstandard.ZstdDecompressor().decompress(data)
    elif flag == 5:
        return data
    return data

def special_decompress(flag: int, data: bytearray) -> bytearray:
    if flag == "rot":
        return  _reverse_bytes(zlib.decompress(ROT.decrypt(data)))
    elif flag == "nxs3":
        buf = nxs_unpack(data)
        return lz4.block.decompress(buf, int.from_bytes(data[16:20], "little"))
    return data