import io
import struct

# Return name of decryption algorithm based on the file_flag index parameter
def get_decryption_algorithm_name(decryption_flag: int = 0) -> str:
    decryption_algorithms = {
        0: "No Encryption",
        1: "XOR_128",
        2: "XOR_32_127_TYPE1",
        3: "XOR_32_127_TYPE2",
        4: "XOR_32_127_TYPE3",
    }

    return decryption_algorithms.get(decryption_flag, None)

def get_decompression_algorithm_name(compression_flag: int = 0) -> str:
    compression_algorithms = {
        0: "No Compression",
        1: "ZLIB",
        2: "LZ4",
        3: "ZSTD",
        5: "Unknown"
    }
    return compression_algorithms.get(compression_flag, None)