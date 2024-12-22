from pathlib import Path

class XORDecryptor:
    def __init__(self, key_path: Path):
        with open(key_path, "rb") as key_reader:
            self.xor_key = key_reader.read()

    # KSA(The Key-scheduling Algorithm)
    def generate_keys(self, length: int) -> bytearray:
        key_data = self.xor_key[:]  # Copy key state
        i, j = 0
        key = bytearray(length)  # Use bytearray for faster appends and memory efficiency

        for k in range(length):
            i = (i + 1) & 0xFF
            j = (j + key_data[i]) & 0xFF

            # Swap in a single line
            key_data[i], key_data[j] = key_data[j], key_data[i]

            # Generate key byte directly without extra variables
            key[k] = key_data[(key_data[i] + key_data[j]) & 0xFF]
        
        return key

    # Decrypts data with key using XOR
    def decrypt(self, data: bytearray) -> bytearray:
        return data ^ self.generate_keys(len(data))
    
# Decrypt file with file's encryption type flag
def file_decrypt(flag, data, key=None, crc=0, file_length=0, file_original_length=0):
    match flag:
        case 1:
            if key == None:
                Exception("KEY FOR FILEFLAG 1 NOT SPECIFIED (check keys.txt)")

            size = file_length

            if size > 0x80:
                size = 0x80

            key = [(key + x) & 0xFF for x in range(0, 0x100)]
            data = bytearray(data)
            for j in range(size):
                data[j] = data[j] ^ key[j % 0xff]
            
        case 2:
            b = crc ^ file_original_length

            start = 0
            size = file_length

            if size > 0x80:
                start = (crc >> 1) % (file_length - 0x80)
                size = 2 * file_original_length % 0x60 + 0x20

            key = [(x + b) & 0xFF for x in range(0, 0x81, 1)]
            for j in range(size):
                data[start + j] = data[start + j] ^ key[j % 0x80]
        case 3:
            b = crc ^ file_original_length

            start = 0
            size = file_length
            if size > 0x80:
                start = (crc >> 1) % (file_length - 0x80)
                size = 2 * file_original_length % 0x60 + 0x20
            
            key = [(x + b) & 0xFF for x in range(0, 0x81, 1)]
            data = bytearray(data)
            for j in range(size):
                data[start + j] = data[start + j] ^ key[j % 0x80]
        case 4:
            v3 = int(file_original_length)
            v4 = int(crc)

            crckey = (v3 ^ v4) & 0xff
            offset = 0
            length = 0

            if file_length <= 0x80:
                length = file_length
            elif file_length > 0x80:
                offset = (v3 >> 1) % (file_length - 0x80)
                length = (((v4 << 1) & 0xffffffff) % 0x60 + 0x20)


            data = bytearray(data)

            for xx in range(offset, offset + length, 1):
                data[xx] ^= crckey
                crckey = (crckey + 1) & 0xff

    return data
