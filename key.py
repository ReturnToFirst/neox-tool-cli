from copy import copy

class XORDecryptor:
    
    #inits the key
    def __init__(self, key_path):
        with open(key_path, "rb") as kr:
            self.xor_key = kr.read()

    #generates the key with a length of X numbers
    def gen_keys(self, length):
        key = []
        key_data = self.xor_key
        key_index = 0
        key_tmp_index = 0
        for i in range(length):
            key_index += 1
            tmp_data = key_data[key_index % 256]
            key_tmp_index += tmp_data
            key_tmp_index %= 256
            key_data[key_index % 256] = key_data[key_tmp_index]
            key_data[key_tmp_index] = tmp_data
            key_i = key_data[(key_data[key_index % 256] + tmp_data) % 256 & 0xFF]
            key.append(key_i)
        return key

    #makes sure the key is long enough
    def ensure_keys(self, length):
        if length > len(self.keys):
            self.gen_keys(max(length, 2000000))

    #decrypts with the key
    def decrypt(self, data):
        self.ensure_keys(len(data))
        data = bytearray(data)
        for i in range(len(data)):
            data[i] = data[i] ^ self.keys[i]
        return data
    
