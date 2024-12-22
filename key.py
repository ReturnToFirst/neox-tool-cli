from copy import copy

class Keys:
    
    #inits the key
    def __init__(self):
        with open("neox_xor.key", "rb") as kr:
            self.keys = kr.read()

    #generates the key with a length of X numbers
    def gen_keys(self, length):
        key_ = []
        key_data = self.keys
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
            key_.append(key_i)
        self.keys = key_

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
    
