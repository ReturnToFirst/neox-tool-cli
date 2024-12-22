from copy import copy

class XORDecryptor:

    #inits the key
    def __init__(self, key_path):
        with open(key_path, "rb") as kr:
            self.xor_key = kr.read()

    #generates the key with a length of X numbers
    def generate_keys(self, length):
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

    #decrypts with the key
    def decrypt(self, data):
        return [data ^ self.generate_keys(len(data))]
    
