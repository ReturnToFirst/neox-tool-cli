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
    def decrypt(self, data) -> bytearray:
        return [data ^ self.generate_keys(len(data))]
    
