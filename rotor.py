from typing import List, Tuple

class Rotor:
    def __init__(self, key: str, n_rotors: int = 6) -> None:
        self.n_rotors: int = n_rotors
        self.set_key(key)

    def set_key(self, key: str) -> None:
        self.key: str = key
        self.rotors = None
        self.positions: List[int | None] = [None, None]

    def encrypt(self, buf: bytes) -> bytes:
        self.positions[0] = None
        return self._crypt(buf, do_decrypt=False)

    def decrypt(self, buf: bytes) -> bytes:
        self.positions[1] = None
        return self._crypt(buf, do_decrypt=True)

    def _crypt(self, buf: bytes, do_decrypt: bool) -> bytes:
        size, nr, rotors, pos = self._get_rotors(do_decrypt)
        outbuf = bytearray(len(buf))  # Using bytearray for in-place modification

        # Use a single loop for both encrypt and decrypt operations
        for i, c in enumerate(buf):
            for rotor, p in zip(reversed(rotors), reversed(pos)) if do_decrypt else zip(rotors, pos):
                c = p ^ rotor[c] if do_decrypt else rotor[c ^ p]
            outbuf[i] = c

        # Update rotor positions
        self._update_rotor_positions(nr, pos, rotors, size)

        return bytes(outbuf)  # Convert bytearray back to bytes before returning

    def _update_rotor_positions(self, nr: int, pos: List[int], rotors: Tuple[Tuple[int]], size: int) -> None:
        pnew = 0
        for i in range(nr):
            pnew = ((pos[i] + (pnew >= size)) & 0xff) + rotors[i][size]
            pos[i] = pnew % size

    def _get_rotors(self, do_decrypt: bool) -> Tuple[int, int, Tuple[int], List[int]]:
        nr = self.n_rotors
        rotors = self.rotors
        positions = self.positions[do_decrypt]

        if positions is None:
            if rotors:
                positions = list(rotors[3])
            else:
                size = 256
                id_rotor = list(range(size + 1))
                rand = random_func(self.key)

                E, D, positions = []
                for _ in range(nr):
                    i = size
                    positions.append(rand(i))
                    erotor, drotor = id_rotor[:], id_rotor[:]
                    drotor[i] = erotor[i] = 1 + 2 * rand(i // 2)

                    while i > 1:
                        r = rand(i)
                        i -= 1
                        erotor[r], erotor[i] = erotor[i], erotor[r]
                        drotor[erotor[0]] = 0

                    E.append(tuple(erotor))
                    D.append(tuple(drotor))

                self.rotors = rotors = (tuple(E), tuple(D), size, tuple(positions))
            self.positions[do_decrypt] = positions
        return rotors[2], nr, rotors[do_decrypt], positions
    
def random_func(key: str):
    # Initialize the state variables
    x, y, z = 995, 576, 767
    mask = 0xffff

    # Use the key to initialize the random state
    for c in map(ord, key):
        x = ((x << 3) | (x >> 13) + c) & mask
        y = ((y << 3) | (y >> 13) ^ c) & mask
        z = ((z << 3) | (z >> 13) - c) & mask

    # Ensure y is odd
    y |= 1

    # Perform modular arithmetic on x, y, z
    x = (171 * (x % 177) - 2 * (x // 177)) % 30269
    y = (172 * (y % 176) - 35 * (y // 176)) % 30307
    z = (170 * (z % 178) - 63 * (z // 178)) % 30323

    # Function to generate a pseudo-random number
    def rand(n: int) -> int:
        nonlocal x, y, z
        x = (171 * x) % 30269
        y = (172 * y) % 30307
        z = (170 * z) % 30323
        # Return a value within the range [0, n)
        return int(((x / 30269 + y / 30307 + z / 30323) * n) % n)

    return rand