from Crypto.Cipher import AES

class XTSAES:
    def __init__(self, key, tweak=None):
        if len(key) != 2 * AES.block_size:
            raise Exception(f"Key size must be {2 * AES.block_size} bytes")
        self.key1 = key[:AES.block_size]
        self.key2 = key[AES.block_size:]
        self.tweak = tweak or b"\xff" * AES.block_size

    def encrypt(self, plaintext):
        if len(plaintext) < AES.block_size:
            raise Exception("Data size must be >= 16")

        aes1 = AES.new(self.key1, AES.MODE_ECB)
        tweak = AES.new(self.key2, AES.MODE_ECB).encrypt(self.tweak)

        data_blocks = [plaintext[i:i+AES.block_size] for i in range(0, len(plaintext), AES.block_size)]
        ciphertext = list()
        is_partial = False
        for block in data_blocks:
            if len(block) < AES.block_size:
                is_partial = True
                break
            cipher_block = aes1.encrypt(self._block_xor(block, tweak))
            ciphertext.append(self._block_xor(cipher_block, tweak))
            tweak = self._get_next_tweak(tweak)

        if is_partial:
            pm = data_blocks[-1]
            last_enc = ciphertext.pop(-1)
            cm = last_enc[:len(pm)]
            cp = last_enc[len(pm):]
            last_plaintext = pm + cp

            cipher_block = aes1.encrypt(self._block_xor(last_plaintext, tweak))
            last_enc = self._block_xor(cipher_block, tweak)

            ciphertext.append(last_enc)
            ciphertext.append(cm)

        return b"".join(ciphertext)

    def decrypt(self, ciphertext):
        if len(ciphertext) < AES.block_size:
            raise Exception("Data size must be >= 16")

        aes1 = AES.new(self.key1, AES.MODE_ECB)
        tweak = AES.new(self.key2, AES.MODE_ECB).encrypt(self.tweak)

        data_blocks = [ciphertext[i:i+AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]
        is_partial = len(data_blocks[-1]) < AES.block_size
        plaintext = list()
        for i, block in enumerate(data_blocks[:-1]):
            if i == len(data_blocks) - 2 and is_partial:
                break
            plain_block = aes1.decrypt(self._block_xor(block, tweak))
            plaintext.append(self._block_xor(plain_block, tweak))
            tweak = self._get_next_tweak(tweak)

        if is_partial:
            next_tweak = self._get_next_tweak(tweak)
            plain_block = aes1.decrypt(self._block_xor(data_blocks[-2], next_tweak))
            last_plaintext = self._block_xor(plain_block, next_tweak)
            cm = data_blocks[-1]
            pm = last_plaintext[:len(cm)]
            cp = last_plaintext[len(cm):]
            last_enc = cm + cp
        else:
            last_enc = data_blocks[-1]

        plain_block = aes1.decrypt(self._block_xor(last_enc, tweak))
        plain_block = self._block_xor(plain_block, tweak)
        plaintext.append(plain_block)

        if is_partial:
            plaintext.append(pm)

        return b"".join(plaintext)

    def _get_next_tweak(self, tweak):
        next_tweak = bytearray()
        carry_in = 0
        carry_out = 0
        for j in range(0, AES.block_size):
            carry_out = (tweak[j] >> 7) & 1
            next_tweak.append(((tweak[j] << 1) + carry_in) & 0xFF)
            carry_in = carry_out
        if carry_out:
            next_tweak[0] ^= 0x87
        return next_tweak

    def _block_xor(self, block1, block2):
        return bytes(a ^ b for a, b in zip(block1, block2))
