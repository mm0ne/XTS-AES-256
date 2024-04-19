from Crypto.Cipher import AES
import secrets

TWEAK = b"\x00" * 16


class XTSAES:
    def __init__(self, key):
        if len(key) != 32:
            raise Exception("Key size must be 32 bytes")
        self.key1 = key[:16]
        self.key2 = key[16:]

    def encrypt(self, plaintext, tweak=TWEAK):
        aes1 = AES.new(self.key1, AES.MODE_ECB)
        if tweak:
            tweak = AES.new(self.key2, AES.MODE_ECB).encrypt(tweak)
        else:
            tweak = AES.new(self.key2, AES.MODE_ECB).encrypt(secrets.token_bytes(16))

        data_blocks = [plaintext[i : i + 16] for i in range(0, len(plaintext), 16)]
        ciphertext = list()
        is_partial = False
        for block in data_blocks:
            if len(block) < 16:
                is_partial = True
                break
            cipher_block = aes1.encrypt(self.block_xor(block, tweak))
            ciphertext.append(self.block_xor(cipher_block, tweak))

            tweak = self.get_next_tweak(tweak)

        if is_partial:
            pm = data_blocks[-1]
            last_enc = ciphertext.pop(-1)
            cm = last_enc[: len(pm)]
            cp = last_enc[len(pm) :]
            last_plaintext = pm + cp

            cipher_block = aes1.encrypt(self.block_xor(last_plaintext, tweak))
            last_enc = self.block_xor(cipher_block, tweak)

            ciphertext.append(last_enc)
            ciphertext.append(cm)

        return b"".join(ciphertext)

    def decrypt(self, ciphertext, tweak=TWEAK):
        aes1 = AES.new(self.key1, AES.MODE_ECB)

        if tweak:
            tweak = AES.new(self.key2, AES.MODE_ECB).encrypt(tweak)
        else:
            tweak = AES.new(self.key2, AES.MODE_ECB).encrypt(secrets.token_bytes(16))

        data_blocks = [ciphertext[i : i + 16] for i in range(0, len(ciphertext), 16)]
        is_partial = len(data_blocks[-1]) < 16
        plaintext = list()
        for i, block in enumerate(data_blocks[:-1]):
            if i == len(data_blocks) - 2 and is_partial:
                break
            plain_block = aes1.decrypt(self.block_xor(block, tweak))
            plaintext.append(self.block_xor(plain_block, tweak))
            tweak = self.get_next_tweak(tweak)

        if is_partial:
            next_tweak = self.get_next_tweak(tweak)
            plain_block = aes1.decrypt(self.block_xor(data_blocks[-2], next_tweak))
            last_plaintext = self.block_xor(plain_block, next_tweak)

            # ciphertext stealing
            cm = data_blocks[-1]
            pm = last_plaintext[: len(cm)]
            cp = last_plaintext[len(cm) :]
            last_enc = cm + cp
            plain_block = aes1.decrypt(self.block_xor(last_enc, tweak))
            plain_block = self.block_xor(plain_block, tweak)
            plaintext.append(plain_block)
            plaintext.append(pm)
        else:
            last_enc = data_blocks[-1]
            plain_block = aes1.decrypt(self.block_xor(last_enc, tweak))
            plain_block = self.block_xor(plain_block, tweak)
            plaintext.append(plain_block)

        return b"".join(plaintext)

    def get_next_tweak(self, tweak):
        next_tweak = bytearray()

        carry_in = 0
        carry_out = 0

        for j in range(0, 16):
            carry_out = (tweak[j] >> 7) & 1
            next_tweak.append(((tweak[j] << 1) + carry_in) & 0xFF)
            carry_in = carry_out

        if carry_out:
            next_tweak[0] ^= 0x87

        return next_tweak

    def block_xor(self, block1, block2):
        return bytes(a ^ b for a, b in zip(block1, block2))

    @staticmethod
    def load_key_from_hex(hex_key):
        return bytes.fromhex(hex_key)

    @staticmethod
    def save_key_to_hex(key):
        return key.hex()
