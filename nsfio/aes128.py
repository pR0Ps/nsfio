#!/usr/bin/env python

from binascii import hexlify as hx
from binascii import unhexlify as uhx

# Pure python AES128 implementation
# SciresM, 2017
from struct import pack as pk
from struct import unpack as up

from Crypto.Cipher import AES
from Crypto.Util import Counter


def sxor(s1, s2):
    assert len(s1) == len(s2)
    return b"".join([pk("B", x ^ y) for x, y in zip(s1, s2)])


class AESCBC:
    """Class for performing AES CBC cipher operations."""

    def __init__(self, key, iv):
        self.aes = AESECB(key)
        if len(iv) != self.aes.block_size:
            raise ValueError("IV must be of size %X!" % self.aes.block_size)
        self.iv = iv

    def encrypt(self, data, iv=None):
        """Encrypts some data in CBC mode."""
        if iv is None:
            iv = self.iv
        out = b""
        while data:
            encb = self.aes.encrypt_block_ecb(sxor(data[:0x10], iv))
            out += encb
            iv = encb
            data = data[0x10:]
        return out

    def decrypt(self, data, iv=None):
        """Decrypts some data in CBC mode."""
        if len(data) % self.aes.block_size:
            raise ValueError("Data is not aligned to block size!")
        if iv is None:
            iv = self.iv
        out = b""
        while data:
            decb = sxor(self.aes.decrypt_block_ecb(data[:0x10]), iv)
            out += decb
            iv = data[:0x10]
            data = data[0x10:]
        return out

    def set_iv(self, iv):
        if len(iv) != self.aes.block_size:
            raise ValueError("IV must be of size %X!" % self.aes.block_size)
        self.iv = iv


class AESCTR:
    """Class for performing AES CTR cipher operations."""

    def __init__(self, key, nonce, offset=0):
        self.key = key
        self.nonce = nonce
        self.seek(offset)

    def encrypt(self, data, ctr=None):
        if ctr is None:
            ctr = self.ctr
        return self.aes.encrypt(data)

    def decrypt(self, data, ctr=None):
        return self.encrypt(data, ctr)

    def seek(self, offset):
        self.ctr = Counter.new(64, prefix=self.nonce[0:8], initial_value=(offset >> 4))
        self.aes = AES.new(self.key, AES.MODE_CTR, counter=self.ctr)

    def bktrPrefix(self, ctr_val):
        return self.nonce[0:4] + ctr_val.to_bytes(4, "big")

    def bktrSeek(self, offset, ctr_val, virtualOffset=0):
        offset += virtualOffset
        self.ctr = Counter.new(64, prefix=self.bktrPrefix(ctr_val), initial_value=(offset >> 4))
        self.aes = AES.new(self.key, AES.MODE_CTR, counter=self.ctr)


class AESXTS:
    """Class for performing AES XTS cipher operations"""

    def __init__(self, keys, sector=0):
        self.keys = keys[:16], keys[16:]
        if not (type(self.keys) is tuple and len(self.keys) == 2):
            raise TypeError("XTS mode requires a tuple of two keys.")
        self.K1 = AESECB(self.keys[0])
        self.K2 = AESECB(self.keys[1])

        self.sector = sector
        self.block_size = self.K1.block_size

        self.sector_size = 0x200

    def encrypt(self, data, sector=None):
        if sector is None:
            sector = self.sector
        if len(data) % self.block_size:
            raise ValueError("Data is not aligned to block size!")
        out = b""
        while data:
            tweak = self.get_tweak(sector)
            out += self.encrypt_sector(data[: self.sector_size], tweak)
            data = data[self.sector_size :]
            sector += 1
        return out

    def encrypt_sector(self, data, tweak):
        if len(data) % self.block_size:
            raise ValueError("Data is not aligned to block size!")
        out = b""
        tweak = self.K2.encrypt(uhx("%032X" % tweak))
        while data:
            out += sxor(tweak, self.K1.encrypt(sxor(data[:0x10], tweak)))
            _t = int(hx(tweak[::-1]), 16)
            _t <<= 1
            if _t & (1 << 128):
                _t ^= (1 << 128) | (0x87)
            tweak = uhx("%032X" % _t)[::-1]
            data = data[0x10:]
        return out

    def decrypt(self, data, sector=None):
        if sector is None:
            sector = self.sector
        if len(data) % self.block_size:
            raise ValueError("Data is not aligned to block size!")
        out = b""
        while data:
            tweak = self.get_tweak(sector)
            out += self.decrypt_sector(data[: self.sector_size], tweak)
            data = data[self.sector_size :]
            sector += 1
        return out

    def decrypt_sector(self, data, tweak):
        if len(data) % self.block_size:
            raise ValueError("Data is not aligned to block size!")
        out = b""
        tweak = self.K2.encrypt(uhx("%032X" % tweak))
        while data:
            a = self.K1.decrypt(sxor(data[:0x10], tweak))
            out += sxor(tweak, a)
            _t = int(hx(tweak[::-1]), 16)
            _t <<= 1
            if _t & (1 << 128):
                _t ^= (1 << 128) | (0x87)
            tweak = uhx("%032X" % _t)[::-1]
            data = data[0x10:]
        return out

    def get_tweak(self, sector=None):
        if sector is None:
            sector = self.sector
        tweak = 0
        for i in range(self.block_size):
            tweak |= (sector & 0xFF) << (i * 8)
            sector >>= 8
        return tweak

    def set_sector(self, sector):
        self.sector = sector


class AESXTSN:
    """Class for performing Nintendo AES XTS cipher operations"""

    def __init__(self, keys, sector_size=0x200, sector=0):
        if not (type(keys) is tuple and len(keys) == 2):
            raise TypeError("XTS mode requires a tuple of two keys.")
        self.K1 = AESECB(keys[0])
        self.K2 = AESECB(keys[1])
        self.keys = keys
        self.sector = sector
        self.sector_size = sector_size
        self.block_size = self.K1.block_size

    def encrypt(self, data, sector=None):
        if sector is None:
            sector = self.sector
        if len(data) % self.block_size:
            raise ValueError("Data is not aligned to block size!")
        out = b""
        while data:
            tweak = self.get_tweak(sector)
            out += self.encrypt_sector(data[: self.sector_size], tweak)
            data = data[self.sector_size :]
            sector += 1
        return out

    def encrypt_sector(self, data, tweak):
        if len(data) % self.block_size:
            raise ValueError("Data is not aligned to block size!")
        out = b""
        tweak = self.K2.encrypt(uhx("%032X" % tweak))
        while data:
            out += sxor(tweak, self.K1.encrypt_block_ecb(sxor(data[:0x10], tweak)))
            _t = int(hx(tweak[::-1]), 16)
            _t <<= 1
            if _t & (1 << 128):
                _t ^= (1 << 128) | (0x87)
            tweak = uhx("%032X" % _t)[::-1]
            data = data[0x10:]
        return out

    def decrypt(self, data, sector=None):
        if sector is None:
            sector = self.sector
        if len(data) % self.block_size:
            raise ValueError("Data is not aligned to block size!")
        out = b""
        while data:
            tweak = self.get_tweak(sector)
            out += self.decrypt_sector(data[: self.sector_size], tweak)
            data = data[self.sector_size :]
            sector += 1
        return out

    def decrypt_sector(self, data, tweak):
        if len(data) % self.block_size:
            raise ValueError("Data is not aligned to block size!")
        out = b""
        tweak = self.K2.encrypt(uhx("%032X" % tweak))
        while data:
            out += sxor(tweak, self.K1.decrypt_block_ecb(sxor(data[:0x10], tweak)))
            _t = int(hx(tweak[::-1]), 16)
            _t <<= 1
            if _t & (1 << 128):
                _t ^= (1 << 128) | (0x87)
            tweak = uhx("%032X" % _t)[::-1]
            data = data[0x10:]
        return out

    def get_tweak(self, sector=None):
        """Gets tweak for use in XEX."""
        if sector is None:
            sector = self.sector
        tweak = 0
        for i in range(self.block_size):
            tweak |= (sector & 0xFF) << (i * 8)
            sector >>= 8
        return tweak

    def set_sector(self, sector):
        self.sector = sector

    def set_sector_size(self, sector_size):
        self.sector_size = sector_size


class AESECB:
    """Class for performing AES ECB cipher operations."""

    # Constants for performing AES operations -- rcon table, S boxes.
    # fmt: off
    rcon_table = [
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
    ]
    sbox_enc = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    sbox_dec = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]

    mult_1_table = list(range(0x100))
    mult_2_table = [
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
        0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
        0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
        0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
        0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
        0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
        0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
        0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
        0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
        0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
        0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
        0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
        0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
        0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
        0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
        0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
    ]
    mult_3_table = [
        0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
        0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39, 0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
        0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
        0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
        0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9, 0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
        0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
        0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
        0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99, 0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
        0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
        0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
        0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2, 0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
        0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
        0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
        0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
        0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
        0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a
    ]
    mult_9_table = [
        0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
        0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7,
        0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
        0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc,
        0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01,
        0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
        0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a,
        0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa,
        0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
        0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b,
        0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0,
        0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
        0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed,
        0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d,
        0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
        0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46
    ]
    mult_B_table = [
        0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69,
        0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81, 0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9,
        0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
        0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4, 0xa9, 0xa2,
        0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7, 0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f,
        0x46, 0x4d, 0x50, 0x5b, 0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
        0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4,
        0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c, 0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54,
        0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
        0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e,
        0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd, 0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5,
        0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
        0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44, 0x75, 0x7e, 0x63, 0x68,
        0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80, 0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8,
        0x7a, 0x71, 0x6c, 0x67, 0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
        0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3
    ]
    mult_D_table = [
        0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b,
        0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3, 0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b,
        0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
        0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20,
        0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e, 0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26,
        0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
        0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d,
        0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25, 0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d,
        0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
        0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41,
        0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42, 0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a,
        0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
        0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc,
        0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44, 0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c,
        0x0c, 0x01, 0x16, 0x1b, 0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
        0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97
    ]
    mult_E_table = [
        0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a,
        0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca, 0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba,
        0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
        0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61,
        0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87, 0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7,
        0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
        0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c,
        0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc, 0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc,
        0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
        0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb,
        0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0, 0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0,
        0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
        0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6,
        0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26, 0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56,
        0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
        0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d
    ]

    mult_table = [
        None, mult_1_table, mult_2_table, mult_3_table,
        None, None,         None,         None,
        None, mult_9_table, None,         mult_B_table,
        None, mult_D_table, mult_E_table, None
    ]

    mix_mults = [
        [0x2, 0x3, 0x1, 0x1],
        [0x1, 0x2, 0x3, 0x1],
        [0x1, 0x1, 0x2, 0x3],
        [0x3, 0x1, 0x1, 0x2]
    ]
    unmix_mults = [
        [0xE, 0xB, 0xD, 0x9],
        [0x9, 0xE, 0xB, 0xD],
        [0xD, 0x9, 0xE, 0xB],
        [0xB, 0xD, 0x9, 0xE]
    ]
    # fmt: on

    def __init__(self, key):
        self.block_size, self.num_rounds = 0x10, 10  # 128-bit AES
        if len(key) != self.block_size:
            raise ValueError("Key must be of size %X!" % self.block_size)
        self.keys = [list(up(">IIII", key))]
        for i in range(1, self.num_rounds + 1):
            new_key = [self.key_schedule_core(self.keys[i - 1][3], i) ^ self.keys[i - 1][0]]
            for j in range(1, 4):
                new_key.append(self.keys[i - 1][j] ^ new_key[j - 1])
            self.keys.append(new_key)

    def encrypt(self, data):
        """Encrypts some data in ECB mode."""
        out = b""
        while data:
            out += self.encrypt_block_ecb(data[:0x10])
            data = data[0x10:]
        return out

    def decrypt(self, data):
        """Decrypts some data in EBC mode."""
        if len(data) % self.block_size:
            raise ValueError("Data is not aligned to block size!")
        out = b""
        while data:
            out += self.decrypt_block_ecb(data[:0x10])
            data = data[0x10:]
        return out

    def encrypt_block_ecb(self, block):
        words = list(up(">IIII", self.pad_block(block)))
        for i in range(len(words)):
            words[i] ^= self.keys[0][i]
        for rnd in range(1, self.num_rounds + 1):
            for i in range(len(words)):
                words[i] = self.send_through_sbox(words[i], self.sbox_enc)
            words = self.shift_columns(words)
            if rnd != self.num_rounds:
                words = self.mix_columns(words)
            for i in range(len(words)):
                words[i] ^= self.keys[rnd][i]
        return pk(">IIII", words[0], words[1], words[2], words[3])

    def decrypt_block_ecb(self, block):
        assert len(block) == self.block_size
        words = list(up(">IIII", block))
        for rnd in range(self.num_rounds, 0, -1):
            for i in range(len(words)):
                words[i] ^= self.keys[rnd][i]
            if rnd != self.num_rounds:
                words = self.unmix_columns(words)
            words = self.unshift_columns(words)
            for i in range(len(words)):
                words[i] = self.send_through_sbox(words[i], self.sbox_dec)
        for i in range(len(words)):
            words[i] ^= self.keys[0][i]
        return pk(">IIII", words[0], words[1], words[2], words[3])

    # Helper functions
    def rotate_op(self, word):
        """Rotate operation"""
        return ((word & 0xFFFFFF) << 8) | ((word & 0xFF000000) >> 24)

    def rcon_op(self, i):
        """Rcon operation"""
        assert 0 <= i and i < len(self.rcon_table)
        return self.rcon_table[i]

    def send_through_sbox(self, word, sbox=sbox_enc):
        """Sends a 32-bit word through an sbox."""
        return (
            (sbox[((word & (0xFF << 0x18)) >> 0x18)] << 0x18)
            | (sbox[((word & (0xFF << 0x10)) >> 0x10)] << 0x10)
            | (sbox[((word & (0xFF << 0x08)) >> 0x08)] << 0x08)
            | (sbox[((word & (0xFF << 0x00)) >> 0x00)] << 0x00)
        )

    def shift_columns(self, words):
        """Performs column shifting for AES."""
        new_words = []
        new_words.append(
            (words[0] & 0xFF000000)
            | (words[1] & 0xFF0000)
            | (words[2] & 0xFF00)
            | (words[3] & 0xFF)
        )
        new_words.append(
            (words[1] & 0xFF000000)
            | (words[2] & 0xFF0000)
            | (words[3] & 0xFF00)
            | (words[0] & 0xFF)
        )
        new_words.append(
            (words[2] & 0xFF000000)
            | (words[3] & 0xFF0000)
            | (words[0] & 0xFF00)
            | (words[1] & 0xFF)
        )
        new_words.append(
            (words[3] & 0xFF000000)
            | (words[0] & 0xFF0000)
            | (words[1] & 0xFF00)
            | (words[2] & 0xFF)
        )
        return new_words

    def unshift_columns(self, words):
        """Performs column unshifting for AES."""
        new_words = []
        new_words.append(
            (words[0] & 0xFF000000)
            | (words[3] & 0xFF0000)
            | (words[2] & 0xFF00)
            | (words[1] & 0xFF)
        )
        new_words.append(
            (words[1] & 0xFF000000)
            | (words[0] & 0xFF0000)
            | (words[3] & 0xFF00)
            | (words[2] & 0xFF)
        )
        new_words.append(
            (words[2] & 0xFF000000)
            | (words[1] & 0xFF0000)
            | (words[0] & 0xFF00)
            | (words[3] & 0xFF)
        )
        new_words.append(
            (words[3] & 0xFF000000)
            | (words[2] & 0xFF0000)
            | (words[1] & 0xFF00)
            | (words[0] & 0xFF)
        )
        return new_words

    def mix_columns(self, words):
        """Performs column mixing for 128-bit AES"""
        return [
            self.mix_column(words[0], self.mix_mults),
            self.mix_column(words[1], self.mix_mults),
            self.mix_column(words[2], self.mix_mults),
            self.mix_column(words[3], self.mix_mults),
        ]

    def unmix_columns(self, words):
        """Performs column unmixing for 128-bit AES"""
        return [
            self.mix_column(words[0], self.unmix_mults),
            self.mix_column(words[1], self.unmix_mults),
            self.mix_column(words[2], self.unmix_mults),
            self.mix_column(words[3], self.unmix_mults),
        ]

    def mix_column(self, word, mults):
        """Performs column mixing on a single column"""
        return (
            ((self.mix(word, mults[0])) << 0x18)
            | ((self.mix(word, mults[1])) << 0x10)
            | ((self.mix(word, mults[2])) << 0x08)
            | ((self.mix(word, mults[3])) << 0x00)
        )

    def mix(self, word, mix):
        """Mixes a word according to a given multiplier."""
        return (
            (self.mult_table[mix[0]][((word >> 0x18) & 0xFF)])
            ^ (self.mult_table[mix[1]][((word >> 0x10) & 0xFF)])
            ^ (self.mult_table[mix[2]][((word >> 0x08) & 0xFF)])
            ^ (self.mult_table[mix[3]][((word >> 0x00) & 0xFF)]) & 0xFF
        )

    def key_schedule_core(self, word, i, sbox=sbox_enc):
        """Performs core key scheduling operation."""
        return self.send_through_sbox(self.rotate_op(word), sbox) ^ (self.rcon_op(i) << 0x18)

    def pad_block(self, block):
        """Pads a block using CMS padding."""
        assert len(block) <= self.block_size
        num_pad = self.block_size - len(block)
        right = (chr(num_pad) * num_pad).encode()
        return block + right
