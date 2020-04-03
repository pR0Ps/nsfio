#!/usr/bin/env python

from nsfio import EncryptedBaseIO, EncryptionScheme, EncryptionType
from nsfio import aes128
import io

class EBIO(EncryptedBaseIO):

    static_size=128

    def parse(self):
        # Only reading a single byte still pulls an entire sector in
        assert list(self.read(1)) == [self.tell() - 1]
        assert len(self._buff) == self.alignment

        # Move to next sector - 1
        self.skip(self.alignment - 1)

        # test crossing sector boundry by reading
        o = self._buff_offset
        assert list(self.read(1)) == [self.tell() - 1]
        assert o != self._buff_offset

        assert list(self.read(10)) == list(range(self.tell()-10, self.tell()))

        # Test reading multiple sectors
        left = self.size - self.tell()
        rest = self.read()
        assert len(rest) == left
        assert list(rest) == list(range(self.tell()-left, self.tell()))

        self.seek(0)
        self.all_data = self.read()

    def serialize(self):
        # Write < sector size
        for x in range(self.alignment - 1):
            self.write(bytes([x]))

        # Write = sector size, not aligned
        self.write(bytes(range(self.tell(), self.tell() + self.alignment)))

        self.write(bytes([self.tell()]))

        # Write = sector size, aligned
        self.write(bytes(range(self.tell(), self.tell() + self.alignment)))

        # Write > sector size
        self.write(bytes(range(self.tell(), self.size)))

        assert self.tell() == self.size


def make_cls(encryption):
    cls = EBIO(encryption=encryption)

    # Read as little as possible so we can test the load/flush behaviour
    cls.min_buffer_size = 1
    return cls

def test_buffering_encrypting_data():

    initial = b"\x00" * EBIO.static_size
    to_write = bytes(range(EBIO.static_size))

    enc = EncryptionScheme(
        method=EncryptionType.AES_XTS,
        key=b'\xaa' * 0x20,
        sector_size=0x10
    )

    encrypted_write = aes128.AESXTS(keys=enc.key, sector_size=enc.sector_size).encrypt(to_write)

    data = io.BytesIO(initial)
    with make_cls(enc).to_io(data) as write_obj:
        assert data.getvalue() == encrypted_write

        # call parse to test decryption
        with make_cls(enc).from_io(data) as read_obj:
            assert read_obj.all_data == to_write

def test_initial_sector_offset():
    initial = b"\x00" * EBIO.static_size
    to_write = bytes(range(EBIO.static_size))

    enc = EncryptionScheme(
        method=EncryptionType.AES_XTS,
        key=b'\xaa' * 0x20,
        sector_size=0x10,
        iv=3,
    )

    encrypted_write = aes128.AESXTS(
        keys=enc.key, initial_sector=enc.iv, sector_size=enc.sector_size
    ).encrypt(to_write)

    data = io.BytesIO(initial)
    with make_cls(enc).to_io(data) as write_obj:
        ### TODO: sector size initial offset
        assert data.getvalue() == encrypted_write

        # call parse to test decryption
        with make_cls(enc).from_io(data) as read_obj:
            assert read_obj.all_data == to_write


if __name__ == "__main__":
    print("Running perf tests...")
    from timeit import timeit, repeat

    print("Setting up a 1MB buffer...", end="", flush=True)
    size = 1024 * 1024
    buff = bytes([b % 256 for b in range(size)])
    print("Done!")

    # XTS
    crypt = aes128.AESXTS(keys=bytes(range(32)))
    print("Encrypting {}MB using XTS (pure Python)....: ".format(len(buff) // 1024**2), end="", flush=True)
    print(timeit("crypt.encrypt(buff)", "crypt.seek(0)", number=1, globals=locals()))
    print("Decrypting {}MB using XTS (pure Python)....: ".format(len(buff) // 1024**2), end="", flush=True)
    print(timeit("crypt.decrypt(buff)", "crypt.seek(0)", number=1, globals=locals()))

    # CTR
    crypt = aes128.AESCTR(key=bytes(range(16)), nonce=bytes(range(16)))
    print("Encrypting {}MB using CTR (C library)...: ".format(len(buff * 1024) // 1024**2), end="", flush=True)
    print(timeit("crypt.encrypt(buff)", "crypt.seek(0)", number=1024, globals=locals()))
