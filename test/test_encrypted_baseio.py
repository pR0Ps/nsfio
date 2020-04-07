#!/usr/bin/env python

import io

from nsfio import UnbufferedBaseIO, BaseIO, EncryptionScheme, EncryptionType
from nsfio import aes128

import pytest


def assert_range(func):

    def wrapper(self, *args, **kwargs):
        assert self.tell() == 0

        func(self, *args, **kwargs)

        assert self.tell() == self.size

        # Reading past the end of the file is an error
        with pytest.raises(IOError):
            if func.__name__ == "parse":
                self.read(1)
            elif func.__name__ == "serialize":
                self.write(bytes([1]))
            else:
                assert False, "Wrong function decorated"

    return wrapper


class EncryptionTest(BaseIO):
    """Dumb class that needs to be serialized before parsing it..."""

    static_size=128

    def __init__(self, *args, **kwargs):
        # Read as little as possible to test the load/flush behaviour
        super().__init__(*args, min_buffer_size=1, **kwargs)

    @assert_range
    def parse(self):
        # Only reading a single byte still pulls an entire sector in
        assert list(self.read(1)) == [self.tell() - 1]
        assert len(self._buff) == self._alignment

        # Move to next sector - 1
        self.skip(self._alignment - 1)

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

    @assert_range
    def serialize(self):
        # Write < sector size
        for x in range(self._alignment - 1):
            self.write(bytes([x]))

        # Write = sector size, not aligned
        self.write(bytes(range(self.tell(), self.tell() + self._alignment)))

        self.write(bytes([self.tell()]))

        # Write = sector size, aligned
        self.write(bytes(range(self.tell(), self.tell() + self._alignment)))

        # Write > sector size
        self.write(bytes(range(self.tell(), self.size)))


def test_buffering_encrypting_data():

    initial = b"\x00" * EncryptionTest.static_size
    to_write = bytes(range(EncryptionTest.static_size))

    enc = EncryptionScheme(
        method=EncryptionType.AES_XTS,
        key=b'\xaa' * 0x20,
        sector_size=0x10
    )

    encrypted_write = aes128.AESXTS(keys=enc.key, sector_size=enc.sector_size).encrypt(to_write)

    data = io.BytesIO(initial)
    with EncryptionTest(encryption=enc).to_io(data) as write_obj:
        assert data.getvalue() == encrypted_write

        # call parse to test decryption
        with EncryptionTest(encryption=enc).from_io(data) as read_obj:
            assert read_obj.all_data == to_write

def test_initial_sector_offset():
    initial = b"\x00" * EncryptionTest.static_size
    to_write = bytes(range(EncryptionTest.static_size))

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
    with EncryptionTest(encryption=enc).to_io(data) as write_obj:
        ### TODO: sector size initial offset
        assert data.getvalue() == encrypted_write

        # call parse to test decryption
        with EncryptionTest(encryption=enc).from_io(data) as read_obj:
            assert read_obj.all_data == to_write

def test_buffering_unencrypted():
    initial = b"\x00" * EncryptionTest.static_size
    to_write = bytes(range(EncryptionTest.static_size))

    enc = EncryptionScheme(
        method=EncryptionType.NONE
    )

    data = io.BytesIO(initial)
    # no encryptuon specified
    with EncryptionTest().to_io(data) as write_obj:
        assert data.getvalue() == to_write

        # call parse to test decryption
        # specify encryption type of NONE
        with EncryptionTest(encryption=enc).from_io(data) as read_obj:
            assert read_obj.all_data == to_write


def test_unbuffered_nested_classes():

    class BIO(UnbufferedBaseIO):

        static_size=128

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.all = []

        @assert_range
        def parse(self):
            for b in bytes(range(BIO.static_size)):
                t = self.read(1)
                assert len(t) == 1
                assert t[0] == b
                self.all.append(t)

        @assert_range
        def serialize(self):
            for x in self.all:
                self.write(x)

    class BIO2(UnbufferedBaseIO):

        static_size=BIO.static_size * 2

        @assert_range
        def parse(self):
            self.o1 = self.read_object(BIO())
            self.o2 = self.read_object(BIO())

        @assert_range
        def serialize(self):
            self.write_object(self.o1)
            self.write_object(self.o2)

    class BIO4(UnbufferedBaseIO):

        static_size=BIO2.static_size * 2

        @assert_range
        def parse(self):
            self.o1 = self.read_object(BIO2())
            self.o2 = self.read_object(BIO2())

        @assert_range
        def serialize(self):
            self.write_object(self.o1)
            self.write_object(self.o2)

    initial = bytes(range(BIO4.static_size // 4)) * 4

    data = io.BytesIO(initial)
    # test parsing
    with BIO4().from_io(data) as read_obj:

        # test serialization
        output = io.BytesIO(bytes(BIO4.static_size))
        with read_obj.to_io(output) as write_obj:
            assert output.getvalue() == initial


def test_buffered_nested_classes():

    class BIO(BaseIO):

        static_size=128

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.all = []

        @assert_range
        def parse(self):
            for b in bytes(range(BIO.static_size)):
                t = self.read(1)
                assert len(t) == 1
                assert t[0] == b
                self.all.append(t)

        @assert_range
        def serialize(self):
            for x in self.all:
                self.write(x)

    class BIO2(BaseIO):

        static_size=BIO.static_size * 2

        @assert_range
        def parse(self):
            self.o1 = self.read_object(BIO())
            self.o2 = self.read_object(BIO())

        @assert_range
        def serialize(self):
            self.write_object(self.o1)
            self.write_object(self.o2)

    class BIO4(BaseIO):

        static_size=BIO2.static_size * 2

        @assert_range
        def parse(self):
            self.o1 = self.read_object(BIO2())
            self.o2 = self.read_object(BIO2())

        @assert_range
        def serialize(self):
            self.write_object(self.o1)
            self.write_object(self.o2)

    initial = bytes(range(BIO4.static_size // 4)) * 4

    data = io.BytesIO(initial)
    # test parsing
    with BIO4().from_io(data) as read_obj:

        # test serialization
        output = io.BytesIO(bytes(BIO4.static_size))
        with read_obj.to_io(output) as write_obj:
            assert output.getvalue() == initial


def test_load_buffer():

    def assert_buff(offset, size):
        assert obj._buff_offset == offset
        assert len(obj._buff) == size

    obj = BaseIO(size=10)
    obj._io = io.BytesIO(bytes(range(10)))
    obj.min_buffer_size=5
    obj._alignment = 1

    # Initial load
    obj._load_buffer(3, 1)
    assert_buff(3, 5)

    # shift left
    obj._load_buffer(0, 5)
    assert_buff(0, 5)

    # shift right
    obj._load_buffer(3, 5)
    assert_buff(3, 5)

    # left and bigger
    obj._load_buffer(1, 8)
    assert_buff(1, 8)

    # right and smaller
    obj._load_buffer(9, 1)
    assert_buff(5, 5)

    # left and smaller
    obj._load_buffer(1, 1)
    assert_buff(1, 5)

    # right and bigger
    obj._load_buffer(2, 8)
    assert_buff(2, 8)

    # sof
    obj._load_buffer(0, 1)
    assert_buff(0, 5)

    # eof
    obj._load_buffer(10, 0)
    assert_buff(5, 5)

    # sof
    obj._load_buffer(0, 1)
    assert_buff(0, 5)

    # eof
    obj._load_buffer(9, 1)
    assert_buff(5, 5)


def test_serialize_to_empty_stream():
    """Test that objects should be able to be serialized to an"""

    class SimpleIO(UnbufferedBaseIO):

        static_size = 128

        def __init__(self, *args, **kwargs):
            # Disable loading extra data into buffer
            super().__init__(*args, min_buffer_size=1, **kwargs)

        def parse(self):
            self.a = self.read(1)
            self.b = self.read(100)
            self.c = self.read()

        def serialize(self):
            self.write(self.a)
            self.write(self.b)
            self.write(self.c)

    class SimpleBufferedIO(BaseIO):

        static_size = 128

        def __init__(self, *args, **kwargs):
            # Disable loading extra data into buffer
            super().__init__(*args, min_buffer_size=1, **kwargs)

            # Make sure the IO is not aligned
            self._alignment = 16

        def parse(self):
            self.a = self.read(1)
            self.b = self.read(100)
            self.c = self.read()

        def serialize(self):
            self.write(self.a)
            self.write(self.b)
            self.write(self.c)

    class SimpleEncryptedIO(BaseIO):

        static_size = 128

        def __init__(self, *args, **kwargs):
            enc = EncryptionScheme(
                method=EncryptionType.AES_XTS,
                key=b'\xaa' * 0x20,
                sector_size=0x10, # Make sure the I/O is not aligned to this
            )
            # Disable loading extra data into buffer
            super().__init__(*args, min_buffer_size=1, encryption=enc, **kwargs)

        def parse(self):
            self.a = self.read(1)
            self.b = self.read(100)
            self.c = self.read()

        def serialize(self):
            self.seek(-len(self.c), io.SEEK_END)
            self.write(self.c)
            self.seek(0)
            self.write(self.a)
            self.write(self.b)

    data = bytes(range(SimpleIO.static_size))
    with SimpleIO().from_bytes(data) as read_obj:
        out = io.BytesIO()
        with read_obj.to_io(out):
            assert out.getvalue() == data

    with SimpleBufferedIO().from_bytes(data) as read_obj:
        out = io.BytesIO()
        with read_obj.to_io(out):
            assert out.getvalue() == data

    with SimpleEncryptedIO().from_bytes(data) as read_obj:
        out = io.BytesIO()
        with read_obj.to_io(out):
            assert out.getvalue() == data


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
