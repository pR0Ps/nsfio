#!/usr/bin/env python

import io
from pathlib import Path
from typing import Union
import logging
from nsfio.keys import ConsoleKeys
from nsfio import aes128
from dataclasses import dataclass

from binascii import hexlify, unhexlify

__log__ = logging.getLogger(__name__)


def try_enum(enum, val):
    try:
        return enum(val)
    except ValueError:
        __log__.warning("Unknown %s value of '%s'", enum, val)
        return val

########################################
# Types
from enum import IntEnum

MEDIA_UNITS = 0x200
SECTOR_SIZE = 0x200

class ContentType(IntEnum):
    PROGRAM = 0x0
    META = 0x1
    CONTROL = 0x2
    MANUAL = 0x3  # HtmlDocument, LegalInformation
    DATA = 0x4  # DeltaFragment
    PUBLICDATA = 0x5


class FsType(IntEnum):
    NONE = 0x0
    PFS0 = 0x2
    ROMFS = 0x3


class EncryptionType(IntEnum):
    AUTO = 0
    NONE = 1
    AES_XTS = 2
    AES_CTR = 3
    AES_CTR_EX = 4


class TicketSignatureType(IntEnum):
    RSA_4096_SHA1 = 0x010000
    RSA_2048_SHA1 = 0x010001
    ECDSA_SHA1 = 0x010002
    RSA_4096_SHA256 = 0x010003
    RSA_2048_SHA256 = 0x010004
    ECDSA_SHA256 = 0x010005

#########################################

@dataclass
class EncryptionScheme:
    method: EncryptionType
    key: bytes
    iv: None

def is_po2(num):
    return num > 0 and (num & (num-1) == 0)


class EncryptionBuffer(io.BufferedIOBase):
    """Sits between the raw io interface and applies encryption if required"""

    # TODO: optimize by allowing the buffer to be bigger
    #       (right now it's just a single sector)

    def __init__(self, raw: io.BufferedIOBase, sector_size):
        if not is_po2(sector_size):
            raise ValueError("Sector size must be a power of 2")

        self._raw = raw
        self._sector_size = sector_size

        rawpos = self._raw.tell()

        self._buff = None # Data contained in the buffer
        self._buf_offset = None # The offset of the buffer (aligned to sector size)
        self._offset = None # The current position within the buffer
        self._dirty = False # the buffer was modified and needs to be written back

        # This class is just a passthrough until encryption is enabled
        self.encryption = False

    def sector_offset(self, offset):
        """Offset aligned to the sector_size"""
        return offset & ~(self._sector_size-1)

    def relative_offset(self, offset):
        """Position relative to the current sector offset"""
        return offset & ~-self._sector_size

    def _sync(self):
        """Sync any written data back to the raw io"""
        if self._dirty:
            p = self.tell()
            self._raw.seek(0) # TODO: seek to sector start, not 0
            self._raw.write("") # TODO: encrypt bytes
            self.seek(p)

    def flush(self):
        if self.encryption:
            self._sync()
        self._raw.flush()

    def close(self):
        self.flush()
        self._raw.close()

    def tell(self):
        return self._raw.tell()

    def seek(self, pos, whence=io.SEEK_SET):
        if not self.encryption:
            return self._raw.seek(pos, whence)
        # TODO

    def read(self, size=None):
        if not self.encryption:
            return self._raw.read(size)

        raise NotImplementedError("Reading encrypted data is not implemented")

    def write(self, b: bytes):
        if not self.encryption:
            return self._raw.write(b)
        self._dirty = True
        p = self.tell()
        # TODO: store write in buffer
        #       (break up into sector_size'd chunks and write them individually)
        raise NotImplementedError("Writing encrypted data is not implemented")


class BaseIO:
    """Base class of all IO-related classes

    Creates BaseIO objects that act as views into the underlying data.
    """

    # Subclasses that are staticly sized can define this instead of passing size to init
    static_size = None

    # TODO: Handle unbounded size for objects (writing a filesystem?)

    # TODO: Handle crypto transparently (decrypt on read, encrypt on write)
    # write a "middleware" that decrypts/encrypts the requested data (block-based)

    def __init__(self, size=None, *args, **kwargs):
        """Store how to parse the file"""
        if size is None and self.static_size:
            size = self.static_size
        self._io = None
        self._offset = 0
        self._size = size
        self._children = []

    # Load data and parse
    def from_io(self, data: io.BufferedIOBase):
        self._io = data
        if self.size is None:
            self._io.seek(0, io.SEEK_END)
            self._size = self.tell()
        self._io.seek(0)
        self.parse()
        self.seek(0, io.SEEK_END)
        return self

    def from_file(self, path: Union[str, Path]):
        self.from_io(open(path, 'rb'))
        return self

    def from_bytes(self, data: Union[bytes, bytearray]):
        self.from_io(io.BytesIO(data))
        return self

    @property
    def size(self):
        return self._size

    # Define how to parse/serialize
    def parse(self):
        """Parse information out of the loaded stream"""
        __log__.error("Parsing not implemented for {} objects".format(self.__class__.__qualname__))

    def serialize(self, fp):
        """Using the stored data, serialize a bytestream and write it to fp"""
        __log__.error("Serialization not implemented for {} objects".format(self.__class__.__qualname__))

    def parse_object(self, instance, offset=None):
        """Parse an object from the bytestream"""
        if self._io is None:
            raise ValueError("No data loaded")

        if instance.size is None:
            raise ValueError("The size of the object to parse must be known")

        if offset is None:
            offset = self.tell()

        # Transfer attributes to the new object
        instance.parent = self
        instance._io = self._io
        instance._offset = self._offset + offset

        self._children.append(instance)

        instance.seek(0)
        instance.parse()
        print(instance)
        instance.seek(0, io.SEEK_END)

        return instance

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __len__(self):
        return self.size

    def __repr__(self):
        return "<{} size={:#x}>".format(self.__class__.__qualname__, self.size)

    def __iter__(self):
        return iter(self._children)

    def __del__(self):
        self.close()

    def _check_offset(self, target):
        # TODO: Test overhead of checking bounds on every read/write/seek
        if not (self._offset <= target <= self._offset + self.size):
            raise IOError("Offset {:#x} is out of range (0 - {:#x} @ {:#x})".format(target - self._offset, self.size, self._offset))

    # Methods to interact with the underlying io object
    def read(self, size=None):
        if size is None:
            size = self.size - self.tell()
        else:
            self._check_offset(self._io.tell() + size)

        return self._io.read(size)

    def read_uint(self, size):
        return int.from_bytes(self.read(size), byteorder="little", signed=False)

    def read_uint8(self):
        return self.read_uint(1)

    def read_uint16(self):
        return self.read_uint(2)

    def read_uint32(self):
        return self.read_uint(4)

    def read_uint64(self):
        return self.read_uint(8)

    def read_uint128(self):
        return self.read_uint(16)

    def read_magic(self, expected):
        self.magic = self.read(len(expected))
        if self.magic != expected:
            raise ValueError("Invalid {}: magic at {:#x} is {} (expected {})".format(
                self.__class__.__qualname__,
                self.tell(),
                self.magic,
                expected
            ))

    def peek(self, size):
        """Peek at the next size bytes without advancing the position"""
        if not size:
            raise ValueError("Peek requires a size")
        self.read(size)
        self._io.seek(-size, io.SEEK_CURR)

    def write(self, b: bytes):
        self._check_offset(self._io.tell() + len(b))
        self._io.write(b)

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            target = self._offset + offset
        elif whence == io.SEEK_CUR:
            target = self._io.tell() + offset
        elif whence == io.SEEK_END:
            target = self._offset + self._size + offset
        else:
            raise ValueError("Invalid whence ({}, should be 0, 1 or 2)".format(whence))

        self._check_offset(target)
        return self._io.seek(target, io.SEEK_SET)

    def skip(self, offset):
        """Convenience function for seeking forwards"""
        self.seek(offset, io.SEEK_CUR)

    def tell(self):
        return self._io.tell() - self._offset

    def close(self):
        if self._io:
            self._io.close()

    @property
    def closed(self):
        if self._io:
            self._io.closed

    def flush(self):
        if self._io:
            self._io.flush()


# TODO: Find a better way to link headers+data
@dataclass
class File:
    header: BaseIO
    data: BaseIO = None


class Filesystem(BaseIO):
    """Contains other objects"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.files = []

    def __iter__(self):
        return iter(self.files)

    @staticmethod
    def cls_from_fsheader(hdr: bytes):
        fs_type = hdr[0x3]

        if fs_type == FsType.PFS0:
            return Pfs0
        elif fs_type == FsType.ROMFS:
            return RomFS

        return Filesystem


class Hfs0FileEntry(BaseIO):

    static_size = 0x40

    def parse(self):
        self.seek(0)
        self.file_offset = self.read_uint64()
        self.file_size = self.read_uint64()
        self.name_offset = self.read_uint32()
        self.hashed_data_size = self.read_uint32()
        self.skip(0x2) # zero/reserved
        self.sha256 = self.read(0x20)

        # null-terminated strings
        self.name = self.parent.string_table[self.name_offset:].split(b"\0", 1)[0].decode("utf-8")


class Hfs0(Filesystem):

    def parse(self):
        self.read_magic(b"HFS0")
        self.num_files = self.read_uint32()
        self.string_table_size = self.read_uint32()
        self.skip(0x4) # padding/reserved

        # Skip forward to get the string table before parsing the filenames
        pos = self.tell()
        self.skip(self.num_files * Hfs0FileEntry.static_size)
        self.string_table = self.read(self.string_table_size)

        # Note the end of the string table (file data is relative to here)
        data_start = self.tell()
        self.seek(pos)

        for i in range(self.num_files):
            f = self.parse_object(Hfs0FileEntry())
            self.files.append(File(f))

        for f in self:
            hdr = f.header
            cls = class_from_name(hdr.name)
            f.data = self.parse_object(cls(size=hdr.file_size), offset=data_start + hdr.file_offset)


class Pfs0(Filesystem):
    pass


class Nsp(Pfs0):
    """A Pfs0 with some extra restrictions/functionality"""
    pass


class RomFS(Filesystem):
    pass


class GameCardCert(BaseIO):

    static_size=0x70

    def parse(self):
        self.cert_raw = self.read()


class GameCardInfo(BaseIO):

    static_size=0x70

    def parse(self):
        self.raw_enc_data = self.read()


class Xci(BaseIO):

    def parse(self):
        self.signature = self.read(0x100)
        self.read_magic(b"HEAD")
        self.secure_offset = self.read_uint32()
        self.backup_offset = self.read_uint32()
        self.title_kek_index = self.read_uint8()
        self.gamecard_size = self.read_uint8() # enum
        self.gamecard_header_version = self.read_uint8()
        self.gamecard_flags = self.read_uint8()
        self.package_id = self.read_uint64()
        self.valid_data_end_address = self.read_uint64() # in MEDIA_UNITS
        self.gamecard_info_iv = self.read(0x10)

        self.hfs0_offset = self.read_uint64()
        self.hfs0_header_size = self.read_uint64()
        self.hfs0_header_hash = self.read(0x20)
        self.hfs0_initial_data_hash = self.read(0x20)
        self.security_mode = self.read_uint32() # enum (0x01 = T1, 0x02 = T2)
        self.t1_key_index = self.read_uint32()
        self.t2_key_index = self.read_uint32()
        self.normal_area_end_address = self.read_uint32() # in MEDIA_UNITS

        self.gamecard_info = self.parse_object(GameCardInfo())
        self.gamecard_cert = self.parse_object(GameCardCert(), offset=0x7000)

        self.hfs0 = self.parse_object(
            Hfs0(
                header_size=self.hfs0_header_size,
                header_hash=self.hfs0_header_hash,
                initial_data_hash=self.hfs0_initial_data_hash,
                size=self.size - self.hfs0_offset # EOF
            ),
            offset=self.hfs0_offset
        )


class KeyGeneration(IntEnum):
    v1_0_0 = 0x00
    NONE = 0x01
    v3_0_0 = 0x02
    v3_0_1 = 0x03
    v4_0_0 = 0x04
    v5_0_0 = 0x05
    v6_0_0 = 0x06
    v6_2_0 = 0x07
    v7_0_0 = 0x08
    v8_1_0 = 0x09
    v9_0_0 = 0x0A
    v9_1_0 = 0x0B
    INVALID = 0xFF


class NcaFsEntry(BaseIO):

    static_size = 0x10

    def parse(self):
        self.start_offset = self.read_uint32()
        self.end_offset = self.read_uint32()
        self.skip(0x8) # reserved


class NcaHeader(BaseIO):

    static_size = 0x400

    # TODO: This won't work with immutable buffers - implement transparent decryption
    def decrypt(self):
        console_keys = ConsoleKeys(Path.home() / ".switch" / "prod.keys")
        crypto = aes128.AESXTS(console_keys['header_key'])
        encrypted = self.read()

        #from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        #from cryptography.hazmat.backends import default_backend
        #cipher = Cipher(
        #    algorithms.AES(console_keys['header_key']),
        #    modes.XTS(),
        #    default_backend()
        #)
        #decryptor = cipher.decryptor()
        #out = decryptor.update(encrypted) + decryptor.finalize()

        decrypted = crypto.decrypt(encrypted)

        #if not out == decrypted:
        #    print(out)
        #    print(decrypted)
        #    assert False

        self.seek(0)
        self.write(decrypted)
        self.seek(0)

    # TODO: unused?
    def has_title_rights(self):
        return self._rights_id != b"0"*32

    def parse(self):
        self.decrypt() # TODO: do this in the BaseIO?

        self.signature1 = self.read(0x100)
        self.signature2 = self.read(0x100)
        self.read_magic(b"NCA3") # TODO: support old versions
        self.distribution_type = self.read_uint8() # enum 0x00 = System NCA, 0x01 = Gamecard NCA
        self.content_type = try_enum(ContentType, self.read_uint8())
        self.key_generation_old = try_enum(KeyGeneration, self.read_uint8())
        self.key_area_encryption_key_index = self.read_uint8() # enum KeyAreaEncryptionKeyIndex (0x00 = Application, 0x01 = Ocean, 0x02 = System)
        self.content_size = self.read_uint64()
        self.program_id = hexlify(self.read(8)[::-1]).decode("utf-8").upper()
        self.content_index = self.read_uint32()
        self.sdk_addon_version = self.read_uint32()
        self.key_generation_new = try_enum(KeyGeneration, self.read_uint8())
        self.header1_sig_key_generation = self.read_uint8()
        self.skip(0xE) # reserved
        self.rights_id = hexlify(self.read(0x10)).upper()

        self.sections = [self.parse_object(NcaFsEntry()) for _ in range(4)]
        self.header_sha256_hashes = [self.read(0x20) for x in self.sections]


        console_keys = ConsoleKeys(Path.home() / ".switch" / "prod.keys")
        key_generation = try_enum(
            KeyGeneration, max(self.key_generation_old, self.key_generation_new)
        )

        encrypted_key_block = self.read(0x40)
        key_block = console_keys.unwrap_title_key(encrypted_key_block, console_keys.master_key_index(key_generation))
        self.keys = [
            key_block[i * 0x10: (i+1) * 0x10]
            for i in range(4)
        ]

class NcaFsHeader(BaseIO):
    static_size = 0x200

    def parse(self):
        self.version = self.read_uint16()
        self.fs_type = try_enum(FsType, self.read_uint8())
        self.hash_type = self.read_uint8() # enum HashType (0 = Auto, 2 = HierarchicalSha256, 3 = HierarchicalIntegrity)
        self.encryption_type = try_enum(EncryptionType, self.read_uint8())
        self.skip(0x1) # padding
        self.hash_info = self.read(0xF8) # TODO: break out into class
        self.patch_info = self.read(0x40) # TODO: break out into class
        self.generation = self.read(0x4)
        self.secure_value = self.read(0x4)
        self.sparce_info = self.read(0x30)
        self.skip(0x88) # reserved

class Nca(BaseIO):

    def parse(self):
        header = self.parse_object(NcaHeader())
        # TODO: decrypt before continuing
        #for s in header.sections:
        #    self.parse_object(NcaFsHeader())

class Cnmt(BaseIO):
    pass


class Ticket(BaseIO):
    pass


class Nacp(BaseIO):
    pass


class Struct:
    """A small unit of data"""


class GamecardInfo(Struct):
    pass


class GamecardCertificate(Struct):
    pass


class HierarchicalIntegrityHash(BaseIO):
    """Ivfc"""

    pass


class PatchInfo(BaseIO):
    """
    Stores the BKTR sections
    """

    pass


def class_from_name(name):
    name = name.lower()
    if name.endswith(".xci"):
        return Xci
    elif name.endswith(".nsp"):
        return Nsp
    elif name.endswith(".nca"):
        return Nca
    elif name.endswith(".nacp"):
        return Nacp
    elif name.endswith(".tik"):
        return Ticket
    elif name.endswith(".cnmt"):
        return Cnmt
    elif name in set(["normal", "logo", "update", "secure"]):
        return Hfs0
    else:
        return BaseIO
