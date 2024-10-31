#!/usr/bin/env python

import io
from pathlib import Path
from typing import Union
import logging
from nsfio.keys import ConsoleKeys
from nsfio import aes128
from dataclasses import dataclass

from binascii import hexlify


__log__ = logging.getLogger(__name__)


# Add level for debugging low-level IO
def _add_log_level(level, name):
    name = name.upper()
    setattr(logging, name, level)
    setattr(logging.getLoggerClass(), name.lower(), lambda s, *a, **k: s.log(getattr(logging, name), *a, **k))
    logging.addLevelName(level, name)

_add_log_level(5, "IOTRACE")


########################################
# Utils

def is_power_of_2(num: int):
    return num > 0 and (num & (num-1) == 0)


SIZE_SUFFIXES = ('B', 'KiB', 'MiB', 'GiB', 'TiB')

def display_bytes(size):
    if size is None:
        return "??"
    exp = min(
        (int.bit_length(abs(size)) - 1) // 10,
        len(SIZE_SUFFIXES) - 1
    ) if size != 0 else 0
    return '{:.4g} {}'.format(size / (1 << (exp * 10)), SIZE_SUFFIXES[exp])


########################################
# Types
from enum import IntEnum

MEDIA_UNITS = 0x200
XTS_SECTOR_SIZE = 0x200
BUFFER_SIZE = 0x1000 # 4KB

class NcaContentType(IntEnum):
    PROGRAM = 0x0
    META = 0x1
    CONTROL = 0x2
    MANUAL = 0x3  # HtmlDocument, LegalInformation
    DATA = 0x4  # DeltaFragment
    PUBLICDATA = 0x5

class CnmtContentType(IntEnum):
    META = 0x0
    PROGRAM = 0x1
    DATA = 0x2
    CONTROL = 0x3
    HTML_DOCUMENT = 0x4
    LEGAL_INFO = 0x5
    DELTA_FRAGMENT = 0x6

class ContentMetaType(IntEnum):
    UNKNOWN = 0x00
    SYSTEM_PROGRAM = 0x01
    SYSTEM_DATA = 0x02
    SYSTEM_UPDATE = 0x03
    BOOT_IMAGE_PACKAGE = 0x04
    BOOT_IMAGE_PACKAGE_SAFE = 0x05
    APPLICATION = 0x80
    PATCH = 0x81
    ADDON_CONTENT = 0x82
    DELTA = 0x83

class FsType(IntEnum):
    ROMFS = 0x0
    PFS0 = 0x1

class HashType(IntEnum):
    AUTO = 0x0
    H_SHA_256 = 0x2
    H_INTEGRITY = 0x3

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

TICKET_SIGNATURE_SIZES = {
    TicketSignatureType.RSA_4096_SHA1: 0x200,
    TicketSignatureType.RSA_2048_SHA1: 0x100,
    TicketSignatureType.ECDSA_SHA1: 0x3C,
    TicketSignatureType.RSA_4096_SHA256: 0x200,
    TicketSignatureType.RSA_2048_SHA256: 0x100,
    TicketSignatureType.ECDSA_SHA256: 0x3C
}


@dataclass
class EncryptionScheme:
    method: EncryptionType

    # The key(s) to use.
    # For XTS this is the block key + tweak key (128 bits/16 bytes each)
    # For CBC it's a single key equal the the block size (128 bits/16 bytes)
    key: bytes = None

    # Initial offset into the encrypted data
    initial_offset: int = 0

    # The sector size for XTS mode
    sector_size: int = XTS_SECTOR_SIZE

    # The nonce for CBC mode
    nonce: Union[int, bytes] = None

#########################################


class UnbufferedBaseIO:
    """Base class of all IO-related classes

    Supports creating "child" UnbufferedBaseIO objects that act as views into
    certain ranges of the underlying data. Each of these children keeps track
    of their offset relative to their parent object. This makes it easier to
    reason about their local data structures.

    It also means that objects can be re-parented without having to be modified.

    When reading/writing data at an offset, the children apply their local
    offset and defer up to the parent object on how to handle the IO. If there
    is no parent, it's assumed to be the top-level object and the request is
    passed to the loaded stream.

    All read/write operations are done directly on the stream making it
    unusable for dealing with encrypted objects.

    The lack of buffering also means that unless the underlying stream is
    buffered, doing many small reads/writes will kill performance.

    The BaseIO subclass adds support for buffering and encryption and is
    probably what you want to use.
    """

    # TODO: __slots__ ?

    # Subclasses that are staticly sized can define this instead of passing size to init
    static_size = None

    # TODO: Handle unbounded size for objects (writing a filesystem?)

    def __init__(self, *, size=None, console_keys: ConsoleKeys = None, **kwargs):
        """Store how to parse the file"""
        if size is None and self.static_size:
            size = self.static_size
        self._io = None
        self._offset = 0
        self._size = size
        self._console_keys = console_keys
        self._children = []
        self._parent = None
        self._parsed = False

    # Load data and parse
    def from_io(self, data: io.BufferedIOBase):
        self._io = data
        if self.size is None:
            self._io.seek(0, io.SEEK_END)
            self._size = self.tell()
        self._parse()
        return self

    def from_file(self, path: Union[str, Path]):
        with open(path, 'rb') as fp:
            return self.from_io(fp)

    def from_bytes(self, data: Union[bytes, bytearray]):
        return self.from_io(io.BytesIO(data))

    #TODO: API? Instantiate from kwargs?
    def to_io(self, data: io.BufferedIOBase):
        self._io = data
        self._io.seek(0)
        self.serialize()
        self.flush()
        return self

    def to_file(self, path: Union[str, Path]):
        with open(path, 'wb') as fp:
            return self.to_io(fp)

    @property
    def size(self):
        return self._size

    def __bool__(self):
        # Ensure the `if self.parent` checks return true even if the parent is
        # 0 bytes
        return True

    @property
    def console_keys(self):
        return self._console_keys

    @property
    def parent(self):
        return self._parent

    @property
    def children(self):
        return self._children

    @property
    def parsed(self):
        return self._parsed

    def _parse(self):
        self.seek(0)
        self.parse()

        # Check for unparsed data at the end
        pos = self.tell()
        newpos = self.seek(0, io.SEEK_END)

        skipped = newpos - pos
        if skipped != 0:
            __log__.debug("WARNING: Skipped %d bytes at the end of %s", skipped, self)

        self._parsed = True

    # Define how to parse/serialize
    def parse(self):
        """Parse information out of the loaded stream"""
        __log__.error("Parsing not implemented for %s", self)

    def serialize(self):
        """Using the stored data, write to the stream"""
        __log__.error("Serialization not implemented for %s", self)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __len__(self):
        return self.size

    def __repr__(self):
        return "<{} size='{}' offset={:#x}>".format(
            self.__class__.__qualname__,
            display_bytes(self.size),
            self._offset
        )

    def __iter__(self):
        return iter(self._children)

    def __del__(self):
        # Don't close objects that haven't been initialized
        if hasattr(self, "_io") and hasattr(self, "_parent"):
            self.close()

    def _check_offset(self, target, size=None):
        """Check the (relative) offset is valid"""
        # TODO: Test overhead of checking bounds on every read/write/seek
        if not size and not (0 <= target <= self.size):
            raise IOError("Can't access {:#x} - out of valid range 0x0-{:#x} @ {:#x})".format(target, self.size, self._offset))
        if size and not (0 <= target <= target + size <= self.size):
            raise IOError("Can't access {:#x}-{:#x} - out of valid range 0x0-{:#x} @ {:#x})".format(target, target+size, self.size, self._offset))

    # Methods to interact with the underlying io object
    def read(self, size=None, check_bounds=True):
        """Read bytes from the object

        Will call read on its parent object, or, if it's the top-level object,
        will read directly from the loaded io stream.

        If check_bounds is True (default) the write offset + size will be
        checked to make sure it's within the object bounds. When calling write
        on the parent object, this flag will always be disabled.
        """
        if size is None:
            size = self.size - self.tell()

        # Only log this out if io tracing is enabled and its not the super()
        # call from a buffered read
        if __log__.isEnabledFor(logging.IOTRACE):
            if not isinstance(self, BaseIO):
                __log__.iotrace("       Reading: %5d bytes from %s", size, self)

        if size <= 0:
            return b""

        if check_bounds:
            self._check_offset(self.tell(), size)

        if self.parent:
            return self.parent.read(size, check_bounds=False)
        else:
            __log__.iotrace("       Reading: %5d bytes from <stream>", size)
            return self._io.read(size)

    def read_object(self, obj: "UnbufferedBaseIO"):
        """Read an object from the bytestream

        Will also add the object to self._children so __iter__ will return it
        """
        if obj.size is None:
            raise ValueError("The size of the object to read must be known")
        elif obj.size < 0:
            raise ValueError("The size of the object cannot be negative ({})".format(obj.size()))

        offset = self.tell()

        # Transfer attributes to the new object
        obj._parent = self
        obj._offset = offset
        obj._console_keys = self.console_keys

        __log__.debug("Reading %s from %s", obj, self)

        self._children.append(obj)
        obj._parse()

        return obj

    def read_string(self, size, null_terminated=True, encoding="utf-8"):
        data = self.read(size)
        if not null_terminated:
            return data.decode(encoding)
        return data.split(b'\x00', 1)[0].decode(encoding)

    def read_hex(self, size, reverse=False):
        data = self.read(size)
        if reverse:
            data = data[::-1]
        return hexlify(data).decode("utf-8").upper()

    def read_int(self, size):
        return int.from_bytes(self.read(size), byteorder="little", signed=True)

    def read_int32(self):
        return self.read_int(4)

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

    def read_expected(self, expected):
        val = self.read(len(expected))
        if val != expected:
            raise ValueError(
                "Error parsing {}: Expected value at {:#x} was {} (expected {})".format(
                    self,
                    self.tell(),
                    val,
                    expected
                )
            )
        return val

    def read_enum(self, size, enum, strict=True):
        """Read size bytes and attempt to upconvert it into an enum

        When strict=True (default) an exception will be raised if the value
        is not a member of the enum.
        """
        if issubclass(enum, int):
            val = self.read_uint(size)
        else:
            val = self.read(size)
        try:
            return enum(val)
        except ValueError:
            if strict:
                raise
            __log__.warning("Unknown %s value of '%s'", enum, val)
            return val

    def peek(self, size=None):
        """Peek at the next size bytes without advancing the position"""
        if size is None:
            size = self.size - self.tell()
        elif size == 0:
            return b""

        p = self.tell()
        try:
            return self.read(size)
        finally:
            self.seek(p)

    def write(self, b: bytes, check_bounds=True):
        """Write bytes to the object

        Will call write on its parent object, or, if it's the top-level object,
        will write directly to the loaded io stream.

        If check_bounds is True (default) the write offset + size will be
        checked to make sure it's within the object bounds. When calling write
        on the parent object, this flag will always be disabled.
        """
        size = len(b)
        if not size:
            return 0

        # Only log this out if io tracing is enabled and its not the super()
        # call from a buffer sync
        if __log__.isEnabledFor(logging.IOTRACE):
            if not isinstance(self, BaseIO):
                __log__.iotrace("       Writing: %5d bytes to %s", size, self)

        if check_bounds:
            self._check_offset(self.tell(), size)

        if self.parent:
            return self.parent.write(b, check_bounds=False)
        else:
            __log__.iotrace("       Writing: %5d bytes to <stream>", len(b))
            return self._io.write(b)

    def write_object(self, obj: "UnbufferedBaseIO"):
        """Write an object to the bytestream using its serialize function"""

        __log__.iotrace("Writing %s to %s", obj, self)
        obj.serialize()
        obj.seek(0, io.SEEK_END)
        return obj.size

    def seek(self, offset, whence=io.SEEK_SET):
        """Seek to the provided offset

        The `whence` param has the same meaning as in `io.seek`

        Returns the offset of the seek point
        """
        if whence == io.SEEK_SET:
            target = offset
        elif whence == io.SEEK_CUR:
            target = self.tell() + offset
        elif whence == io.SEEK_END:
            target = self.size + offset
        else:
            raise ValueError("Invalid whence ({}, should be 0, 1 or 2)".format(whence))

        # Don't actually care if we seek out of range (read/write will do the
        # check) so only check when debugging.
        if __log__.isEnabledFor(logging.DEBUG):
            self._check_offset(target)

        if self.parent:
            return self.parent.seek(self._offset + target, io.SEEK_SET) - self._offset
        else:
            return self._io.seek(self._offset + target, io.SEEK_SET) - self._offset

    def skip(self, offset):
        """Convenience function for seeking forwards"""
        self.seek(offset, io.SEEK_CUR)

    def tell(self, absolute=False):
        if self.parent:
            p = self.parent.tell(absolute=absolute)
        else:
            p = self._io.tell()

        if not absolute:
            p -= self._offset
        return p

    @property
    def closed(self):
        if self.parent:
            return self.parent.closed
        elif self._io:
            return self._io.closed
        else:
            return True

    def close(self):
        if self.parent:
            self.parent.close()
        elif self._io and not self._io.closed:
            self._io.close()

    def flush(self):
        if self.parent:
            self.parent.flush()
        elif self._io:
            self._io.flush()


class BaseIO(UnbufferedBaseIO):
    """A subclasses of UnbufferedBaseIO that implements buffering and block-based encryption

    Without encryption enabled will just buffer data to reduce I/O calls to the
    underlying stream.

    With encryption enabled will buffer data as well a as apply block-based
    encryption when data is read from/written to the underlying stream.
    """

    def __init__(self,
        *args,
        encryption: EncryptionScheme = None,
        min_buffer_size=BUFFER_SIZE,
        **kwargs
    ):
        """
        Initialize the buffer and set up encryption (if any)

        min_buffer_size: Always load this many bytes into the buffer, regardless
                         of what was requested.
                         When using encryption this should be a multiple of the alignment
                         (sector size for XTS, block size for CBC/CTR/ECB) for best
                         performance (keeps writes aligned in the buffer).
        """
        super().__init__(*args, **kwargs)

        self._buff : bytearray = None # Data contained in the buffer
        self._buff_offset = None # The offset of the buffer (aligned to sector size)
        self._dirty = False # the buffer was modified and needs to be written back

        self.min_buffer_size = min_buffer_size

        self._setup_encryption(encryption)

    def _setup_encryption(self, encryption):

        if not encryption or encryption.method == EncryptionType.NONE:
            self._crypt = None
            self._alignment = 1
            return

        __log__.debug("Setting up encryption for %s: %s", self, encryption)
        if encryption.method == EncryptionType.AES_XTS:
            if not is_power_of_2(encryption.sector_size):
                raise ValueError("Sector size must be a power of 2 for AES XTS")

            self._crypt = aes128.AESXTS(
                keys=encryption.key,
                sector_size=encryption.sector_size,
                initial_offset=encryption.initial_offset or 0
            )
            self._alignment = encryption.sector_size
        elif encryption.method in (EncryptionType.AES_CTR, EncryptionType.AES_CTR_EX):
            # AES 128, therefore the key needs to be 16 bytes (128 bits)
            lk = len(encryption.key)
            if lk != 16:
                raise ValueError(
                    "Invalid key length for AES CTR (got {}, need 16)".format(lk)
                )

            self._crypt = aes128.AESCTR(
                key=encryption.key,
                nonce=encryption.nonce,
                initial_offset=encryption.initial_offset or 0
            )
            self._alignment = 16
        else:
            raise NotImplementedError(
                "Encryption method {} not implemented".format(encryption.method)
            )

    def aligned(self, offset, *, upper=False, alignment=None):
        """Return the offset aligned to the lower/upper alignment boundry

        If alignment is not provided, the current object's block alignment will
        be used (1 when no encryption is used, 16 for CTR, the sector size for XTS)

        If upper is False (default), the offset will be aligned to the start of
        the current aligned block (floor). If True, it will be aligned to the
        start of the next aligned block (ceil)
        """
        if alignment is None:
            alignment = self._alignment
        elif not is_power_of_2(alignment):
            raise ValueError("Alignment must be a power of 2")

        if upper:
            offset += alignment - 1
        return offset & ~(alignment-1)

    def misalignment(self, offset, *, alignment=None):
        """Return the offset relative to its lower alignment boundry

        If alignment is not provided, the current object's block alignment will
        be used (1 when no encryption is used, 16 for CTR, the sector size for XTS)
        """
        if alignment is None:
            alignment = self._alignment
        elif not is_power_of_2(alignment):
            raise ValueError("Alignment must be a power of 2")

        return offset & ~-alignment

    def _is_buffered(self, offset, size):
        """Check if the current offset+size is already in the buffer"""
        return self._buff and (
            self._buff_offset <=
            offset <=
            offset + size <=
            self._buff_offset + len(self._buff)
        )

    def _calc_min_buffer(self, offset, size):
        """Calculate the offset and minimum size of the buffer so it includes
        size bytes at offset.
        """
        # Align the starting offset back, increase the size to compensate
        # Align the amount requested with the upper sector boundry
        new_buff_offset = self.aligned(offset)
        required_size = self.aligned(size + self.misalignment(offset), upper=True)

        # Ensure the required range to load into the buffer is valid
        self._check_offset(new_buff_offset, required_size)

        return new_buff_offset, required_size

    def _calc_buffer(self, offset, size):
        """Calculate the offset and size of the buffer so it includes size
        bytes at offset while attempting to load up to min_buffer_size bytes
        """
        new_buff_offset, new_buff_size = self._calc_min_buffer(offset, size)

        # Attempt to fill the buffer until EOF
        # (new_buff_size has been verified to be inside EOF so the result of
        # this will never be smaller than it)
        new_buff_size = self.aligned(
            min(
                max(new_buff_size, self.min_buffer_size),
                self.size - new_buff_offset
            )
        )
        # Use any remaining bytes to go left until SOF
        read_prev = self.aligned(
            min(
                max(0, self.min_buffer_size - new_buff_size),
                new_buff_offset
            ),
            upper=True
        )
        new_buff_offset -= read_prev
        new_buff_size += read_prev
        return new_buff_offset, new_buff_size

    def _read(self, offset, size, zeropad=False):
        """Read size bytes at offset and decrypt them

        If zeropad is False, it's an error if not enough data could be read.
        Otherwise the data will be padded with null bytes
        """
        self.seek(offset)
        data = super().read(size, check_bounds=False)

        missing = size - len(data)
        if zeropad:
            data += b'\x00' * missing
        elif missing:
            raise ValueError(
                "Failed to read {} bytes at {:#x} (missing {})".format(
                    size, offset, missing
                )
            )
        if self._crypt:
            self._crypt.seek(offset)
            data = self._crypt.decrypt(data)
        return data

    def _load_buffer(self, offset, size, content=None):
        """Load data into the buffer

        Will start at the first sector that contains the offset and go until
        all the bytes requested by the size have been read.

        If content is supplied, it will be written into the buffer as if it
        was read from the stream at the supplied offset. The length of content
        is assumed to be <= size.
        """
        # Check if already loaded
        if self._is_buffered(offset, size):
            if content:
                tmp = offset - self._buff_offset
                self._buff[tmp : tmp + len(content)] = content
            return

        new_buff_offset, new_buff_size = self._calc_buffer(offset, size)

        if not self._buff:
            self._buff_offset = new_buff_offset
            curr_buff_size = 0
        else:
            curr_buff_size = len(self._buff)

        # Avoid re-reading and re-decrypting any overlapping sectors by
        # calculating the overlap with the current buffer (if any)
        new_buff_end = new_buff_offset + new_buff_size
        curr_buff_end = self._buff_offset + curr_buff_size

        overlap_start = max(self._buff_offset, new_buff_offset)
        overlap_end = max(overlap_start, min(curr_buff_end, new_buff_end))
        overlap_size = overlap_end - overlap_start

        if overlap_size < curr_buff_size:
            # dropping something out of the buffer - sync any changes
            self._sync()

        if overlap_size <= 0:
            # No overlapping data - read an entirely new buffer
            read_left = 0
            read_right = new_buff_size
            overlap_end = new_buff_offset
        else:
            read_left = overlap_start - new_buff_offset
            read_right = new_buff_end - overlap_end

        __log__.iotrace("     Buffering: %5d bytes from %s", read_left + overlap_size + read_right, self)

        # Optimization:
        # Figure out which blocks to exclude from reading if we're just going
        # to overwrite them entirely with the content
        #if content:
        #    exclude_start = self.aligned(offset, upper=True)
        #    exclude_end = self.aligned(offset + len(content))
        #    exclude_size = exclude_end - exclude_start

        # Need to pad the buffer with null bytes when writing so it stays aligned
        # Ex:
        # Want to write a single byte into a new 16-byte block. Reading the new
        # block will return b'' since there's no data there yet. We need to pad
        # that read out with null bytes so when the buffer is synced back to the
        # stream it can write a full sector.
        writing = bool(content)

        new_buff = bytearray()
        if read_left > 0:
            new_buff.extend(self._read(overlap_start - read_left, read_left, zeropad=writing))

        if overlap_size > 0:
            tmp = overlap_start - self._buff_offset
            new_buff.extend(self._buff[tmp : tmp + overlap_size])

        if read_right > 0:
            new_buff.extend(self._read(overlap_end, read_right, zeropad=writing))

        # write the content
        if writing:
            tmp = offset - new_buff_offset
            new_buff[tmp : tmp + len(content)] = content

        self._buff_offset = new_buff_offset
        self._buff = new_buff

    def _sync(self):
        """Sync any written data back to the underlying stream"""
        if self._buff and self._dirty:
            p = self.tell()

            __log__.iotrace(" Write buffer: %5d bytes to %s", len(self._buff), self)

            to_write = self._buff
            if self._crypt:
                self._crypt.seek(self._buff_offset)
                to_write = self._crypt.encrypt(to_write)

            # Bounds were already checked when adding data to the buffer
            self.seek(self._buff_offset)
            super().write(to_write, check_bounds=False)

            self.seek(p)
            self._dirty = False

    def flush(self):
        self._sync()
        super().flush()

    def close(self):
        if not self.closed:
            self._sync()
        super().close()

    def read(self, size=None, check_bounds=True):
        pos = self.tell()
        if size is None:
            size = self.size - pos

        if size <= 0:
            return b""

        __log__.iotrace(" Buffered read: %5d bytes from %s", size, self)

        self._load_buffer(pos, size)

        # position the stream cursor after the "read"
        self.seek(pos + size)

        offset = pos - self._buff_offset
        return bytes(self._buff[offset : offset + size])

    def write(self, b: bytes, check_bounds=True):
        """Will write the object the the buffer

        Calls write on parent objects as well so they can update their own
        buffers.
        """
        size = len(b)
        if not size:
            return 0

        __log__.iotrace("Buffered write: %5d bytes to %s", size, self)

        pos = self.tell()

        # Load buffer will load any required data into the buffer and replace
        # the bytes at the correct offset with the data to write
        self._load_buffer(pos, size, content=b)
        self._dirty = True

        # Propagate the write up so parent objects change their buffers too
        if self.parent:
            self.parent.write(b, check_bounds=False)

        # position the stream cursor after the "write"
        self.seek(pos + size)

        return size


class NamedFileMixin:
    """A mixin for classes that are named"""

    def __init__(self, *args, name=None, **kwargs):
        self._name = name
        super().__init__(*args, **kwargs)


    @property
    def name(self):
        return self._name

    def __repr__(self):
        if self.name:
            return "<{} {} size='{}' offset={:#x}>".format(
                self.__class__.__qualname__,
                self.name,
                display_bytes(self.size),
                self._offset
            )
        return super().__repr__()


class Filesystem(BaseIO):
    """Contains other objects"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.files = []

    def __iter__(self):
        return iter(self.files)


class Hfs0FileEntry(BaseIO):

    static_size = 0x40

    def parse(self):
        self.file_offset = self.read_uint64()
        self.file_size = self.read_uint64()
        self.name_offset = self.read_uint32()
        self.hashed_data_size = self.read_uint32()
        self.skip(0x2) # zero/reserved
        self.sha256 = self.read(0x20)

        # null-terminated strings
        self.name = self.parent.string_table[self.name_offset:].split(b"\x00", 1)[0].decode("utf-8")


class Pfs0FileEntry(BaseIO):

    static_size = 0x18

    def parse(self):
        self.file_offset = self.read_uint64()
        self.file_size = self.read_uint64()
        self.name_offset = self.read_uint32()
        self.skip(0x4) # padding/reserved

        # null-terminated strings
        self.name = self.parent.string_table[self.name_offset:].split(b"\0", 1)[0].decode("utf-8")


@dataclass
class FilesystemEntryData:
    header: Union[Hfs0FileEntry, Pfs0FileEntry]
    data: BaseIO = None


class _xfs0Filesystem(Filesystem):
    """Adapater for Pfs0 and Hfs0 filesytems"""

    def __init__(self, *args, file_entry_cls, **kwargs):
        self._file_entry_cls = file_entry_cls
        super().__init__(*args, **kwargs)

    def _parse_files(self, data_start):
        for f in self:
            self._parse_file(data_start, f)

    def _parse_file(self, data_start, f):
        """Iterates over the header and reads the files"""
        self.seek(data_start + f.header.file_offset)
        f.data = self.read_object(
            named_object(
                name=f.header.name,
                size=f.header.file_size
            )
        )

    def parse(self):
        if self._file_entry_cls == Hfs0FileEntry:
            self.magic = self.read_expected(b"HFS0")
        elif self._file_entry_cls == Pfs0FileEntry:
            self.magic = self.read_expected(b"PFS0")
        else:
            raise ValueError("Invalid file entry class {}".format(self._file_entry_cls))

        self.num_files = self.read_uint32()
        self.string_table_size = self.read_uint32()
        self.skip(0x4) # padding/reserved

        # Skip forward to get the string table before parsing the filenames
        pos = self.tell()
        self.skip(self.num_files * self._file_entry_cls.static_size)
        self.string_table = self.read(self.string_table_size)

        # Note the end of the string table (file data is relative to here)
        data_start = self.tell()
        self.seek(pos)

        self.files = []
        for _ in range(self.num_files):
            self.files.append(
                FilesystemEntryData(
                    header=self.read_object(self._file_entry_cls())
                )
            )

        self._parse_files(data_start)


class Hfs0(NamedFileMixin, _xfs0Filesystem):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, file_entry_cls=Hfs0FileEntry, **kwargs)


class Pfs0(_xfs0Filesystem):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, file_entry_cls=Pfs0FileEntry, **kwargs)


class Nsp(NamedFileMixin, Pfs0):
    """A Pfs0 with some extra restrictions/functionality"""

    def __init__(self, *args, **kwargs):
        self._ticket = None
        super().__init__(*args, **kwargs)

    def _parse_files(self, data_start):
        # If the NSP contains a ticket parse it first so we can use it to
        # decrypt the rest of the contents
        for f in self:
            if class_from_name(f.header.name) == Ticket:
                self._parse_file(data_start, f)
                __log__.info("Found a ticket: %s", hexlify(f.data.title_key).decode("utf-8").upper())
                self._ticket = f.data

        for f in self:
            if f.data:
                continue
            self._parse_file(data_start, f)

    @property
    def ticket(self):
        return self._ticket


class RomFS(Filesystem):
    pass


class GameCardCert(BaseIO):

    static_size=0x70

    def parse(self):
        # TODO
        self.cert_raw = self.read()


class GameCardInfo(BaseIO):

    static_size=0x70

    def parse(self):
        # TODO
        self.raw_enc_data = self.read()


class Xci(NamedFileMixin, BaseIO):

    def parse(self):
        self.signature = self.read(0x100)
        self.magic = self.read_expected(b"HEAD")
        self.secure_offset = self.read_uint32()
        self.backup_offset = self.read_uint32()
        self.title_kek_index = self.read_uint8()
        self.gamecard_size = self.read_uint8() # TODO: enum
        self.gamecard_header_version = self.read_uint8()
        self.gamecard_flags = self.read_uint8()
        self.package_id = self.read_uint64()
        self.valid_data_end_address = self.read_uint64() * MEDIA_UNITS
        self.gamecard_info_iv = self.read(0x10)

        self.hfs0_offset = self.read_uint64()
        self.hfs0_header_size = self.read_uint64()
        self.hfs0_header_hash = self.read(0x20)
        self.hfs0_initial_data_hash = self.read(0x20)
        self.security_mode = self.read_uint32() # TODO: enum (0x01 = T1, 0x02 = T2)
        self.t1_key_index = self.read_uint32()
        self.t2_key_index = self.read_uint32()
        self.normal_area_end_address = self.read_uint32() # in MEDIA_UNITS

        self.gamecard_info = self.read_object(GameCardInfo())
        self.seek(0x7000)
        self.gamecard_cert = self.read_object(GameCardCert())

        self.seek(self.hfs0_offset)
        self.filesystem = self.read_object(
            Hfs0(
                header_size=self.hfs0_header_size,
                header_hash=self.hfs0_header_hash,
                initial_data_hash=self.hfs0_initial_data_hash,
                size=self.size - self.hfs0_offset # EOF
            )
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
        self.start_offset = self.read_uint32() * MEDIA_UNITS
        self.end_offset = self.read_uint32() * MEDIA_UNITS
        self.skip(0x8) # reserved

    @property
    def fs_size(self):
        return self.end_offset - self.start_offset

    @property
    def is_padding(self):
        return self.start_offset == 0 and self.end_offset == 0

    def __repr__(self):
        if self.parsed and self.is_padding:
            return "<NcaFsEntry [padding]>"
        else:
            return super().__repr__()


class NcaHeader(BaseIO):

    static_size = 0x400

    def __init__(self, *args, header_key, **kwargs):
        encryption = EncryptionScheme(
            method=EncryptionType.AES_XTS,
            key=header_key
        )

        super().__init__(*args, encryption=encryption, **kwargs)

    @property
    def has_title_rights(self):
        return self.rights_id != "0"*32

    def parse(self):
        self.signature1 = self.read(0x100)
        self.signature2 = self.read(0x100)
        self.magic = self.read_expected(b"NCA3") # TODO: support old versions?
        self.distribution_type = self.read_uint8() # enum 0x00 = System NCA, 0x01 = Gamecard NCA
        self.content_type = self.read_enum(0x1, NcaContentType)
        self.key_generation_old = self.read_enum(0x1, KeyGeneration)
        self.key_area_encryption_key_index = self.read_uint8() # enum KeyAreaEncryptionKeyIndex (0x00 = Application, 0x01 = Ocean, 0x02 = System)
        self.content_size = self.read_uint64()
        self.program_id = self.read_hex(0x8, reverse=True)
        self.content_index = self.read_uint32()
        self.sdk_addon_version = self.read_uint32()
        self.key_generation_new = self.read_enum(0x1, KeyGeneration)
        self.header1_sig_key_generation = self.read_uint8()
        self.skip(0xE) # reserved
        self.rights_id = self.read_hex(0x10)

        self.sections = [self.read_object(NcaFsEntry()) for _ in range(4)]
        self.header_sha256_hashes = [self.read(0x20) for x in self.sections]

        self._key_generation = KeyGeneration(
           max(self.key_generation_old, self.key_generation_new)
        )

        encrypted_key_block = self.read(0x40)
        key_block = self.console_keys.unwrap_title_key(encrypted_key_block, self.console_keys.master_key_index(self._key_generation))
        self.keys = [
            key_block[i * 0x10: (i+1) * 0x10]
            for i in range(4)
        ]


    def _parent_nsp(self):
        """Traverse up the hierarchy to find the NSP container this header is inside"""
        p = self._parent
        while p:
            if isinstance(p, Nsp):
                return p
            p = p._parent
        return None

    @property
    def decryption_key(self):
        if self.has_title_rights:
            # TODO: what about within an _fs0??
            nsp = self._parent_nsp()
            if not nsp:
                raise ValueError("No title key available (object is not in an NSP)")

            ticket = nsp.ticket
            if not ticket:
                raise ValueError("No title key available (no ticket found inside NSP {})".format(nsp))

            return self.console_keys.decrypt_title_key(
                ticket.title_key, self.console_keys.master_key_index(self._key_generation)
            )
        return self.keys[2] # TODO: why 2?


class HashInfo(BaseIO):
    static_size = 0xF8


class HierarchicalSha256(HashInfo):

    def parse(self):
        self.hash = self.read(0x20)
        self.block_size = self.read_uint32()
        self.read_expected(b"\x02\x00\x00\x00")
        self.table_offset = self.read_uint64()
        self.table_size = self.read_uint64()
        self.relative_offset = self.read_uint64()
        self.pfs0_size = self.read_uint64()
        self.skip(0xB0) # reserved


class HierarchicalIntegrityLevel(BaseIO):

    static_size = 0x18

    def parse(self):
        self.level_offset = self.read_uint64()
        self.level_size = self.read_uint64()
        self.block_size = self.read_uint32()
        self.read(0x4) # padding


class HierarchicalIntegrity(HashInfo):

    def parse(self):
        self.magic = self.read_expected(b"IVFC")
        self.read_expected(b"\x00\x00\x02\x00")
        self.master_hash_size = self.read_uint32()
        self.num_levels = self.read_uint32()

        self.levels = [
            self.read_object(HierarchicalIntegrityLevel())
            for _ in range(self.num_levels - 1)
        ]

        self.skip(0x20) # padding/reserved
        self.hash = self.read(0x20)
        self.skip(0x18) # padding


class HierarchicalSha256Table(BaseIO):

    def __init__(self, *args, hash_info: HierarchicalSha256, **kwargs):
        self._hi = hash_info
        super().__init__(*args, size=hash_info.relative_offset, **kwargs)

    def parse(self):
        self.skip(self._hi.table_offset)
        self.hash_table = self.read(self._hi.table_size) # TODO

        # padding
        self.skip(self._hi.relative_offset - self._hi.table_size)


class BktrInfo(BaseIO):
    static_size = 0x20

    def parse(self):
        self.entry_offset = self.read_uint64()
        self.entry_size = self.read_uint64()
        self.read_expected(b'BKTR')

        # TODO: What are these?
        self.u32 = self.read_uint32()
        self.s32 = self.read_int32()

        self.skip(0x4) # padding


class PatchInfo(BaseIO):
    """
    Stores the BKTR section information
    """
    static_size = 0x40

    def parse(self):
        # Check for a totally null PatchInfo
        if self.peek(self.static_size) == bytes(self.static_size):
            self.entries = []
            return

        self.entries = [
            self.read_object(BktrInfo())
            for _ in range(2)
        ]

    @property
    def is_padding(self):
        return not self.entries


class NcaFsHeader(BaseIO):
    static_size = 0x200

    def __init__(self, *args, header_key, encryption_offset=0, **kwargs):
        encryption = EncryptionScheme(
            method=EncryptionType.AES_XTS,
            key=header_key,
            initial_offset=encryption_offset
        )
        super().__init__(*args, encryption=encryption, **kwargs)

    def parse(self):
        self.version = self.read_expected(b'\x02\x00')
        self.fs_type = self.read_enum(0x1, FsType)
        self.hash_type = self.read_enum(0x1, HashType)
        self.encryption_type = self.read_enum(0x1, EncryptionType)
        self.skip(0x3) # padding
        self.hash_info = self.read_object(hashinfo_from_type(self.hash_type)())
        self.patch_info = self.read_object(PatchInfo())
        self.generation = self.read(0x4)
        self.secure_value = self.read(0x4)
        self.sparce_info = self.read(0x30)
        self.skip(0x88) # reserved


class NcaSection(BaseIO):
    """A section of an NCA (including the header and hash tables)"""

    def __init__(self, *args, nca_header, fs_header, encryption_offset, **kwargs):

        # RomFS uses the CTR_EX by default
        encryption_type = fs_header.encryption_type
        if encryption_type == EncryptionType.AUTO and fs_header.fs_type == FsType.ROMFS:
            encryption_type = EncryptionType.AES_CTR_EX

        encryption = EncryptionScheme(
            method=encryption_type,
            key=nca_header.decryption_key,
            nonce=(fs_header.generation + fs_header.secure_value)[::-1] + bytes(8),
            initial_offset=encryption_offset
        )
        self.header = fs_header

        super().__init__(*args, encryption=encryption, **kwargs)

    def parse(self):
        fs_size = None

        # Special case:
        # When using HierarchicalSha256 HashInfo there is a table preceeding
        # the filesystem (which is always a Pfs0).
        if self.header.hash_type == HashType.H_SHA_256:
            self.hash_table = self.read_object(
                HierarchicalSha256Table(hash_info=self.header.hash_info)
            )
            fs_size = self.header.hash_info.pfs0_size

        # skip to next aligned block
        self.seek(self.aligned(self.tell(), upper=True))

        # Assume the filesystem completely fills the NcaSection unless a
        # HierarchicalSha256 HashInfo in the header says otherwise.
        fs_size = fs_size or self.size - self.tell()

        self.filesystem = self.read_object(
            filesystem_from_type(self.header.fs_type)(size=fs_size)
        )


@dataclass
class NcaSectionData:
    location: NcaFsEntry
    header: NcaFsHeader = None
    section: NcaSection = None


class Nca(NamedFileMixin, BaseIO):

    def __init__(self, *args, **kwargs):
        self.sections = []
        super().__init__(*args, **kwargs)

    def parse(self):
        self.header = self.read_object(
            NcaHeader(
                header_key=self.console_keys['header_key']
            )
        )

        # No decryption_key = skip with error
        try:
            self.header.decryption_key
        except ValueError as e:
            __log__.error("Can't decrypt %s: %s", self, e)
            return

        self.sections = [
            NcaSectionData(location=x) for x in self.header.sections
        ]

        # Parse section headers
        for s in self:
            if s.location.is_padding:
                self.skip(NcaFsHeader.static_size)
            else:
                s.header = self.read_object(
                    # TODO: In pre NCA3 the sector count is reset to 0 per header
                    #       In NCA3+ it's relative to the start of the entire NCA
                    NcaFsHeader(
                        header_key=self.console_keys['header_key'],
                        encryption_offset=self.tell()
                    )
                )

        # Parse sections
        for s in self:
            if s.location.is_padding:
                continue

            self.seek(s.location.start_offset)
            s.section = self.read_object(
                NcaSection(
                    size=s.location.fs_size,
                    fs_header=s.header,
                    nca_header=self.header,
                    encryption_offset=self.tell()
                )
            )

    def __iter__(self):
        return iter(self.sections)


class CnmtContentMetaInfo(BaseIO):

    static_size = 0x10

    def parse(self):
        self.program_id = self.read_hex(0x8, reverse=True)
        self.version = self.read_uint32()
        self.content_meta_type = self.read_enum(0x01, ContentMetaType)
        self.content_meta_attrs = self.read(0x1) # (0=None, 1=IncludesExFatDriver, 2=Rebootless)
        self.skip(0x2) # reserved


class CnmtPackagedContentInfo(BaseIO):

    static_size = 0x38

    def parse(self):
        self.hash = self.read(0x20)
        self.content_id = self.read_hex(0x10)
        self.content_size = self.read_uint(0x6)
        self.content_type = self.read_enum(0x1, CnmtContentType)
        self.id_offset = self.read_uint8()


class Cnmt(NamedFileMixin, BaseIO):
    """PackagedContentMeta"""

    def parse(self):
        self.program_id = self.read_hex(0x8, reverse=True)
        self.version = self.read_uint32()
        self.content_meta_type = self.read_enum(0x01, ContentMetaType)
        self.skip(0x01) # reserved
        self.extended_header_size = self.read_uint16()
        self.content_count = self.read_uint16()
        self.content_meta_count = self.read_uint16()
        self.content_meta_attrs = self.read(0x1) # (0=None, 1=IncludesExFatDriver, 2=Rebootless)
        self.skip(0x3) # padding
        self.required_system_version = self.read_uint32()
        self.skip(0x4) # reserved

        # TODO: Parse into objects
        self.extended_header = self.read(self.extended_header_size)

        self.content = [
            self.read_object(CnmtPackagedContentInfo())
            for _ in range(self.content_count)
        ]
        self.meta = [
            self.read_object(CnmtContentMetaInfo())
            for _ in range(self.content_meta_count)
        ]

        # TODO: parse this data based on the extended_header
        self.extended_data = self.read(self.size - self.tell() - 0x20)

        self.digest = self.read(0x20)


class Ticket(NamedFileMixin, BaseIO):

    def parse(self):
        self.signature_type = self.read_enum(0x4, TicketSignatureType)
        self.signature = self.read(TICKET_SIGNATURE_SIZES[self.signature_type])

        # skip to next 0x40-aligned block
        self.seek(self.aligned(self.tell(), upper=True, alignment=0x40))

        self.issuer = self.read_string(0x40)
        self.title_key_block = self.read(0x100)
        self.skip(0x1) # unknown/padding
        self.title_key_type = self.read_uint8()
        self.skip(0x3) # unknown/padding
        self.master_key_rev = self.read_uint8()
        self.skip(0xA) # unknown/padding
        self.ticket_id = self.read_hex(0x8)
        self.device_id = self.read_hex(0x8)
        self.rights_id = self.read_hex(0x10)
        self.account_id = self.read_hex(0x4)

        self.skip(0xC) # padding/reserved/unknown

    @property
    def title_key(self):
        if self.title_key_type == 0:
            return self.title_key_block[:0x10]
        return None


class Nacp(NamedFileMixin, BaseIO):
    pass


def hashinfo_from_type(hash_type):
    if hash_type == HashType.H_SHA_256:
        return HierarchicalSha256
    elif hash_type == HashType.H_INTEGRITY:
        return HierarchicalIntegrity
    elif hash_type == HashType.AUTO:
        return HashInfo

    raise ValueError("Unknown hash type {}".format(hash_type))


def filesystem_from_type(fs_type):
    if fs_type == FsType.PFS0:
        return Pfs0
    elif fs_type == FsType.ROMFS:
        return RomFS

    raise ValueError("Unknown filesystem type {}".format(fs_type))


def named_object(*args, name, **kwargs):
    """Uses the name to pick a class and instantiates it with the rest of the params"""

    cls = class_from_name(name)
    if issubclass(cls, NamedFileMixin):
        return cls(*args, name=name, **kwargs)

    return cls(*args, **kwargs)


def class_from_name(name):
    """Uses the name to determine which class of object to parse it as"""
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
        __log__.warning("Unknown object named '%s'", name)
        return BaseIO
