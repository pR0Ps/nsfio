#!/usr/bin/env python

import functools
import logging
from binascii import crc32
from binascii import unhexlify as uhx

from nsfio import aes128

__log__ = logging.getLogger(__name__)


# Checksums to ensure the keys are correct
KEY_CHECKSUMS = {
    "aes_kek_generation_source": 2545229389,
    "aes_key_generation_source": 459881589,
    "titlekek_source": 3510501772,
    "key_area_key_application_source": 4130296074,
    "key_area_key_ocean_source": 3975316347,
    "key_area_key_system_source": 4024798875,
    "master_key_00": 3540309694,
    "master_key_01": 3477638116,
    "master_key_02": 2087460235,
    "master_key_03": 4095912905,
    "master_key_04": 3833085536,
    "master_key_05": 2078263136,
    "master_key_06": 2812171174,
    "master_key_07": 1146095808,
    "master_key_08": 1605958034,
    "master_key_09": 3456782962,
    "master_key_0a": 2012895168,
    "master_key_0b": 3813624150,
    "master_key_0c": 3881579466,
    "master_key_0d": 723654444,
    "master_key_0e": 2690905064,
    "master_key_0f": 4082108335,
    "master_key_10": 788455323,
    "master_key_11": 1214507020,
}


class ConsoleKeys:
    def __init__(self, keyfile):
        self._keys = {}
        self._key_area_keys = []
        self._title_keks = []
        self._load(keyfile)

    def __contains__(self, k):
        try:
            self[k]
        except KeyError:
            return False
        return True

    @functools.lru_cache()
    def __getitem__(self, k):
        value = uhx(self._keys[k])

        checksum = crc32(value)
        if KEY_CHECKSUMS.get(k, checksum) != checksum:
            raise KeyError("Key '{}' is invalid (crc32 missmatch)".format(k))

        return value

    def _load(self, filename):
        __log__.info("Loading keys from %s", filename)

        with open(filename, encoding="utf8") as f:
            for line in f.readlines():
                k, v = line.split("=", 1)
                self._keys[k.strip()] = v.strip()

        for i in range(32):
            self._key_area_keys.append([None, None, None])

        for i in range(32):
            try:
                master_key = self.master_key(i)
            except KeyError:
                continue

            crypto = aes128.AESECB(master_key)
            self._title_keks.append(crypto.decrypt(self["titlekek_source"]).hex())
            self._key_area_keys[i][0] = self.generate_kek(
                self["key_area_key_application_source"], master_key
            )
            self._key_area_keys[i][1] = self.generate_kek(
                self["key_area_key_ocean_source"], master_key
            )
            self._key_area_keys[i][2] = self.generate_kek(
                self["key_area_key_system_source"], master_key
            )

    # getMasterKey
    def master_key(self, i):
        return self["master_key_{:02x}".format(i)]

    # keyAreaKey
    def key_area_key(self, crypto_type, i):
        return self._key_area_keys[crypto_type][i]

    # getTitleKek
    def title_kek(self, i):
        return self._title_keks[i]

    # generateKek
    def generate_kek(self, src, master_key):
        kek_seed = self["aes_kek_generation_source"]
        key_seed = self["aes_key_generation_source"]

        kek = aes128.AESECB(master_key).decrypt(kek_seed)
        src_kek = aes128.AESECB(kek).decrypt(src)

        return aes128.AESECB(src_kek).decrypt(key_seed)

    # decryptTitleKey
    def decrypt_title_key(self, key, i):
        kek = self.title_kek(i)
        return aes128.AESECB(uhx(kek)).decrypt(key)

    # encryptTitleKey
    def encrypt_title_key(self, key, i):
        kek = self.title_kek(i)
        return aes128.AESECB(uhx(kek)).encrypt(key)

    # changeTitleKeyMasterKey
    def change_title_key(self, key, current_idx, new_idx):
        return self.encrypt_title_key(self.decrypt_title_key(key, current_idx), new_idx)

    # unwrapAesWrappedTitleKey
    def unwrap_title_key(self, wrapped_key, key_generation):
        kek = self.generate_kek(
            self["key_area_key_application_source"], self.master_key(key_generation)
        )
        return aes128.AESECB(kek).decrypt(wrapped_key)

    # TODO: remove
    # getMasterKeyIndex
    @staticmethod
    def master_key_index(i):
        if i > 0:
            return i - 1
        else:
            return 0


class ConsoleKeysRequiredMixin:
    """Mix this into any class that needs access to console_keys"""

    def __init__(self, *args, console_keys: ConsoleKeys, **kwargs):
        if not console_keys:
            raise Exception("Console keys are required to initialize a %s", type(self))
        self._console_keys = console_keys
        super().__init__(*args, **kwargs)

    @property
    def console_keys(self):
        return self._console_keys
