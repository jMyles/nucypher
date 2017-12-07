from nkms.crypto.utils import BytestringSplitter
from npre.constants import UNKNOWN_KFRAG
from npre.umbral import EncryptedKey


class PFrag(object):
    _key_length = 34
    _message_length = 72
    _EXPECTED_LENGTH = _key_length + _message_length

    splitter = BytestringSplitter((bytes, _key_length), (bytes, _message_length))

    def __init__(self, ephemeral_data_as_bytes=None, encrypted_key=None, encrypted_message=None):
        # from nkms.crypto.api import PRE  # Avoid circular import
        if ephemeral_data_as_bytes and encrypted_key:
            raise ValueError("Pass either the ephemeral data as bytes or the encrypted key and message.  Not both.")
        elif ephemeral_data_as_bytes:
            encrypted_key, self.encrypted_message = self.splitter(ephemeral_data_as_bytes)
            self.encrypted_key = EncryptedKey(ekey=PRE.load_key(encrypted_key), re_id=None)
        elif encrypted_key and encrypted_message:
            self.encrypted_key = encrypted_key
            self.encrypted_message = encrypted_message
        else:
            assert False  # What do we do if all the values were None?  Perhaps have an "UNKNOWN_PFRAG" concept?

    def __bytes__(self):
        from nkms.crypto.api import PRE  # Avoid circular import
        encrypted_key_bytes = PRE.save_key(self.encrypted_key.ekey)
        return encrypted_key_bytes + self.encrypted_message

    def __len__(self):
        return len(bytes(self))

    def deserialized(self):
        return self.encrypted_key, self.encrypted_message


class KFrag(object):

    _EXPECTED_LENGTH = 66
    _is_unknown_kfrag = False

    def __init__(self, id_plus_key_as_bytes=None, umbral_kfrag=None):
        from nkms.crypto.api import PRE
        if all((id_plus_key_as_bytes, umbral_kfrag)):
            raise ValueError("Pass either the id/key or an umbral_kfrag (or neither for UNKNOWN_KFRAG).  Not both.")
        elif id_plus_key_as_bytes:
            id = ec.deserialize(pre.ecgroup, kfrag_bytes[:len(kfrag_bytes) // 2]),
            key=ec.deserialize(pre.ecgroup, kfrag_bytes[len(kfrag_bytes) // 2:])
        elif umbral_kfrag:
            self._umbral_kfrag = umbral_kfrag
        else:
            self._is_unknown_kfrag = True

    def __bytes__(self):
        return bytes(self._umbral_kfrag)

    def __eq__(self, other_kfrag):
        if other_kfrag is UNKNOWN_KFRAG:
            return bool(self._is_unknown_kfrag)
        else:
            return bytes(self) == bytes(other_kfrag)

    def __add__(self, other):
        return bytes(self) + other

    def __radd__(self, other):
        return other + bytes(self)

    def __getitem__(self, slice):
        return bytes(self)[slice]

    @property
    def key(self):
        return self._umbral_kfrag.key

    @property
    def id(self):
        return self._umbral_kfrag.id


class CFrag(object):
    _EXPECTED_LENGTH = 67
    _key_element_length = 34
    _re_id_length = 33

    def __init__(self, encrypted_key_as_bytes=None, reencrypted_data=None):
        from nkms.crypto.api import PRE  # Avoid circular import
        if encrypted_key_as_bytes and reencrypted_data:
            raise ValueError("Pass the bytes or the EncryptedKey, not both.")
        elif encrypted_key_as_bytes:
            if not len(encrypted_key_as_bytes) == self._EXPECTED_LENGTH:
                raise ValueError("Got {} bytes; need {} for a proper cFrag.".format(len(encrypted_key_as_bytes)),
                                 self._EXPECTED_LENGTH)
            key_element = PRE.load_key(encrypted_key_as_bytes[:self._key_element_length])
            re_id = PRE.load_key(encrypted_key_as_bytes[self._key_element_length:])
            self.encrypted_key = EncryptedKey(ekey=key_element, re_id=re_id)
        elif reencrypted_data:
            self.encrypted_key = reencrypted_data
        else:
            assert False  # Again, do we want a concept of an "empty" CFrag?

    def __bytes__(self):
        from nkms.crypto.api import PRE  # Avoid circular import
        as_bytes = PRE.save_key(self.encrypted_key.ekey) + PRE.save_key(self.encrypted_key.re_id)
        if len(as_bytes) != self._EXPECTED_LENGTH:
            raise TypeError("Something went crazy wrong here.  This CFrag serialized to {} bytes.".format(len(as_bytes)))
        else:
            return as_bytes

    def __len__(self):
        return len(bytes(self))

    def __add__(self, other):
        return bytes(self) + other

    def __radd__(self, other):
        return other + bytes(self)

    def __eq__(self, other_cfrag):
        return bytes(self) == bytes(other_cfrag)
