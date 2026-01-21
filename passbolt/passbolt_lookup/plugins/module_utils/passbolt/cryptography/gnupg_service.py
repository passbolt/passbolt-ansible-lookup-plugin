import gnupg

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.exceptions.gnupg_exception import \
    GnuPGException


class GnuPGService:
    GPG = gnupg.GPG()

    @classmethod
    def import_key(cls, armored_key: str, passphrase: str = None) -> str:
        return cls.GPG.import_keys(armored_key, passphrase=passphrase).fingerprints

    @classmethod
    def decrypt(cls, data: str, passphrase: str) -> str:
        decrypted = cls.GPG.decrypt(data, passphrase=passphrase)
        if not decrypted.ok:
            raise GnuPGException("Couldn't decrypt data: '%s'." % decrypted.status)
        return decrypted.data.decode('utf-8')

    @classmethod
    def encrypt(cls, data: str, encrypt_key_id: str, sign_key_id: str | None = None,
                sign_passphrase: str | None = None) -> str:
        encrypted = cls.GPG.encrypt(data, encrypt_key_id, sign=sign_key_id, passphrase=sign_passphrase, armor=True,
                                    always_trust=True)
        if not encrypted.ok:
            raise GnuPGException("Couldn't encrypt data: '%s'." % encrypted.status)
        return encrypted.data.decode('ascii')

    @classmethod
    def sign(cls, data: str, key_id: str, passphrase: str) -> str:
        signed = cls.GPG.sign(data, keyid=key_id, passphrase=passphrase)
        if not signed.ok:
            raise GnuPGException("Couldn't sign data: '%s'." % signed.status)
        return signed.data.decode('utf-8')

    @classmethod
    def verify(cls, data: str, key_id: str) -> str:
        verified = cls.GPG.verify(data, extra_args=['-o', '-'])
        if key_id is not None and verified.fingerprint != key_id:
            raise GnuPGException("Couldn't verify data.")
        return verified.data
