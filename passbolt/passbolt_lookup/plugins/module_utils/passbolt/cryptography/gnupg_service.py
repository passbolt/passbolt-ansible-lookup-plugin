import subprocess
import threading

import gnupg

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.exceptions.gnupg_exception import \
    GnuPGException


class GnuPGService:
    _thread_local = threading.local()

    @classmethod
    def _gpg(cls) -> gnupg.GPG:
        instance = getattr(cls._thread_local, "gpg", None)
        if instance is None:
            instance = gnupg.GPG()
            cls._thread_local.gpg = instance
        return instance

    @classmethod
    def __decrypt(cls, data: str, passphrase: str, sign_key_fingerprint: str | None = None) -> str:
        decrypted = cls._gpg().decrypt(data, passphrase=passphrase)
        if not decrypted.ok:
            raise GnuPGException("Couldn't decrypt data: '%s'." % decrypted.status)
        if sign_key_fingerprint is not None and decrypted.fingerprint != sign_key_fingerprint:
            raise GnuPGException("Couldn't verify decrypted data.")
        return decrypted.data.decode('utf-8')

    @classmethod
    def __encrypt(cls, data: str, encrypt_key_id: str, sign_key_id: str | None = None,
                sign_passphrase: str | None = None) -> str:
        encrypted = cls._gpg().encrypt(data, encrypt_key_id, sign=sign_key_id, passphrase=sign_passphrase, armor=True,
                                    always_trust=True)
        if not encrypted.ok:
            raise GnuPGException("Couldn't encrypt data: '%s'." % encrypted.status)
        return encrypted.data.decode('ascii')

    @classmethod
    def import_key(cls, armored_key: str, passphrase: str = None) -> str:
        imported_fingerprints = cls._gpg().import_keys(armored_key, passphrase=passphrase).fingerprints
        if None in imported_fingerprints:
            raise GnuPGException("One or more imported fingerprints were null.")
        return imported_fingerprints

    @classmethod
    def decrypt(cls, data: str, passphrase: str) -> str:
        return cls.__decrypt(data, passphrase)

    @classmethod
    def decrypt_and_verify(cls, data: str, passphrase: str, sign_key_fingerprint: str) -> str:
        if sign_key_fingerprint is None:
            raise GnuPGException("Signing key fingerprint is required for verification.")
        return cls.__decrypt(data, passphrase, sign_key_fingerprint)

    @classmethod
    def decrypt_with_session_key(cls, data: str, session_key: str,
                                 sign_key_fingerprint: str | None = None) -> str:
        if not session_key:
            raise GnuPGException("A session key is required for session-key decryption.")
        cmd = ["gpg", "--batch", "--no-tty", "--status-fd", "2",
               "--override-session-key", session_key, "--decrypt"]
        gnupghome = cls._gpg().gnupghome
        if gnupghome:
            cmd[1:1] = ["--homedir", gnupghome]
        proc = subprocess.run(cmd, input=data.encode("utf-8"),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        status = proc.stderr.decode("utf-8", "replace")
        if not cls._status_indicates_plaintext(status):
            raise GnuPGException("Couldn't decrypt data with session key: '%s'." %
                                 cls._gpg_error_reason(status))
        if sign_key_fingerprint is not None and not cls._status_has_valid_signature(
                status, sign_key_fingerprint):
            raise GnuPGException("Couldn't verify session-key-decrypted data.")
        return proc.stdout.decode("utf-8")

    @staticmethod
    def _status_indicates_plaintext(status: str) -> bool:
        recovered = False
        for line in status.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "[GNUPG:]":
                if parts[1] in ("PLAINTEXT", "PLAINTEXT_LENGTH"):
                    recovered = True
                elif parts[1] == "NODATA":
                    return False
        return recovered

    @staticmethod
    def _gpg_error_reason(stderr: str) -> str:
        human = [line for line in stderr.splitlines()
                 if line.strip() and not line.startswith("[GNUPG:]")]
        if human:
            return human[-1].strip()
        return " ".join(stderr.split())

    @staticmethod
    def _status_has_valid_signature(status: str, sign_key_fingerprint: str) -> bool:
        for line in status.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "[GNUPG:]" and parts[1] == "VALIDSIG" \
                    and parts[2] == sign_key_fingerprint:
                return True
        return False

    @classmethod
    def encrypt(cls, data: str, encrypt_key_id: str) -> str:
        return cls.__encrypt(data, encrypt_key_id)

    @classmethod
    def encrypt_and_sign(cls, data: str, encrypt_key_id: str, sign_key_id: str, sign_passphrase: str) -> str:
        if sign_key_id is None:
            raise GnuPGException("Signing key id is required.")
        return cls.__encrypt(data, encrypt_key_id, sign_key_id, sign_passphrase)

    @classmethod
    def sign(cls, data: str, key_id: str, passphrase: str) -> str:
        signed = cls._gpg().sign(data, keyid=key_id, passphrase=passphrase)
        if not signed.ok:
            raise GnuPGException("Couldn't sign data: '%s'." % signed.status)
        return signed.data.decode('utf-8')

    @classmethod
    def verify(cls, data: str, key_id: str) -> str:
        verified = cls._gpg().verify(data, extra_args=['-o', '-'])
        if key_id is not None and (not verified or verified.fingerprint != key_id):
            raise GnuPGException("Couldn't verify data.")
        return verified.data
