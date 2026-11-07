import unittest
from unittest.mock import MagicMock, patch

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service import (
    GnuPGService,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.exceptions.gnupg_exception import (
    GnuPGException,
)

# --- Constants ---

SESSION_KEY = "9:DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
FPR = "72EC3E19B9D4549A5658F3ECC0DA1C8F7C049034"
PLAINTEXT = '{"name": "Test Resource"}'

_PATCH_SUBPROCESS = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.subprocess.run"
_PATCH_GPG = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.GnuPGService._gpg"


def _proc(returncode=0, stdout=b"", stderr=b""):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


_PLAINTEXT_STATUS = "[GNUPG:] PLAINTEXT 62 1782283507 msg.txt\n[GNUPG:] PLAINTEXT_LENGTH 25\n"


def _status_validsig(fingerprint):
    return (_PLAINTEXT_STATUS
            + "[GNUPG:] DECRYPTION_OKAY\n"
            + "[GNUPG:] GOODSIG ABCD %s\n" % "signer"
            + "[GNUPG:] VALIDSIG %s 2026-06-24 1782283507 0 4 0 22 10 01 %s\n"
            % (fingerprint, fingerprint)).encode("utf-8")


class TestDecryptAndVerifyAny(unittest.TestCase):

    @staticmethod
    def _result(
        *,
        ok=True,
        valid=True,
        fingerprint=FPR,
        pubkey_fingerprint=None,
        status="decryption ok",
    ):
        result = MagicMock()
        result.ok = ok
        result.valid = valid
        result.fingerprint = fingerprint
        result.pubkey_fingerprint = pubkey_fingerprint
        result.status = status
        result.data = PLAINTEXT.encode("utf-8")
        return result

    @patch(_PATCH_GPG)
    def test_accepts_trusted_signer(self, mock_gpg):
        mock_gpg.return_value.decrypt.return_value = self._result()

        result = GnuPGService.decrypt_and_verify_any(
            "encrypted",
            "passphrase",
            {FPR, "OTHERFPR"},
        )

        self.assertEqual(result, PLAINTEXT)

    @patch(_PATCH_GPG)
    def test_accepts_primary_fingerprint_for_signing_subkey(self, mock_gpg):
        mock_gpg.return_value.decrypt.return_value = self._result(
            fingerprint="SIGNINGSUBKEYFPR",
            pubkey_fingerprint=FPR,
        )

        result = GnuPGService.decrypt_and_verify_any(
            "encrypted",
            "passphrase",
            {FPR},
        )

        self.assertEqual(result, PLAINTEXT)

    @patch(_PATCH_GPG)
    def test_matches_fingerprints_case_insensitively(self, mock_gpg):
        mock_gpg.return_value.decrypt.return_value = self._result(
            fingerprint=FPR.lower(),
        )

        result = GnuPGService.decrypt_and_verify_any(
            "encrypted",
            "passphrase",
            {FPR},
        )

        self.assertEqual(result, PLAINTEXT)

    @patch(_PATCH_GPG)
    def test_rejects_unknown_signer(self, mock_gpg):
        mock_gpg.return_value.decrypt.return_value = self._result(
            fingerprint="UNKNOWNFPR",
        )

        with self.assertRaises(GnuPGException):
            GnuPGService.decrypt_and_verify_any(
                "encrypted",
                "passphrase",
                {FPR},
            )

    @patch(_PATCH_GPG)
    def test_rejects_invalid_signature_from_trusted_key(self, mock_gpg):
        mock_gpg.return_value.decrypt.return_value = self._result(
            valid=False,
            fingerprint=FPR,
        )

        with self.assertRaises(GnuPGException):
            GnuPGService.decrypt_and_verify_any(
                "encrypted",
                "passphrase",
                {FPR},
            )

    @patch(_PATCH_GPG)
    def test_rejects_missing_signature(self, mock_gpg):
        mock_gpg.return_value.decrypt.return_value = self._result(
            valid=False,
            fingerprint=None,
            pubkey_fingerprint=None,
        )

        with self.assertRaises(GnuPGException):
            GnuPGService.decrypt_and_verify_any(
                "encrypted",
                "passphrase",
                {FPR},
            )

    @patch(_PATCH_GPG)
    def test_rejects_decryption_failure(self, mock_gpg):
        mock_gpg.return_value.decrypt.return_value = self._result(
            ok=False,
            valid=False,
            fingerprint=None,
            status="decryption failed",
        )

        with self.assertRaises(GnuPGException):
            GnuPGService.decrypt_and_verify_any(
                "encrypted",
                "passphrase",
                {FPR},
            )

    def test_rejects_empty_trusted_signer_set(self):
        with self.assertRaises(GnuPGException):
            GnuPGService.decrypt_and_verify_any(
                "encrypted",
                "passphrase",
                set(),
            )


class TestDecryptWithSessionKey(unittest.TestCase):

    @patch(_PATCH_GPG, return_value=MagicMock(gnupghome=None))
    @patch(_PATCH_SUBPROCESS)
    def test_success_no_signature_check(self, mock_run, _mock_gpg):
        mock_run.return_value = _proc(0, PLAINTEXT.encode("utf-8"),
                                      _PLAINTEXT_STATUS.encode("utf-8") + b"[GNUPG:] DECRYPTION_OKAY\n")

        result = GnuPGService.decrypt_with_session_key("blob", SESSION_KEY)

        self.assertEqual(result, PLAINTEXT)
        # override-session-key passed verbatim, decrypt from stdin
        args = mock_run.call_args[0][0]
        self.assertIn("--override-session-key", args)
        self.assertIn(SESSION_KEY, args)
        self.assertEqual(mock_run.call_args[1]["input"], b"blob")

    @patch(_PATCH_GPG, return_value=MagicMock(gnupghome=None))
    @patch(_PATCH_SUBPROCESS)
    def test_decryption_failure_raises(self, mock_run, _mock_gpg):
        # No PLAINTEXT status line means no literal data was recovered.
        mock_run.return_value = _proc(2, b"", b"gpg: decryption failed")

        with self.assertRaises(GnuPGException):
            GnuPGService.decrypt_with_session_key("blob", SESSION_KEY)

    @patch(_PATCH_GPG, return_value=MagicMock(gnupghome=None))
    @patch(_PATCH_SUBPROCESS)
    def test_wrong_session_key_nodata_raises(self, mock_run, _mock_gpg):
        # A wrong override key still emits DECRYPTION_OKAY/GOODMDC but no PLAINTEXT and a NODATA.
        mock_run.return_value = _proc(
            2, b"",
            b"[GNUPG:] NODATA 3\n[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n[GNUPG:] NODATA 3\n")

        with self.assertRaises(GnuPGException):
            GnuPGService.decrypt_with_session_key("blob", SESSION_KEY)

    @patch(_PATCH_GPG, return_value=MagicMock(gnupghome=None))
    @patch(_PATCH_SUBPROCESS)
    def test_unverifiable_signature_without_check_still_decrypts(self, mock_run, _mock_gpg):
        # gpg exits nonzero on an unverifiable embedded signature, but the plaintext was
        # recovered; with no fingerprint to enforce we must return it (the scan fast path).
        stderr = (_PLAINTEXT_STATUS
                  + "[GNUPG:] ERRSIG 06339200709FA9FE 1 10 00 1782372021 9 AAAA\n"
                  + "[GNUPG:] NO_PUBKEY 06339200709FA9FE\n"
                  + "[GNUPG:] DECRYPTION_OKAY\n").encode("utf-8")
        mock_run.return_value = _proc(2, PLAINTEXT.encode("utf-8"), stderr)

        result = GnuPGService.decrypt_with_session_key("blob", SESSION_KEY)

        self.assertEqual(result, PLAINTEXT)

    @patch(_PATCH_GPG, return_value=MagicMock(gnupghome=None))
    @patch(_PATCH_SUBPROCESS)
    def test_signature_valid(self, mock_run, _mock_gpg):
        mock_run.return_value = _proc(0, PLAINTEXT.encode("utf-8"), _status_validsig(FPR))

        result = GnuPGService.decrypt_with_session_key("blob", SESSION_KEY, FPR)

        self.assertEqual(result, PLAINTEXT)

    @patch(_PATCH_GPG, return_value=MagicMock(gnupghome=None))
    @patch(_PATCH_SUBPROCESS)
    def test_signature_missing_raises(self, mock_run, _mock_gpg):
        mock_run.return_value = _proc(0, PLAINTEXT.encode("utf-8"),
                                      _PLAINTEXT_STATUS.encode("utf-8") + b"[GNUPG:] DECRYPTION_OKAY\n")

        with self.assertRaises(GnuPGException):
            GnuPGService.decrypt_with_session_key("blob", SESSION_KEY, FPR)

    @patch(_PATCH_GPG, return_value=MagicMock(gnupghome=None))
    @patch(_PATCH_SUBPROCESS)
    def test_signature_wrong_fingerprint_raises(self, mock_run, _mock_gpg):
        mock_run.return_value = _proc(0, PLAINTEXT.encode("utf-8"), _status_validsig("OTHERFPR"))

        with self.assertRaises(GnuPGException):
            GnuPGService.decrypt_with_session_key("blob", SESSION_KEY, FPR)

    def test_empty_session_key_raises(self):
        with self.assertRaises(GnuPGException):
            GnuPGService.decrypt_with_session_key("blob", "")

    @patch(_PATCH_GPG, return_value=MagicMock(gnupghome="/custom/home"))
    @patch(_PATCH_SUBPROCESS)
    def test_homedir_forwarded_when_set(self, mock_run, _mock_gpg):
        mock_run.return_value = _proc(0, PLAINTEXT.encode("utf-8"), _PLAINTEXT_STATUS.encode("utf-8"))

        GnuPGService.decrypt_with_session_key("blob", SESSION_KEY)

        args = mock_run.call_args[0][0]
        self.assertIn("--homedir", args)
        self.assertIn("/custom/home", args)

    def test_status_has_valid_signature_matches_fingerprint(self):
        status = _status_validsig(FPR).decode("utf-8")
        self.assertTrue(GnuPGService._status_has_valid_signature(status, FPR))
        self.assertFalse(GnuPGService._status_has_valid_signature(status, "NOPE"))
        self.assertFalse(GnuPGService._status_has_valid_signature("[GNUPG:] DECRYPTION_OKAY", FPR))

    def test_status_indicates_plaintext(self):
        self.assertTrue(GnuPGService._status_indicates_plaintext(_PLAINTEXT_STATUS))
        # DECRYPTION_OKAY/GOODMDC alone are not enough; a wrong key emits them with NODATA.
        self.assertFalse(GnuPGService._status_indicates_plaintext(
            "[GNUPG:] NODATA 3\n[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n"))
        self.assertFalse(GnuPGService._status_indicates_plaintext("[GNUPG:] DECRYPTION_OKAY\n"))
        # A NODATA anywhere invalidates a stray PLAINTEXT marker.
        self.assertFalse(GnuPGService._status_indicates_plaintext(
            _PLAINTEXT_STATUS + "[GNUPG:] NODATA 3\n"))


if __name__ == "__main__":
    unittest.main()
