import os
import stat
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service import (
    GnuPGService,
)
from ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service import (
    KEYRING_DIR_PREFIX,
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
_PATCH_GPG_CLASS = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.gnupg.GPG"
_PATCH_RMTREE = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.shutil.rmtree"
_PATCH_DISPLAY = "ansible_collections.passbolt.passbolt_lookup.plugins.module_utils.passbolt.cryptography.gnupg_service.display"


def _fake_gpg(gnupghome=None, **_kwargs):
    return MagicMock(gnupghome=gnupghome)


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


def _reset_keyring_state():
    GnuPGService._thread_local.gpg = None
    GnuPGService._thread_local.temporary_gnupghome = None


class _KeyringTestCase(unittest.TestCase):
    """Shared isolation: GPG is faked, gpgconf is mocked and temporary keyrings land in a test-owned dir."""

    def setUp(self):
        _reset_keyring_state()
        self._tmp_root = tempfile.TemporaryDirectory()
        self.root = self._tmp_root.name
        # Route tempfile.mkdtemp into a test-owned directory so leaks are observable.
        tempdir_patcher = patch.object(tempfile, "tempdir", self.root)
        tempdir_patcher.start()
        self.addCleanup(tempdir_patcher.stop)
        gpg_patcher = patch(_PATCH_GPG_CLASS, side_effect=_fake_gpg)
        self.mock_gpg_class = gpg_patcher.start()
        self.addCleanup(gpg_patcher.stop)
        run_patcher = patch(_PATCH_SUBPROCESS)
        self.mock_run = run_patcher.start()
        self.addCleanup(run_patcher.stop)

    def tearDown(self):
        _reset_keyring_state()
        self._tmp_root.cleanup()


class TestOperatorKeyring(_KeyringTestCase):
    """PB-54783: without the option, the operator's keyring is used and never torn down."""

    def test_operator_keyring_is_used_by_default(self):
        gpg = GnuPGService._gpg()

        # No gnupghome means gpg falls back to ~/.gnupg or $GNUPGHOME.
        self.assertIsNone(gpg.gnupghome)
        self.mock_gpg_class.assert_called_once_with()
        self.assertEqual(os.listdir(self.root), [])

    def test_operator_keyring_is_reused_within_a_thread(self):
        first = GnuPGService._gpg()
        second = GnuPGService._gpg()

        self.assertIs(first, second)
        self.mock_gpg_class.assert_called_once()

    @patch(_PATCH_RMTREE)
    def test_close_leaves_the_operator_keyring_alone(self, mock_rmtree):
        gpg = GnuPGService._gpg()

        GnuPGService.close_temporary_keyring()

        # Neither the operator's gpg-agent nor its keyring directory may be touched.
        self.mock_run.assert_not_called()
        mock_rmtree.assert_not_called()
        self.assertIs(GnuPGService._gpg(), gpg)


class TestTemporaryKeyring(_KeyringTestCase):
    """PB-54783: with the option, each lookup works in its own temporary keyring, removed afterwards."""

    def test_keyring_is_a_private_temporary_directory(self):
        GnuPGService.open_temporary_keyring()
        gnupghome = GnuPGService._gpg().gnupghome

        self.assertEqual(os.path.dirname(gnupghome), self.root)
        self.assertTrue(os.path.basename(gnupghome).startswith(KEYRING_DIR_PREFIX))
        self.assertTrue(os.path.isdir(gnupghome))
        self.assertEqual(stat.S_IMODE(os.stat(gnupghome).st_mode), 0o700)
        self.mock_gpg_class.assert_called_once_with(gnupghome=gnupghome)

    def test_keyring_is_reused_within_a_thread(self):
        GnuPGService.open_temporary_keyring()

        self.assertIs(GnuPGService._gpg(), GnuPGService._gpg())
        self.mock_gpg_class.assert_called_once()

    def test_keyring_replaces_a_cached_operator_keyring(self):
        # A previous lookup without the option left the operator's keyring cached in this thread.
        operator_gpg = GnuPGService._gpg()

        GnuPGService.open_temporary_keyring()

        gpg = GnuPGService._gpg()
        self.assertIsNot(gpg, operator_gpg)
        self.assertEqual(os.path.dirname(gpg.gnupghome), self.root)

    def test_operator_keyring_is_used_again_after_close(self):
        GnuPGService.open_temporary_keyring()
        GnuPGService.close_temporary_keyring()

        gpg = GnuPGService._gpg()

        self.assertIsNone(gpg.gnupghome)
        self.assertEqual(os.listdir(self.root), [])

    def test_each_thread_gets_its_own_keyring(self):
        GnuPGService.open_temporary_keyring()
        main_home = GnuPGService._gpg().gnupghome
        other = {}

        def worker():
            GnuPGService.open_temporary_keyring()
            other["home"] = GnuPGService._gpg().gnupghome
            GnuPGService.close_temporary_keyring()

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

        self.assertNotEqual(main_home, other["home"])
        self.assertTrue(os.path.isdir(main_home))
        self.assertFalse(os.path.exists(other["home"]))

    def test_close_stops_agents_then_removes_keyring(self):
        GnuPGService.open_temporary_keyring()
        gnupghome = GnuPGService._gpg().gnupghome
        # Simulate key material left by an import.
        os.makedirs(os.path.join(gnupghome, "private-keys-v1.d"))
        with open(os.path.join(gnupghome, "private-keys-v1.d", "user.key"), "w") as f:
            f.write("secret")
        home_existed_when_agents_stopped = []
        self.mock_run.side_effect = lambda *a, **kw: home_existed_when_agents_stopped.append(
            os.path.isdir(gnupghome))

        GnuPGService.close_temporary_keyring()

        args = self.mock_run.call_args[0][0]
        self.assertEqual(args, ["gpgconf", "--homedir", gnupghome, "--kill", "all"])
        # Agents must be stopped while their homedir still exists, so gpgconf can reach them.
        self.assertEqual(home_existed_when_agents_stopped, [True])
        self.assertFalse(os.path.exists(gnupghome))
        self.assertEqual(os.listdir(self.root), [])

    def test_reopening_closes_the_previous_keyring(self):
        GnuPGService.open_temporary_keyring()
        first_home = GnuPGService._gpg().gnupghome

        GnuPGService.open_temporary_keyring()

        second_home = GnuPGService._gpg().gnupghome
        self.assertNotEqual(first_home, second_home)
        # The first keyring, which may hold a private key, must not be left orphaned.
        self.assertFalse(os.path.exists(first_home))
        self.assertTrue(os.path.isdir(second_home))

    def test_close_without_open_keyring_is_a_noop(self):
        GnuPGService.close_temporary_keyring()

        self.mock_run.assert_not_called()

    def test_close_still_removes_keyring_when_gpgconf_is_missing(self):
        GnuPGService.open_temporary_keyring()
        gnupghome = GnuPGService._gpg().gnupghome
        self.mock_run.side_effect = FileNotFoundError("gpgconf")

        GnuPGService.close_temporary_keyring()

        self.assertFalse(os.path.exists(gnupghome))

    @patch(_PATCH_DISPLAY)
    @patch(_PATCH_RMTREE)
    def test_close_warns_when_keyring_cannot_be_removed(self, _mock_rmtree, mock_display):
        GnuPGService.open_temporary_keyring()
        gnupghome = GnuPGService._gpg().gnupghome

        GnuPGService.close_temporary_keyring()

        mock_display.warning.assert_called_once()
        self.assertIn(gnupghome, mock_display.warning.call_args[0][0])

    def test_keyring_removed_when_gpg_initialisation_fails(self):
        self.mock_gpg_class.side_effect = OSError("gpg not found")

        with self.assertRaises(OSError):
            GnuPGService.open_temporary_keyring()

        self.assertEqual(os.listdir(self.root), [])
        self.assertIsNone(GnuPGService._thread_local.temporary_gnupghome)
        self.assertIsNone(GnuPGService._thread_local.gpg)


if __name__ == "__main__":
    unittest.main()
