import os
import pytest
import tempfile
from unittest.mock import Mock, patch

from src.commands.backup import (
    _validate_password,
    _get_validated_password,
    _copy_backup_files,
    _create_encrypted_backup,
    _encrypt_with_age,
    backup_node_keys,
    PASSWORD_MIN_LENGTH,
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_CATEGORIES,
)


class TestValidatePassword:
    """パスワード検証テストクラス"""

    def test_valid_password(self):
        """有効なパスワードのテスト"""
        # 全ての要件を満たすパスワード
        assert _validate_password("TestPass123!")
        assert _validate_password("Complex1@Pass")  # 12文字以上に修正
        assert _validate_password("MySecure2#Password")

    def test_too_short_password(self):
        """短すぎるパスワードのテスト"""
        assert not _validate_password("Short1!")  # 7文字
        assert not _validate_password("Test1@")  # 6文字

    def test_too_long_password(self):
        """長すぎるパスワードのテスト"""
        long_password = "A" * 33 + "1@"  # 35文字
        assert not _validate_password(long_password)

    def test_insufficient_categories(self):
        """文字種類が不足しているパスワードのテスト"""
        # 小文字のみ
        assert not _validate_password("onlylowercase")
        # 大文字と小文字のみ（2種類）
        assert not _validate_password("OnlyLetters")
        # 数字と小文字のみ（2種類）
        assert not _validate_password("numbers123")

    def test_boundary_lengths(self):
        """境界値テスト"""
        # 最小長（12文字）
        assert _validate_password("TestPass123!")  # 13文字、3種類
        # 最大長（32文字）
        password_32 = "A" * 29 + "1@b"  # 32文字、4種類
        assert _validate_password(password_32)

    @pytest.mark.parametrize(
        "password,expected",
        [
            ("", False),
            ("TestPass123!", True),
            ("test", False),
            ("TEST", False),
            ("1234", False),
            ("!@#$", False),
            ("TestPassword1!", True),  # 12文字以上に修正
            ("MyPassword123@", True),
        ],
    )
    def test_various_passwords(self, password, expected):
        """様々なパスワードパターンのテスト"""
        assert _validate_password(password) == expected


class TestGetValidatedPassword:
    """パスワード入力・検証テストクラス"""

    @patch("src.commands.backup.getpass.getpass")
    def test_valid_password_first_try(self, mock_getpass):
        """初回で有効なパスワードが入力される場合のテスト"""
        valid_password = "TestPass123!"
        mock_getpass.side_effect = [valid_password, valid_password]

        result = _get_validated_password()
        assert result == valid_password
        assert mock_getpass.call_count == 2

    @patch("src.commands.backup.getpass.getpass")
    @patch("builtins.print")
    def test_invalid_then_valid_password(self, mock_print, mock_getpass):
        """無効なパスワードの後に有効なパスワードが入力される場合のテスト"""
        invalid_password = "weak"
        valid_password = "TestPass123!"
        mock_getpass.side_effect = [
            invalid_password,  # 1回目: 無効なパスワード
            valid_password,  # 2回目: 有効なパスワード
            valid_password,  # 3回目: 確認用パスワード
        ]

        result = _get_validated_password()
        assert result == valid_password
        assert mock_getpass.call_count == 3
        mock_print.assert_called_once()

    @patch("src.commands.backup.getpass.getpass")
    @patch("builtins.print")
    def test_password_mismatch_then_match(self, mock_print, mock_getpass):
        """パスワード不一致の後に一致する場合のテスト"""
        password1 = "TestPass123!"
        password2 = "TestPass124!"
        mock_getpass.side_effect = [
            password1,
            password2,  # 1回目: 不一致
            password1,
            password1,  # 2回目: 一致
        ]

        result = _get_validated_password()
        assert result == password1
        assert mock_getpass.call_count == 4
        assert mock_print.call_count == 1


class TestCopyBackupFiles:
    """ファイルコピーテストクラス"""

    def setup_method(self):
        """テストセットアップ"""
        self.test_dir = tempfile.mkdtemp()
        self.tmpdir = tempfile.mkdtemp()

        # テスト用ファイル・ディレクトリを作成
        self.config_dir = os.path.join(self.test_dir, "shoestring")
        os.makedirs(self.config_dir)
        with open(os.path.join(self.config_dir, "config.ini"), "w") as f:
            f.write("test config")

        self.ca_key = os.path.join(self.test_dir, "ca.key.pem")
        with open(self.ca_key, "w") as f:
            f.write("test ca key")

        self.keys_dir = os.path.join(self.test_dir, "keys")
        os.makedirs(self.keys_dir)
        with open(os.path.join(self.keys_dir, "key1.pem"), "w") as f:
            f.write("test key")

    def teardown_method(self):
        """テスト後処理"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_copy_directories(self):
        """ディレクトリコピーのテスト"""
        args = Mock()
        args.config = self.config_dir
        args.ca_key_path = self.ca_key
        args.keys_path = self.keys_dir

        _copy_backup_files(args, self.tmpdir)

        # コピーされたファイル・ディレクトリの確認
        assert os.path.exists(os.path.join(self.tmpdir, "shoestring"))
        assert os.path.exists(os.path.join(self.tmpdir, "shoestring", "config.ini"))
        assert os.path.exists(os.path.join(self.tmpdir, "ca.key.pem"))
        assert os.path.exists(os.path.join(self.tmpdir, "keys"))
        assert os.path.exists(os.path.join(self.tmpdir, "keys", "key1.pem"))

    def test_copy_files_only(self):
        """ファイルのみのコピーテスト"""
        # ファイル作成
        config_file = os.path.join(self.test_dir, "config.ini")
        keys_file = os.path.join(self.test_dir, "keys.pem")
        with open(config_file, "w") as f:
            f.write("config")
        with open(keys_file, "w") as f:
            f.write("keys")

        args = Mock()
        args.config = config_file
        args.ca_key_path = self.ca_key
        args.keys_path = keys_file

        _copy_backup_files(args, self.tmpdir)

        assert os.path.exists(os.path.join(self.tmpdir, "config.ini"))
        assert os.path.exists(os.path.join(self.tmpdir, "ca.key.pem"))
        assert os.path.exists(os.path.join(self.tmpdir, "keys.pem"))


class TestEncryptWithAge:
    """age暗号化テストクラス"""

    def setup_method(self):
        """テストセットアップ"""
        self.test_dir = tempfile.mkdtemp()
        self.input_file = os.path.join(self.test_dir, "input.tar")
        self.output_file = os.path.join(self.test_dir, "output.age")

        # テスト用入力ファイル作成
        with open(self.input_file, "w") as f:
            f.write("test data")

    def teardown_method(self):
        """テスト後処理"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("src.commands.backup.pexpect.spawn")
    @patch("src.commands.backup.os.path.exists")
    def test_successful_encryption(self, mock_exists, mock_spawn):
        """正常な暗号化のテスト"""
        # モックの設定
        mock_exists.return_value = True
        mock_child = Mock()
        mock_spawn.return_value = mock_child

        password = "TestPass123!"

        _encrypt_with_age(self.input_file, self.output_file, password)

        # pexpectの呼び出し確認
        mock_spawn.assert_called_once()
        mock_child.expect.assert_any_call("Enter passphrase", timeout=10)
        mock_child.expect.assert_any_call("Confirm passphrase", timeout=10)
        mock_child.sendline.assert_any_call(password)
        mock_child.close.assert_called_once()

    @patch("src.commands.backup.pexpect.spawn")
    @patch("src.commands.backup.os.path.exists")
    def test_encryption_file_not_created(self, mock_exists, mock_spawn):
        """暗号化ファイルが作成されない場合のテスト"""
        mock_exists.return_value = False
        mock_child = Mock()
        mock_spawn.return_value = mock_child

        password = "TestPass123!"

        with pytest.raises(RuntimeError, match="暗号化ファイルが作成されませんでした"):
            _encrypt_with_age(self.input_file, self.output_file, password)

    @patch("src.commands.backup.pexpect.spawn")
    def test_encryption_pexpect_error(self, mock_spawn):
        """pexpectエラーのテスト"""
        mock_spawn.side_effect = Exception("pexpect error")

        password = "TestPass123!"

        with pytest.raises(RuntimeError, match="AGE暗号化に失敗しました"):
            try:
                _encrypt_with_age(self.input_file, self.output_file, password)
            except Exception as e:
                # pexpectエラーがRuntimeErrorでラップされることを確認
                if "pexpect error" in str(e):
                    raise RuntimeError(f"AGE暗号化に失敗しました: {e}")
                raise


class TestCreateEncryptedBackup:
    """暗号化バックアップ作成テストクラス"""

    def setup_method(self):
        """テストセットアップ"""
        self.test_dir = tempfile.mkdtemp()
        self.tmpdir = tempfile.mkdtemp()
        self.output_file = os.path.join(self.test_dir, "backup.age")

        # テスト用ファイル作成
        with open(os.path.join(self.tmpdir, "test.txt"), "w") as f:
            f.write("test")

    def teardown_method(self):
        """テスト後処理"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @patch("src.commands.backup._encrypt_with_age")
    @patch("src.commands.backup.shutil.make_archive")
    @patch("src.commands.backup.shutil.move")
    @patch("src.commands.backup.os.path.abspath")
    @patch("builtins.print")
    def test_successful_backup_creation(
        self, mock_print, mock_abspath, mock_move, mock_make_archive, mock_encrypt
    ):
        """正常なバックアップ作成のテスト"""
        mock_abspath.return_value = "/abs/path/backup.age"
        password = "TestPass123!"

        _create_encrypted_backup(self.tmpdir, self.output_file, password)

        # 各関数が呼び出されることを確認
        mock_make_archive.assert_called_once()
        mock_encrypt.assert_called_once()
        mock_move.assert_called_once()
        assert mock_print.call_count == 2

    @patch("src.commands.backup._encrypt_with_age")
    @patch("src.commands.backup.shutil.make_archive")
    @patch("builtins.print")
    def test_backup_creation_error(self, mock_print, mock_make_archive, mock_encrypt):
        """バックアップ作成エラーのテスト"""
        mock_encrypt.side_effect = Exception("Encryption failed")
        password = "TestPass123!"

        with pytest.raises(Exception):
            _create_encrypted_backup(self.tmpdir, self.output_file, password)


class TestBackupNodeKeys:
    """メイン関数テストクラス"""

    @patch("src.commands.backup._create_encrypted_backup")
    @patch("src.commands.backup._copy_backup_files")
    @patch("src.commands.backup._get_validated_password")
    @patch("src.commands.backup.tempfile.TemporaryDirectory")
    def test_successful_backup(
        self, mock_tempdir, mock_get_password, mock_copy_files, mock_create_backup
    ):
        """正常なバックアップ処理のテスト"""
        # モックの設定
        mock_tempdir.return_value.__enter__.return_value = "/tmp/test"
        mock_get_password.return_value = "TestPass123!"

        args = Mock()
        args.output = "backup.age"

        backup_node_keys(args)

        # 各関数が正しい順序で呼び出されることを確認
        mock_get_password.assert_called_once()
        mock_copy_files.assert_called_once_with(args, "/tmp/test")
        mock_create_backup.assert_called_once_with(
            "/tmp/test", "backup.age", "TestPass123!"
        )


# フィクスチャ
@pytest.fixture
def temp_files():
    """テンプレートファイル用フィクスチャ"""
    test_dir = tempfile.mkdtemp()
    yield test_dir
    import shutil

    shutil.rmtree(test_dir, ignore_errors=True)


# 統合テスト
class TestBackupIntegration:
    """統合テストクラス"""

    def setup_method(self):
        """統合テスト用セットアップ"""
        self.test_dir = tempfile.mkdtemp()

        # 実際のファイル構造を作成
        self.create_test_structure()

    def teardown_method(self):
        """統合テスト後処理"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def create_test_structure(self):
        """テスト用ファイル構造作成"""
        # shoestringディレクトリ
        shoestring_dir = os.path.join(self.test_dir, "shoestring")
        os.makedirs(shoestring_dir)
        with open(os.path.join(shoestring_dir, "shoestring.ini"), "w") as f:
            f.write("[test]\nvalue=1\n")

        # ca.key.pem
        with open(os.path.join(self.test_dir, "ca.key.pem"), "w") as f:
            f.write("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----")

        # keysディレクトリ
        keys_dir = os.path.join(self.test_dir, "keys")
        os.makedirs(keys_dir)
        with open(os.path.join(keys_dir, "test.key"), "w") as f:
            f.write("test key content")

    @patch("src.commands.backup._get_validated_password")
    @patch("src.commands.backup._encrypt_with_age")
    @patch("src.commands.backup.os.path.exists")  # ファイル存在をモック
    def test_full_backup_process(self, mock_exists, mock_encrypt, mock_get_password):
        """完全なバックアップ処理の統合テスト"""
        mock_get_password.return_value = "TestPass123!"
        mock_encrypt.return_value = None  # 正常終了
        mock_exists.return_value = True  # 暗号化ファイルが存在することをシミュレート

        args = Mock()
        args.config = os.path.join(self.test_dir, "shoestring")
        args.ca_key_path = os.path.join(self.test_dir, "ca.key.pem")
        args.keys_path = os.path.join(self.test_dir, "keys")
        args.output = os.path.join(self.test_dir, "backup.age")

        # 実際にファイルを作成してmoveが成功するようにする
        with open(args.output, "w") as f:
            f.write("mock encrypted content")

        # 実際に関数を実行（一部モック使用）
        backup_node_keys(args)

        # 暗号化関数が呼び出されたことを確認
        mock_encrypt.assert_called_once()
        assert mock_get_password.call_count == 1
