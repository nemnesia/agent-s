import os
import pytest
import tempfile
import tarfile
from unittest.mock import Mock, patch

from src.commands.restore import (
    _decrypt_age_file,
    _extract_tar_with_confirmation,
    _check_existing_files,
    _confirm_overwrite,
    _remove_existing_files,
    restore_node_keys,
)


class TestDecryptAgeFile:
    """age復号化テストクラス"""

    def setup_method(self):
        """テストセットアップ"""
        self.test_dir = tempfile.mkdtemp()
        self.input_file = os.path.join(self.test_dir, "input.age")
        self.output_file = os.path.join(self.test_dir, "output.tar")

        # テスト用入力ファイル作成
        with open(self.input_file, "w") as f:
            f.write("encrypted data")

    def teardown_method(self):
        """テスト後処理"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("src.commands.restore.pexpect.spawn")
    @patch("src.commands.restore.os.path.exists")
    def test_successful_decryption(self, mock_exists, mock_spawn):
        """正常な復号化のテスト"""
        # モックの設定
        mock_exists.return_value = True
        mock_child = Mock()
        mock_spawn.return_value = mock_child

        password = "TestPass123!"

        result = _decrypt_age_file(self.input_file, self.output_file, password)

        assert result is True
        # pexpectの呼び出し確認
        mock_spawn.assert_called_once()
        mock_child.expect.assert_any_call("Enter passphrase", timeout=10)
        mock_child.sendline.assert_called_once_with(password)
        mock_child.close.assert_called_once()

    @patch("src.commands.restore.pexpect.spawn")
    @patch("src.commands.restore.os.path.exists")
    def test_decryption_file_not_created(self, mock_exists, mock_spawn):
        """復号化ファイルが作成されない場合のテスト"""
        mock_exists.return_value = False
        mock_child = Mock()
        mock_spawn.return_value = mock_child

        password = "TestPass123!"

        result = _decrypt_age_file(self.input_file, self.output_file, password)

        assert result is False

    @patch("src.commands.restore.pexpect.spawn")
    @patch("builtins.print")
    def test_decryption_pexpect_error(self, mock_print, mock_spawn):
        """pexpectエラーのテスト"""
        mock_spawn.side_effect = Exception("pexpect error")

        password = "TestPass123!"

        result = _decrypt_age_file(self.input_file, self.output_file, password)

        assert result is False
        mock_print.assert_called_with("AGE復号化に失敗しました。")


class TestCheckExistingFiles:
    """既存ファイルチェックテストクラス"""

    def setup_method(self):
        """テストセットアップ"""
        self.test_dir = tempfile.mkdtemp()
        self.tar_path = os.path.join(self.test_dir, "test.tar")

        # テスト用tarファイル作成
        with tarfile.open(self.tar_path, "w") as tar:
            # テスト用ファイル作成
            file1 = os.path.join(self.test_dir, "file1.txt")
            file2 = os.path.join(self.test_dir, "file2.txt")
            with open(file1, "w") as f:
                f.write("content1")
            with open(file2, "w") as f:
                f.write("content2")
            tar.add(file1, arcname="file1.txt")
            tar.add(file2, arcname="file2.txt")

    def teardown_method(self):
        """テスト後処理"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_no_existing_files(self):
        """既存ファイルがない場合のテスト"""
        output_dir = tempfile.mkdtemp()
        try:
            with tarfile.open(self.tar_path, "r") as tar:
                existing_files = _check_existing_files(tar, output_dir)
            assert existing_files == []
        finally:
            import shutil

            shutil.rmtree(output_dir, ignore_errors=True)

    def test_existing_files_present(self):
        """既存ファイルがある場合のテスト"""
        output_dir = tempfile.mkdtemp()
        try:
            # 既存ファイルを作成
            existing_file = os.path.join(output_dir, "file1.txt")
            with open(existing_file, "w") as f:
                f.write("existing content")

            with tarfile.open(self.tar_path, "r") as tar:
                existing_files = _check_existing_files(tar, output_dir)

            assert "file1.txt" in existing_files
            assert "file2.txt" not in existing_files
        finally:
            import shutil

            shutil.rmtree(output_dir, ignore_errors=True)

    def test_all_files_existing(self):
        """全ファイルが既存の場合のテスト"""
        output_dir = tempfile.mkdtemp()
        try:
            # 全ての既存ファイルを作成
            for filename in ["file1.txt", "file2.txt"]:
                existing_file = os.path.join(output_dir, filename)
                with open(existing_file, "w") as f:
                    f.write("existing content")

            with tarfile.open(self.tar_path, "r") as tar:
                existing_files = _check_existing_files(tar, output_dir)

            assert len(existing_files) == 2
            assert "file1.txt" in existing_files
            assert "file2.txt" in existing_files
        finally:
            import shutil

            shutil.rmtree(output_dir, ignore_errors=True)


class TestConfirmOverwrite:
    """上書き確認テストクラス"""

    @patch("builtins.input")
    @patch("builtins.print")
    def test_confirm_yes(self, mock_print, mock_input):
        """yで上書き確認のテスト"""
        mock_input.return_value = "y"
        existing_files = ["file1.txt", "file2.txt"]

        result = _confirm_overwrite(existing_files)

        assert result is True
        mock_input.assert_called_once()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_confirm_no(self, mock_print, mock_input):
        """nで上書き拒否のテスト"""
        mock_input.return_value = "n"
        existing_files = ["file1.txt"]

        result = _confirm_overwrite(existing_files)

        assert result is False
        mock_input.assert_called_once()

    @patch("builtins.input")
    @patch("builtins.print")
    def test_confirm_yes_full_word(self, mock_print, mock_input):
        """yesで上書き確認のテスト"""
        mock_input.return_value = "yes"
        existing_files = ["file1.txt"]

        result = _confirm_overwrite(existing_files)

        assert result is True

    @patch("builtins.input")
    @patch("builtins.print")
    def test_confirm_no_full_word(self, mock_print, mock_input):
        """noで上書き拒否のテスト"""
        mock_input.return_value = "no"
        existing_files = ["file1.txt"]

        result = _confirm_overwrite(existing_files)

        assert result is False

    @patch("builtins.input")
    @patch("builtins.print")
    def test_confirm_invalid_then_yes(self, mock_print, mock_input):
        """無効な入力の後にyesのテスト"""
        mock_input.side_effect = ["invalid", "maybe", "y"]
        existing_files = ["file1.txt"]

        result = _confirm_overwrite(existing_files)

        assert result is True
        assert mock_input.call_count == 3

    def test_display_existing_files(self):
        """既存ファイルリスト表示のテスト"""
        with patch("builtins.print") as mock_print, patch(
            "builtins.input", return_value="y"
        ):
            existing_files = ["file1.txt", "file2.txt", "file3.txt"]

            _confirm_overwrite(existing_files)

            # print呼び出しの確認
            print_calls = mock_print.call_args_list
            assert any(
                "以下のファイルが既に存在します:" in str(call) for call in print_calls
            )
            assert any("file1.txt" in str(call) for call in print_calls)
            assert any("file2.txt" in str(call) for call in print_calls)


class TestRemoveExistingFiles:
    """既存ファイル削除テストクラス"""

    def setup_method(self):
        """テストセットアップ"""
        self.test_dir = tempfile.mkdtemp()

    def teardown_method(self):
        """テスト後処理"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    @patch("builtins.print")
    def test_remove_files_success(self, mock_print):
        """正常なファイル削除のテスト"""
        # テスト用ファイル作成
        test_files = ["file1.txt", "file2.txt"]
        for filename in test_files:
            filepath = os.path.join(self.test_dir, filename)
            with open(filepath, "w") as f:
                f.write("test content")

        _remove_existing_files(test_files, self.test_dir)

        # ファイルが削除されたことを確認
        for filename in test_files:
            filepath = os.path.join(self.test_dir, filename)
            assert not os.path.exists(filepath)

        mock_print.assert_called_once_with("既存ファイルを削除しています...")

    @patch("src.commands.restore.os.chmod")
    @patch("src.commands.restore.os.remove")
    @patch("builtins.print")
    def test_remove_readonly_files(self, mock_print, mock_remove, mock_chmod):
        """読み取り専用ファイル削除のテスト"""
        test_files = ["readonly.txt"]

        _remove_existing_files(test_files, self.test_dir)

        # chmod が呼び出されたことを確認
        mock_chmod.assert_called_once_with(
            os.path.join(self.test_dir, "readonly.txt"), 0o644
        )
        mock_remove.assert_called_once()

    @patch("src.commands.restore.os.chmod")
    @patch("src.commands.restore.os.remove")
    @patch("builtins.print")
    def test_remove_files_error(self, mock_print, mock_remove, mock_chmod):
        """ファイル削除エラーのテスト"""
        mock_remove.side_effect = OSError("Permission denied")
        test_files = ["error_file.txt"]

        with patch("src.commands.restore.logger") as mock_logger:
            _remove_existing_files(test_files, self.test_dir)

            # 警告ログが出力されたことを確認
            mock_logger.warning.assert_called_once()


class TestExtractTarWithConfirmation:
    """tar展開テストクラス"""

    def setup_method(self):
        """テストセットアップ"""
        self.test_dir = tempfile.mkdtemp()
        self.tar_path = os.path.join(self.test_dir, "test.tar")
        self.output_dir = tempfile.mkdtemp()

        # テスト用tarファイル作成
        test_content = {"file1.txt": "content1", "file2.txt": "content2"}
        with tarfile.open(self.tar_path, "w") as tar:
            for filename, content in test_content.items():
                temp_file = os.path.join(self.test_dir, filename)
                with open(temp_file, "w") as f:
                    f.write(content)
                tar.add(temp_file, arcname=filename)

    def teardown_method(self):
        """テスト後処理"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)
        shutil.rmtree(self.output_dir, ignore_errors=True)

    @patch("src.commands.restore._check_existing_files")
    @patch("builtins.print")
    def test_extract_no_existing_files(self, mock_print, mock_check):
        """既存ファイルがない場合の展開テスト"""
        mock_check.return_value = []

        _extract_tar_with_confirmation(self.tar_path, self.output_dir)

        # ファイルが展開されたことを確認
        assert os.path.exists(os.path.join(self.output_dir, "file1.txt"))
        assert os.path.exists(os.path.join(self.output_dir, "file2.txt"))

        # 成功メッセージが出力されたことを確認
        mock_print.assert_called_with(f"ファイルを復元しました: {self.output_dir}")

    @patch("src.commands.restore._check_existing_files")
    @patch("src.commands.restore._confirm_overwrite")
    @patch("src.commands.restore._remove_existing_files")
    @patch("builtins.print")
    def test_extract_with_overwrite_confirmed(
        self, mock_print, mock_remove, mock_confirm, mock_check
    ):
        """上書き確認ありで展開のテスト"""
        mock_check.return_value = ["file1.txt"]
        mock_confirm.return_value = True

        _extract_tar_with_confirmation(self.tar_path, self.output_dir)

        # 削除関数が呼び出されたことを確認
        mock_remove.assert_called_once_with(["file1.txt"], self.output_dir)
        # 成功メッセージが出力されたことを確認
        mock_print.assert_called_with(f"ファイルを復元しました: {self.output_dir}")

    @patch("src.commands.restore._check_existing_files")
    @patch("src.commands.restore._confirm_overwrite")
    @patch("builtins.print")
    def test_extract_with_overwrite_declined(
        self, mock_print, mock_confirm, mock_check
    ):
        """上書き拒否で展開中止のテスト"""
        mock_check.return_value = ["file1.txt"]
        mock_confirm.return_value = False

        _extract_tar_with_confirmation(self.tar_path, self.output_dir)

        # 中止メッセージが出力されたことを確認
        mock_print.assert_called_with("レストアを中止しました。")
        # ファイルが展開されていないことを確認
        assert not os.path.exists(os.path.join(self.output_dir, "file1.txt"))

    @patch("src.commands.restore.tarfile.open")
    @patch("builtins.print")
    def test_extract_tar_error(self, mock_print, mock_tar_open):
        """tar展開エラーのテスト"""
        mock_tar_open.side_effect = Exception("tar error")

        with patch("src.commands.restore.logger") as mock_logger:
            _extract_tar_with_confirmation(self.tar_path, self.output_dir)

            # エラーログとメッセージが出力されたことを確認
            mock_logger.error.assert_called_once()
            mock_print.assert_called_with("tar展開に失敗しました。")


class TestRestoreNodeKeys:
    """メイン関数テストクラス"""

    @patch("src.commands.restore._extract_tar_with_confirmation")
    @patch("src.commands.restore._decrypt_age_file")
    @patch("src.commands.restore.getpass.getpass")
    @patch("src.commands.restore.tempfile.TemporaryDirectory")
    def test_successful_restore(
        self, mock_tempdir, mock_getpass, mock_decrypt, mock_extract
    ):
        """正常なレストア処理のテスト"""
        # モックの設定
        mock_tempdir.return_value.__enter__.return_value = "/tmp/test"
        mock_getpass.return_value = "TestPass123!"
        mock_decrypt.return_value = True

        args = Mock()
        args.input = "backup.age"
        args.output = "."

        restore_node_keys(args)

        # 各関数が正しい順序で呼び出されることを確認
        mock_getpass.assert_called_once()
        mock_decrypt.assert_called_once_with(
            "backup.age", "/tmp/test/restored.tar", "TestPass123!"
        )
        mock_extract.assert_called_once_with("/tmp/test/restored.tar", ".")

    @patch("src.commands.restore._decrypt_age_file")
    @patch("src.commands.restore.getpass.getpass")
    @patch("src.commands.restore.tempfile.TemporaryDirectory")
    def test_restore_decrypt_failure(self, mock_tempdir, mock_getpass, mock_decrypt):
        """復号化失敗のテスト"""
        # モックの設定
        mock_tempdir.return_value.__enter__.return_value = "/tmp/test"
        mock_getpass.return_value = "TestPass123!"
        mock_decrypt.return_value = False  # 復号化失敗

        args = Mock()
        args.input = "backup.age"
        args.output = "."

        restore_node_keys(args)

        # 復号化関数のみ呼び出され、展開関数は呼び出されない
        mock_decrypt.assert_called_once()


# 統合テスト
class TestRestoreIntegration:
    """統合テストクラス"""

    def setup_method(self):
        """統合テスト用セットアップ"""
        self.test_dir = tempfile.mkdtemp()
        self.create_test_tar()

    def teardown_method(self):
        """統合テスト後処理"""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def create_test_tar(self):
        """テスト用tarファイル作成"""
        self.tar_path = os.path.join(self.test_dir, "test.tar")

        # テスト用ファイル構造作成
        test_files = {
            "shoestring/shoestring.ini": "[test]\nvalue=1\n",
            "ca.key.pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            "keys/test.key": "test key content",
        }

        with tarfile.open(self.tar_path, "w") as tar:
            for filename, content in test_files.items():
                # ディレクトリ作成
                file_dir = os.path.dirname(filename)
                if file_dir:
                    full_dir = os.path.join(self.test_dir, file_dir)
                    os.makedirs(full_dir, exist_ok=True)

                # ファイル作成
                full_path = os.path.join(self.test_dir, filename)
                with open(full_path, "w") as f:
                    f.write(content)

                tar.add(full_path, arcname=filename)

    @patch("src.commands.restore.getpass.getpass")
    @patch("src.commands.restore._decrypt_age_file")
    def test_full_restore_process(self, mock_decrypt, mock_getpass):
        """完全なレストア処理の統合テスト"""
        mock_getpass.return_value = "TestPass123!"
        mock_decrypt.return_value = True

        # 出力ディレクトリ
        output_dir = tempfile.mkdtemp()

        try:
            args = Mock()
            args.input = "backup.age"
            args.output = output_dir

            # _decrypt_age_file をモックして実際のtarファイルをコピー
            def mock_decrypt_side_effect(input_path, output_path, password):
                import shutil

                shutil.copy2(self.tar_path, output_path)
                return True

            mock_decrypt.side_effect = mock_decrypt_side_effect

            # 実際に関数を実行（復号化のみモック使用）
            restore_node_keys(args)

            # ファイルが正しく復元されたことを確認
            assert os.path.exists(
                os.path.join(output_dir, "shoestring", "shoestring.ini")
            )
            assert os.path.exists(os.path.join(output_dir, "ca.key.pem"))
            assert os.path.exists(os.path.join(output_dir, "keys", "test.key"))

            # 復号化関数が呼び出されたことを確認
            mock_decrypt.assert_called_once()
            assert mock_getpass.call_count == 1

        finally:
            import shutil

            shutil.rmtree(output_dir, ignore_errors=True)


# フィクスチャ
@pytest.fixture
def temp_files():
    """テンプレートファイル用フィクスチャ"""
    test_dir = tempfile.mkdtemp()
    yield test_dir
    import shutil

    shutil.rmtree(test_dir, ignore_errors=True)


# パラメータ化テスト
class TestParametrizedTests:
    """パラメータ化テストクラス"""

    @pytest.mark.parametrize(
        "user_input,expected",
        [
            ("y", True),
            ("yes", True),
            ("Y", True),
            ("YES", True),
            ("n", False),
            ("no", False),
            ("N", False),
            ("NO", False),
        ],
    )
    def test_confirm_overwrite_responses(self, user_input, expected):
        """様々な上書き確認レスポンスのテスト"""
        with patch("builtins.input", return_value=user_input), patch("builtins.print"):
            result = _confirm_overwrite(["test.txt"])
            assert result == expected

    @pytest.mark.parametrize(
        "file_count,expected_calls",
        [
            (1, 1),
            (3, 3),
            (5, 5),
            (10, 10),
        ],
    )
    def test_remove_files_call_count(self, file_count, expected_calls):
        """削除ファイル数に応じた呼び出し回数テスト"""
        test_files = [f"file{i}.txt" for i in range(file_count)]

        with patch("src.commands.restore.os.chmod") as mock_chmod, patch(
            "src.commands.restore.os.remove"
        ) as mock_remove, patch("builtins.print"):

            _remove_existing_files(test_files, "/test/dir")

            assert mock_chmod.call_count == expected_calls
            assert mock_remove.call_count == expected_calls
