"""show_key.pyモジュールのテスト"""

import argparse
import configparser
import pytest
import sys
import os
from io import StringIO
from unittest.mock import Mock, patch, MagicMock, mock_open, call

# プロジェクトルートをパスに追加
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

from cryptography import x509
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.facade.SymbolFacade import SymbolFacade, SymbolPublicAccount
from symbolchain.symbol.KeyPair import KeyPair

# テスト対象のモジュールをインポート
import commands.show_key as show_key


class TestGetNetworkName:
    """get_network_name関数のテストクラス"""

    def test_success_mainnet(self):
        """正常系テスト - mainnet取得"""
        mock_config = """
[network]
name = mainnet
"""
        with patch("builtins.open", mock_open(read_data=mock_config)):
            result = show_key.get_network_name("test.ini")
            assert result == "mainnet"

    def test_success_testnet(self):
        """正常系テスト - testnet取得"""
        mock_config = """
[network]  
name = testnet
"""
        with patch("builtins.open", mock_open(read_data=mock_config)):
            result = show_key.get_network_name("test.ini")
            assert result == "testnet"

    def test_fallback_to_default(self):
        """設定が見つからない場合のフォールバック"""
        mock_config = """
[other]
value = test
"""
        with patch("builtins.open", mock_open(read_data=mock_config)):
            result = show_key.get_network_name("test.ini")
            assert result == "testnet"

    def test_file_not_found(self):
        """ファイルが見つからない場合"""
        with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
            result = show_key.get_network_name("nonexistent.ini")
            assert result == "testnet"

    def test_config_parse_error(self):
        """設定ファイルの解析エラー"""
        with patch("builtins.open", mock_open(read_data="invalid config")):
            with patch(
                "configparser.ConfigParser.read", side_effect=Exception("Parse error")
            ):
                result = show_key.get_network_name("invalid.ini")
                assert result == "testnet"


class TestExtractPublicKeyFromCert:
    """_extract_public_key_from_cert関数のテストクラス"""

    def test_extract_public_key_success(self):
        """公開鍵抽出の正常系テスト"""
        mock_cert = Mock(spec=x509.Certificate)
        mock_public_key = Mock()
        # 32バイト + 12バイトヘッダ = 44バイトのダミーデータ
        mock_der_bytes = b"\\x00" * 44

        mock_public_key.public_bytes.return_value = mock_der_bytes
        mock_cert.public_key.return_value = mock_public_key

        result = show_key._extract_public_key_from_cert(mock_cert)

        # ヘッダの12バイトが削除されることを確認
        expected = mock_der_bytes[show_key.DER_PUBLIC_KEY_HEADER_SIZE :]
        assert result == expected

        mock_public_key.public_bytes.assert_called_once_with(
            encoding=show_key.serialization.Encoding.DER,
            format=show_key.serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class TestReadPublicKeysFromPemChain:
    """read_public_keys_from_pem_chain関数のテストクラス"""

    @patch("commands.show_key._extract_public_key_from_cert")
    @patch("commands.show_key.x509.load_pem_x509_certificate")
    def test_read_single_cert(self, mock_load_cert, mock_extract):
        """単一証明書の読み込みテスト"""
        mock_pem_data = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"DUMMY_CERT_DATA\n"
            b"-----END CERTIFICATE-----"
        )
        mock_cert = Mock(spec=x509.Certificate)
        mock_extract.return_value = b"extracted_key"
        mock_load_cert.return_value = mock_cert

        with patch("builtins.open", mock_open(read_data=mock_pem_data)):
            result = show_key.read_public_keys_from_pem_chain("test.pem")

        assert result == [b"extracted_key"]
        mock_load_cert.assert_called_once()
        mock_extract.assert_called_once_with(mock_cert)

    @patch("commands.show_key._extract_public_key_from_cert")
    @patch("commands.show_key.x509.load_pem_x509_certificate")
    def test_read_multiple_certs(self, mock_load_cert, mock_extract):
        """複数証明書の読み込みテスト"""
        mock_pem_data = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"CERT1_DATA\n"
            b"-----END CERTIFICATE-----"
            b"-----BEGIN CERTIFICATE-----\n"
            b"CERT2_DATA\n"
            b"-----END CERTIFICATE-----"
        )
        mock_cert1 = Mock(spec=x509.Certificate)
        mock_cert2 = Mock(spec=x509.Certificate)
        mock_extract.side_effect = [b"key1", b"key2"]
        mock_load_cert.side_effect = [mock_cert1, mock_cert2]

        with patch("builtins.open", mock_open(read_data=mock_pem_data)):
            result = show_key.read_public_keys_from_pem_chain("test.pem")

        assert result == [b"key1", b"key2"]
        assert mock_load_cert.call_count == 2
        assert mock_extract.call_count == 2

    def test_file_not_found(self):
        """ファイルが見つからない場合"""
        with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
            result = show_key.read_public_keys_from_pem_chain("nonexistent.pem")
            assert result == []

    @patch("commands.show_key.x509.load_pem_x509_certificate")
    def test_invalid_certificate(self, mock_load_cert):
        """無効な証明書の処理テスト"""
        mock_pem_data = (
            b"-----BEGIN CERTIFICATE-----\\n"
            b"INVALID_CERT_DATA\\n"
            b"-----END CERTIFICATE-----\\n"
        )
        mock_load_cert.side_effect = Exception("Invalid certificate")

        with patch("builtins.open", mock_open(read_data=mock_pem_data)):
            result = show_key.read_public_keys_from_pem_chain("test.pem")

        assert result == []

    def test_empty_file(self):
        """空ファイルの処理テスト"""
        with patch("builtins.open", mock_open(read_data=b"")):
            result = show_key.read_public_keys_from_pem_chain("empty.pem")
            assert result == []


class TestReadPrivateKeyFromPem:
    """read_private_key_from_pem関数のテストクラス"""

    @patch("commands.show_key.serialization.load_pem_private_key")
    def test_read_private_key_success(self, mock_load_key):
        """秘密鍵読み込みの正常系テスト"""
        mock_key_obj = Mock()
        # 32バイト + 16バイトヘッダ = 48バイトのダミーデータ
        mock_der_data = b"\\x00" * 48
        mock_key_obj.private_bytes.return_value = mock_der_data
        mock_load_key.return_value = mock_key_obj

        mock_pem_data = (
            b"-----BEGIN PRIVATE KEY-----\\nKEY_DATA\\n-----END PRIVATE KEY-----"
        )

        with patch("builtins.open", mock_open(read_data=mock_pem_data)):
            result = show_key.read_private_key_from_pem("test.pem")

        expected_hex = (
            mock_der_data[show_key.DER_PRIVATE_KEY_HEADER_SIZE :].hex().upper()
        )
        assert result == expected_hex

        mock_load_key.assert_called_once_with(
            mock_pem_data, password=None, backend=show_key.default_backend()
        )

    def test_file_not_found(self):
        """ファイルが見つからない場合"""
        with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
            result = show_key.read_private_key_from_pem("nonexistent.pem")
            assert result is None

    @patch("commands.show_key.serialization.load_pem_private_key")
    def test_invalid_private_key(self, mock_load_key):
        """無効な秘密鍵の処理テスト"""
        mock_load_key.side_effect = Exception("Invalid key")

        with patch("builtins.open", mock_open(read_data=b"invalid key data")):
            result = show_key.read_private_key_from_pem("invalid.pem")

        assert result is None


class TestCreateFacadeAndKeypair:
    """_create_facade_and_keypair関数のテストクラス"""

    @patch("commands.show_key.read_private_key_from_pem")
    @patch("commands.show_key.get_network_name")
    @patch("commands.show_key.SymbolFacade")
    @patch("commands.show_key.KeyPair")
    def test_success_with_private_key(
        self, mock_keypair_cls, mock_facade_cls, mock_get_network, mock_read_key
    ):
        """秘密鍵ありの正常系テスト"""
        mock_get_network.return_value = "testnet"
        # 32バイト（64文字）の有効な16進文字列を使用
        mock_read_key.return_value = "ABCD1234" * 8  # 64文字の16進文字列
        mock_facade = Mock(spec=SymbolFacade)
        mock_keypair = Mock(spec=KeyPair)
        mock_facade_cls.return_value = mock_facade
        mock_keypair_cls.return_value = mock_keypair

        result_facade, result_keypair = show_key._create_facade_and_keypair(
            "config.ini", "key.pem"
        )

        assert result_facade == mock_facade
        assert result_keypair == mock_keypair
        mock_facade_cls.assert_called_once_with("testnet")
        mock_keypair_cls.assert_called_once()

    @patch("commands.show_key.read_private_key_from_pem")
    @patch("commands.show_key.get_network_name")
    @patch("commands.show_key.SymbolFacade")
    def test_success_without_private_key(
        self, mock_facade_cls, mock_get_network, mock_read_key
    ):
        """秘密鍵なしの正常系テスト"""
        mock_get_network.return_value = "mainnet"
        mock_read_key.return_value = None
        mock_facade = Mock(spec=SymbolFacade)
        mock_facade_cls.return_value = mock_facade

        result_facade, result_keypair = show_key._create_facade_and_keypair(
            "config.ini", "key.pem"
        )

        assert result_facade == mock_facade
        assert result_keypair is None
        mock_facade_cls.assert_called_once_with("mainnet")


class TestGetCertPublicKeyInfo:
    """_get_cert_public_key_info関数のテストクラス"""

    @patch("commands.show_key.read_public_keys_from_pem_chain")
    @patch("commands.show_key.PublicKey")
    def test_success(self, mock_publickey_cls, mock_read_keys):
        """正常系テスト"""
        mock_read_keys.return_value = [b"key1", b"key2"]
        mock_public_key = Mock(spec=PublicKey)
        mock_publickey_cls.return_value = mock_public_key
        mock_facade = Mock(spec=SymbolFacade)
        mock_account = Mock(spec=SymbolPublicAccount)
        mock_facade.create_public_account.return_value = mock_account

        result_key, result_account = show_key._get_cert_public_key_info(
            "keys", 1, "test", mock_facade
        )

        assert result_key == mock_public_key
        assert result_account == mock_account
        mock_read_keys.assert_called_once_with("keys/cert/node.full.crt.pem")
        mock_publickey_cls.assert_called_once_with(b"key2")  # インデックス1

    @patch("commands.show_key.read_public_keys_from_pem_chain")
    def test_no_keys_found(self, mock_read_keys):
        """公開鍵が見つからない場合"""
        mock_read_keys.return_value = []
        mock_facade = Mock(spec=SymbolFacade)

        result_key, result_account = show_key._get_cert_public_key_info(
            "keys", 0, "test", mock_facade
        )

        assert result_key is None
        assert result_account is None

    @patch("commands.show_key.read_public_keys_from_pem_chain")
    def test_index_out_of_range(self, mock_read_keys):
        """インデックスが範囲外の場合"""
        mock_read_keys.return_value = [b"key1"]
        mock_facade = Mock(spec=SymbolFacade)

        result_key, result_account = show_key._get_cert_public_key_info(
            "keys", 5, "test", mock_facade
        )

        assert result_key is None
        assert result_account is None


class TestValidateKeyConsistency:
    """_validate_key_consistency関数のテストクラス"""

    def test_keys_match(self):
        """キーが一致する場合"""
        mock_key1 = Mock(spec=PublicKey)
        mock_key2 = Mock(spec=PublicKey)
        mock_key1.__eq__ = Mock(return_value=True)

        result = show_key._validate_key_consistency(mock_key1, mock_key2, "test")
        assert result is True

    def test_keys_dont_match(self):
        """キーが一致しない場合"""
        mock_key1 = Mock(spec=PublicKey)
        mock_key2 = Mock(spec=PublicKey)
        mock_key1.__eq__ = Mock(return_value=False)

        result = show_key._validate_key_consistency(mock_key1, mock_key2, "test")
        assert result is False

    def test_private_key_none(self):
        """秘密鍵がNoneの場合"""
        mock_key2 = Mock(spec=PublicKey)

        result = show_key._validate_key_consistency(None, mock_key2, "test")
        assert result is True

    def test_cert_key_none(self):
        """証明書キーがNoneの場合"""
        mock_key1 = Mock(spec=PublicKey)

        result = show_key._validate_key_consistency(mock_key1, None, "test")
        assert result is True

    def test_both_keys_none(self):
        """両方のキーがNoneの場合"""
        result = show_key._validate_key_consistency(None, None, "test")
        assert result is True


class TestDisplayAccountInfo:
    """_display_account_info関数のテストクラス"""

    def test_display_with_cert_account(self, capsys):
        """証明書アカウントありの表示テスト"""
        mock_cert_account = Mock(spec=SymbolPublicAccount)
        mock_cert_account.address = "TEST_ADDRESS"
        mock_cert_key = Mock(spec=PublicKey)
        mock_cert_key.__str__ = Mock(return_value="TEST_PUBLIC_KEY")
        mock_facade = Mock(spec=SymbolFacade)

        show_key._display_account_info(
            "テスト",
            mock_cert_account,
            mock_cert_key,
            None,
            "PRIVATE_KEY_HEX",
            True,
            mock_facade,
        )

        captured = capsys.readouterr()
        assert "テストアカウント情報:" in captured.out
        assert "TEST_ADDRESS" in captured.out
        assert "TEST_PUBLIC_KEY" in captured.out
        assert "PRIVATE_KEY_HEX" in captured.out

    def test_display_with_private_key_only(self, capsys):
        """秘密鍵のみの表示テスト"""
        mock_private_key = Mock(spec=PublicKey)
        mock_private_key.__str__ = Mock(return_value="PRIVATE_PUBLIC_KEY")
        mock_facade = Mock(spec=SymbolFacade)
        mock_account = Mock(spec=SymbolPublicAccount)
        mock_account.address = "PRIVATE_ADDRESS"
        mock_facade.create_public_account.return_value = mock_account

        show_key._display_account_info(
            "リモート", None, None, mock_private_key, None, False, mock_facade
        )

        captured = capsys.readouterr()
        assert "リモートアカウント情報:" in captured.out
        assert "PRIVATE_ADDRESS" in captured.out
        assert "PRIVATE_PUBLIC_KEY" in captured.out
        assert "秘密鍵" not in captured.out  # show_private_key=Falseなので表示されない

    def test_display_no_keys(self, capsys):
        """キーが見つからない場合の表示テスト"""
        mock_facade = Mock(spec=SymbolFacade)

        show_key._display_account_info(
            "エラー", None, None, None, None, False, mock_facade
        )

        captured = capsys.readouterr()
        assert "エラーアカウント情報:" in captured.out
        assert "エラーキーの秘密鍵が読み込めませんでした。" in captured.out


class TestShowAccountInfo:
    """show_account_info関数のテストクラス"""

    @patch("commands.show_key._display_account_info")
    @patch("commands.show_key._validate_key_consistency")
    @patch("commands.show_key._get_cert_public_key_info")
    @patch("commands.show_key._create_facade_and_keypair")
    def test_main_account_success(
        self, mock_create, mock_get_cert, mock_validate, mock_display
    ):
        """メインアカウント表示の正常系テスト"""
        mock_args = Mock()
        mock_args.config = "config.ini"
        mock_args.keys_path = "keys"
        mock_args.show_private_key = True

        mock_facade = Mock(spec=SymbolFacade)
        mock_keypair = Mock(spec=KeyPair)
        mock_keypair.public_key = Mock(spec=PublicKey)
        mock_keypair.private_key.bytes.hex.return_value = "private_hex"
        mock_create.return_value = (mock_facade, mock_keypair)

        mock_cert_key = Mock(spec=PublicKey)
        mock_cert_account = Mock(spec=SymbolPublicAccount)
        mock_get_cert.return_value = (mock_cert_key, mock_cert_account)

        mock_validate.return_value = True

        show_key.show_account_info(mock_args, "main", "ca.key.pem", 1, "メイン")

        mock_create.assert_called_once_with("config.ini", "ca.key.pem")
        mock_get_cert.assert_called_once_with("keys", 1, "メイン", mock_facade)
        mock_validate.assert_called_once()
        mock_display.assert_called_once()

    @patch("commands.show_key._create_facade_and_keypair")
    def test_remote_account_no_cert(self, mock_create, capsys):
        """リモートアカウント（証明書なし）の正常系テスト"""
        mock_args = Mock()
        mock_args.config = "config.ini"
        mock_args.show_private_key = False

        mock_facade = Mock(spec=SymbolFacade)
        mock_keypair = Mock(spec=KeyPair)
        mock_create.return_value = (mock_facade, mock_keypair)

        with patch("commands.show_key._display_account_info") as mock_display:
            show_key.show_account_info(
                mock_args, "remote", "remote.pem", None, "リモート"
            )

        mock_create.assert_called_once_with("config.ini", "remote.pem")
        mock_display.assert_called_once()

    @patch("commands.show_key._get_cert_public_key_info")
    @patch("commands.show_key._create_facade_and_keypair")
    def test_cert_key_not_found(self, mock_create, mock_get_cert, capsys):
        """証明書キーが見つからない場合"""
        mock_args = Mock()
        mock_facade = Mock(spec=SymbolFacade)
        mock_keypair = Mock(spec=KeyPair)
        mock_create.return_value = (mock_facade, mock_keypair)
        mock_get_cert.return_value = (None, None)

        show_key.show_account_info(mock_args, "main", "ca.key.pem", 1, "メイン")

        captured = capsys.readouterr()
        assert "証明書からメイン公開鍵の取得に失敗しました。" in captured.out

    @patch("commands.show_key._validate_key_consistency")
    @patch("commands.show_key._get_cert_public_key_info")
    @patch("commands.show_key._create_facade_and_keypair")
    def test_key_validation_failure(
        self, mock_create, mock_get_cert, mock_validate, capsys
    ):
        """キー検証失敗の場合"""
        mock_args = Mock()
        mock_facade = Mock(spec=SymbolFacade)
        mock_keypair = Mock(spec=KeyPair)
        mock_create.return_value = (mock_facade, mock_keypair)
        mock_get_cert.return_value = (
            Mock(spec=PublicKey),
            Mock(spec=SymbolPublicAccount),
        )
        mock_validate.return_value = False

        show_key.show_account_info(mock_args, "main", "ca.key.pem", 1, "メイン")

        captured = capsys.readouterr()
        assert "メイン証明書の秘密鍵と公開鍵が一致しません。" in captured.out

    @patch("commands.show_key._create_facade_and_keypair")
    def test_exception_handling(self, mock_create, capsys):
        """例外処理のテスト"""
        mock_args = Mock()
        mock_create.side_effect = Exception("Test error")

        show_key.show_account_info(mock_args, "main", "ca.key.pem", 1, "メイン")

        captured = capsys.readouterr()
        assert "メインアカウント情報の取得に失敗しました。" in captured.out


class TestShowFunctions:
    """show_main, show_node, show_remote, show_vrf関数のテストクラス"""

    @patch("commands.show_key.show_account_info")
    def test_show_main(self, mock_show_account_info):
        """show_main関数のテスト"""
        mock_args = Mock()
        mock_args.ca_key_path = "ca.key.pem"

        show_key.show_main(mock_args)

        mock_show_account_info.assert_called_once_with(
            mock_args, "main", "ca.key.pem", 1, "メイン"
        )

    @patch("commands.show_key.show_account_info")
    def test_show_node(self, mock_show_account_info):
        """show_node関数のテスト"""
        mock_args = Mock()
        mock_args.keys_path = "keys"

        show_key.show_node(mock_args)

        mock_show_account_info.assert_called_once_with(
            mock_args, "node", "keys/cert/node.key.pem", 0, "ノード"
        )

    @patch("commands.show_key.show_account_info")
    def test_show_remote(self, mock_show_account_info):
        """show_remote関数のテスト"""
        mock_args = Mock()
        mock_args.keys_path = "keys"

        show_key.show_remote(mock_args)

        mock_show_account_info.assert_called_once_with(
            mock_args, "remote", "keys/remote.pem", None, "リモート"
        )

    @patch("commands.show_key.show_account_info")
    def test_show_vrf(self, mock_show_account_info):
        """show_vrf関数のテスト"""
        mock_args = Mock()
        mock_args.keys_path = "keys"

        show_key.show_vrf(mock_args)

        mock_show_account_info.assert_called_once_with(
            mock_args, "vrf", "keys/vrf.pem", None, "VRF"
        )


class TestGetCommonShowkeyArgs:
    """get_common_showkey_args関数のテストクラス"""

    def test_parser_creation(self):
        """ArgumentParserの作成テスト"""
        parser = show_key.get_common_showkey_args()

        assert isinstance(parser, argparse.ArgumentParser)
        assert parser.add_help is False

    def test_default_arguments(self):
        """デフォルト引数のテスト"""
        parser = show_key.get_common_showkey_args()

        args = parser.parse_args([])

        assert args.config == show_key.DEFAULT_CONFIG_PATH
        assert args.ca_key_path == show_key.DEFAULT_CA_KEY_PATH
        assert args.keys_path == show_key.DEFAULT_KEYS_PATH
        assert args.show_private_key is False

    def test_custom_arguments(self):
        """カスタム引数のテスト"""
        parser = show_key.get_common_showkey_args()

        args = parser.parse_args(
            [
                "--config",
                "custom.ini",
                "--ca-key-path",
                "custom_ca.pem",
                "--keys-path",
                "custom_keys",
                "--show-private-key",
            ]
        )

        assert args.config == "custom.ini"
        assert args.ca_key_path == "custom_ca.pem"
        assert args.keys_path == "custom_keys"
        assert args.show_private_key is True

    def test_short_arguments(self):
        """短縮引数のテスト"""
        parser = show_key.get_common_showkey_args()

        args = parser.parse_args(
            ["-c", "short.ini", "-ca", "short_ca.pem", "-k", "short_keys", "-p"]
        )

        assert args.config == "short.ini"
        assert args.ca_key_path == "short_ca.pem"
        assert args.keys_path == "short_keys"
        assert args.show_private_key is True


class TestCreateSubparser:
    """_create_subparser関数のテストクラス"""

    def test_create_subparser(self):
        """サブパーサー作成のテスト"""
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()
        common_args = [show_key.get_common_showkey_args()]

        def dummy_func():
            pass

        show_key._create_subparser(
            subparsers, "test", "Test command", dummy_func, common_args
        )

        # testサブコマンドでパース
        args = main_parser.parse_args(["test"])
        assert args.func == dummy_func


class TestSetupShowKeySubparser:
    """setup_show_key_subparser関数のテストクラス"""

    def test_subparser_setup(self):
        """サブパーサー設定のテスト"""
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        show_key.setup_show_key_subparser(subparsers)

        # show-key mainサブコマンドでパース
        args = main_parser.parse_args(["show-key", "main"])
        assert args.func == show_key.show_main

        # show-key nodeサブコマンドでパース
        args = main_parser.parse_args(["show-key", "node"])
        assert args.func == show_key.show_node

        # show-key remoteサブコマンドでパース
        args = main_parser.parse_args(["show-key", "remote"])
        assert args.func == show_key.show_remote

        # show-key vrfサブコマンドでパース
        args = main_parser.parse_args(["show-key", "vrf"])
        assert args.func == show_key.show_vrf

    def test_subparser_with_arguments(self):
        """サブパーサーと引数のテスト"""
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        show_key.setup_show_key_subparser(subparsers)

        args = main_parser.parse_args(
            ["show-key", "main", "--config", "test.ini", "--show-private-key"]
        )

        assert args.func == show_key.show_main
        assert args.config == "test.ini"
        assert args.show_private_key is True


class TestConstants:
    """定数のテストクラス"""

    def test_constants(self):
        """定数のテスト"""
        assert show_key.NODE_KEY_PEM == "/cert/node.key.pem"
        assert show_key.REMOTE_KEY_PEM == "/remote.pem"
        assert show_key.VRF_KEY_PEM == "/vrf.pem"
        assert show_key.NODE_FULL_CERT_PEM == "/cert/node.full.crt.pem"
        assert show_key.DEFAULT_CONFIG_PATH == "shoestring/shoestring.ini"
        assert show_key.DEFAULT_CA_KEY_PATH == "ca.key.pem"
        assert show_key.DEFAULT_KEYS_PATH == "keys"
        assert show_key.DER_PUBLIC_KEY_HEADER_SIZE == 12
        assert show_key.DER_PRIVATE_KEY_HEADER_SIZE == 16


class TestEdgeCases:
    """エッジケースと境界値のテストクラス"""

    def test_get_network_name_empty_config(self):
        """空の設定ファイルのテスト"""
        with patch("builtins.open", mock_open(read_data="")):
            result = show_key.get_network_name("empty.ini")
            assert result == "testnet"  # デフォルト値

    def test_get_network_name_malformed_config(self):
        """不正な形式の設定ファイルのテスト"""
        malformed_config = """
[network
name = mainnet
"""
        with patch("builtins.open", mock_open(read_data=malformed_config)):
            result = show_key.get_network_name("malformed.ini")
            assert result == "testnet"  # デフォルト値

    @patch("os.path.exists", return_value=False)
    def test_read_private_key_from_pem_file_not_exists(self, mock_exists):
        """存在しないPEMファイルの読み込みテスト"""
        result = show_key.read_private_key_from_pem("nonexistent.pem")
        assert result is None

    def test_read_private_key_from_pem_invalid_format(self):
        """無効な形式のPEMファイルのテスト"""
        invalid_pem = "INVALID PEM DATA"
        with patch("builtins.open", mock_open(read_data=invalid_pem)):
            with patch("os.path.exists", return_value=True):
                result = show_key.read_private_key_from_pem("invalid.pem")
                assert result is None

    @patch("os.path.exists", return_value=False)
    def test_read_public_keys_from_pem_chain_file_not_exists(self, mock_exists):
        """存在しないチェーン証明書ファイルの読み込みテスト"""
        result = show_key.read_public_keys_from_pem_chain("nonexistent.pem")
        assert result == []

    def test_read_public_keys_from_pem_chain_invalid_format(self):
        """無効な形式のチェーン証明書ファイルのテスト"""
        invalid_cert = "INVALID CERT DATA"
        with patch("builtins.open", mock_open(read_data=invalid_cert)):
            with patch("os.path.exists", return_value=True):
                result = show_key.read_public_keys_from_pem_chain("invalid.pem")
                assert result == []


class TestErrorHandling:
    """エラーハンドリングのテストクラス"""

    def test_get_network_name_permission_error(self):
        """設定ファイルのアクセス権限エラーのテスト"""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            result = show_key.get_network_name("protected.ini")
            assert result == "testnet"  # デフォルト値

    def test_get_network_name_io_error(self):
        """設定ファイルのI/Oエラーのテスト"""
        with patch("builtins.open", side_effect=IOError("IO Error")):
            result = show_key.get_network_name("error.ini")
            assert result == "testnet"  # デフォルト値

    def test_read_private_key_from_pem_permission_error(self):
        """秘密鍵ファイルのアクセス権限エラーのテスト"""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with patch("os.path.exists", return_value=True):
                result = show_key.read_private_key_from_pem("protected.pem")
                assert result is None

    def test_read_private_key_from_pem_io_error(self):
        """秘密鍵ファイルのI/Oエラーのテスト"""
        with patch("builtins.open", side_effect=IOError("IO Error")):
            with patch("os.path.exists", return_value=True):
                result = show_key.read_private_key_from_pem("error.pem")
                assert result is None


class TestIntegration:
    """統合テストクラス"""

    @patch("commands.show_key.get_network_name", return_value="testnet")
    @patch("commands.show_key.read_private_key_from_pem", return_value="ABCD1234")
    @patch(
        "commands.show_key.read_public_keys_from_pem_chain",
        return_value=[b"PUBKEY1", b"PUBKEY2"],
    )
    @patch("commands.show_key.PublicKey")
    @patch("commands.show_key.SymbolFacade")
    @patch("commands.show_key.PrivateKey")
    @patch("commands.show_key.KeyPair")
    def test_show_main_integration(
        self,
        mock_keypair_cls,
        mock_privkey_cls,
        mock_facade_cls,
        mock_pubkey_cls,
        mock_read_pub_keys,
        mock_read_priv_key,
        mock_get_network,
    ):
        """show_main関数の統合テスト"""
        # モックの設定
        mock_facade_instance = Mock()
        mock_facade_cls.return_value = mock_facade_instance

        mock_private_key = Mock()
        mock_privkey_cls.return_value = mock_private_key

        # 共通の公開鍵インスタンスを作成（秘密鍵と証明書で同じものを使用）
        mock_public_key_shared = Mock()

        mock_keypair = Mock()
        mock_keypair.public_key = mock_public_key_shared
        mock_keypair.private_key.bytes.hex.return_value = "ABCD1234"
        mock_keypair_cls.return_value = mock_keypair

        # 証明書からの公開鍵も同じインスタンスを使用
        mock_pubkey_cls.return_value = mock_public_key_shared

        mock_account = Mock()
        mock_account.address = "TESTADDRESS123"
        mock_facade_instance.create_public_account.return_value = mock_account

        # Argsの設定
        args = Mock()
        args.config = "test.ini"
        args.ca_key_path = "ca.key.pem"
        args.keys_path = "keys"
        args.show_private_key = False

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            show_key.show_main(args)
            output = mock_stdout.getvalue()

            # 出力に期待される文字列が含まれていることを確認
            assert "メインアカウント情報:" in output

    @patch("commands.show_key.get_network_name", return_value="testnet")
    @patch("commands.show_key.read_private_key_from_pem", return_value="ABCD1234")
    @patch(
        "commands.show_key.read_public_keys_from_pem_chain",
        return_value=[b"PUBKEY1", b"PUBKEY2"],
    )
    @patch("commands.show_key.PublicKey")
    @patch("commands.show_key.SymbolFacade")
    @patch("commands.show_key.PrivateKey")
    @patch("commands.show_key.KeyPair")
    def test_show_node_integration(
        self,
        mock_keypair_cls,
        mock_privkey_cls,
        mock_facade_cls,
        mock_pubkey_cls,
        mock_read_pub_keys,
        mock_read_priv_key,
        mock_get_network,
    ):
        """show_node関数の統合テスト"""
        # モックの設定
        mock_facade_instance = Mock()
        mock_facade_cls.return_value = mock_facade_instance

        mock_private_key = Mock()
        mock_privkey_cls.return_value = mock_private_key

        # 共通の公開鍵インスタンスを作成（秘密鍵と証明書で同じものを使用）
        mock_public_key_shared = Mock()

        mock_keypair = Mock()
        mock_keypair.public_key = mock_public_key_shared
        mock_keypair.private_key.bytes.hex.return_value = "ABCD1234"
        mock_keypair_cls.return_value = mock_keypair

        # 証明書からの公開鍵も同じインスタンスを使用
        mock_pubkey_cls.return_value = mock_public_key_shared

        mock_account = Mock()
        mock_account.address = "TESTADDRESS123"
        mock_facade_instance.create_public_account.return_value = mock_account

        # Argsの設定
        args = Mock()
        args.config = "test.ini"
        args.keys_path = "keys"
        args.show_private_key = False

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            show_key.show_node(args)
            output = mock_stdout.getvalue()

            # 出力に期待される文字列が含まれていることを確認
            assert "ノードアカウント情報:" in output

    @patch("commands.show_key.get_network_name", return_value="testnet")
    @patch("commands.show_key.read_private_key_from_pem", return_value="ABCD1234")
    @patch("commands.show_key.KeyPair")
    @patch("commands.show_key.SymbolFacade")
    @patch("commands.show_key.PrivateKey")
    def test_show_remote_integration(
        self,
        mock_privkey_cls,
        mock_facade_cls,
        mock_keypair_cls,
        mock_read_priv_key,
        mock_get_network,
    ):
        """show_remote関数の統合テスト"""
        # モックの設定
        mock_facade_instance = Mock()
        mock_facade_cls.return_value = mock_facade_instance

        mock_private_key = Mock()
        mock_privkey_cls.return_value = mock_private_key

        mock_keypair = Mock()
        mock_keypair.public_key = Mock()
        mock_keypair.private_key.bytes.hex.return_value = "abcd1234"
        mock_keypair_cls.return_value = mock_keypair

        mock_account = Mock()
        mock_account.address = "TESTADDRESS123"
        mock_facade_instance.create_public_account.return_value = mock_account

        # Argsの設定
        args = Mock()
        args.config = "test.ini"
        args.keys_path = "keys"
        args.show_private_key = False

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            show_key.show_remote(args)
            output = mock_stdout.getvalue()

            # 出力に期待される文字列が含まれていることを確認
            assert "リモートアカウント情報:" in output

    @patch("commands.show_key.get_network_name", return_value="testnet")
    @patch("commands.show_key.read_private_key_from_pem", return_value="ABCD1234")
    @patch("commands.show_key.KeyPair")
    @patch("commands.show_key.SymbolFacade")
    @patch("commands.show_key.PrivateKey")
    def test_show_vrf_integration(
        self,
        mock_privkey_cls,
        mock_facade_cls,
        mock_keypair_cls,
        mock_read_priv_key,
        mock_get_network,
    ):
        """show_vrf関数の統合テスト"""
        # モックの設定
        mock_facade_instance = Mock()
        mock_facade_cls.return_value = mock_facade_instance

        mock_private_key = Mock()
        mock_privkey_cls.return_value = mock_private_key

        mock_keypair = Mock()
        mock_keypair.public_key = Mock()
        mock_keypair.private_key.bytes.hex.return_value = "abcd1234"
        mock_keypair_cls.return_value = mock_keypair

        mock_account = Mock()
        mock_account.address = "TESTADDRESS123"
        mock_facade_instance.create_public_account.return_value = mock_account

        # Argsの設定
        args = Mock()
        args.config = "test.ini"
        args.keys_path = "keys"
        args.show_private_key = False

        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            show_key.show_vrf(args)
            output = mock_stdout.getvalue()

            # 出力に期待される文字列が含まれていることを確認
            assert "VRFアカウント情報:" in output


if __name__ == "__main__":
    pytest.main([__file__])
