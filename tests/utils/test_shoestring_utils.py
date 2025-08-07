import pytest
import configparser
from unittest.mock import patch, mock_open, Mock, MagicMock
from src.utils import shoestring_utils
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from symbolchain.CryptoTypes import PrivateKey
from symbolchain.symbol.KeyPair import KeyPair


class TestGetNetworkName:
    """get_network_nameのテストクラス"""

    # 正常系のテスト（設定ファイルが存在し、networkセクションがある場合）
    def test_get_network_name_valid(self):
        mock_config_content = """
[network]
name = mainnet
"""
        with patch("builtins.open", mock_open(read_data=mock_config_content)):
            result = shoestring_utils.get_network_name("valid_config.ini")
            assert result == "mainnet"

    # 正常系のテスト（networkセクションはあるがnameが無い場合、fallbackを使用）
    def test_get_network_name_fallback(self):
        mock_config_content = """
[network]
other_setting = value
"""
        with patch("builtins.open", mock_open(read_data=mock_config_content)):
            result = shoestring_utils.get_network_name("config.ini")
            assert result == "testnet"

    # 正常系のテスト（networkセクションが存在しない場合、fallbackを使用）
    def test_get_network_name_no_network_section(self):
        mock_config_content = """
[other_section]
setting = value
"""
        with patch("builtins.open", mock_open(read_data=mock_config_content)):
            result = shoestring_utils.get_network_name("config.ini")
            assert result == "testnet"

    # 異常系のテスト（ファイルが存在しない場合）
    def test_get_network_name_file_not_found(self):
        result = shoestring_utils.get_network_name("not_exist.ini")
        assert result == "testnet"

    # 異常系のテスト（無効なconfig形式）
    def test_get_network_name_invalid_config(self):
        mock_config_content = "invalid config content"
        with patch("builtins.open", mock_open(read_data=mock_config_content)):
            result = shoestring_utils.get_network_name("invalid_config.ini")
            assert result == "testnet"

    # 異常系のテスト（configparser.Errorが発生した場合）
    def test_get_network_name_config_parser_error(self):
        with patch("configparser.ConfigParser") as mock_parser:
            mock_instance = Mock()
            # configparser.Errorは実装でcatchされているのでこちらを使用
            import configparser

            mock_instance.read.side_effect = configparser.Error("ConfigParser Error")
            mock_parser.return_value = mock_instance
            result = shoestring_utils.get_network_name("error_config.ini")
            assert result == "testnet"

    # 異常系のテスト（OSErrorが発生した場合）
    def test_get_network_name_os_error(self):
        with patch("builtins.open", side_effect=OSError("Permission denied")):
            result = shoestring_utils.get_network_name("permission_denied.ini")
            assert result == "testnet"


class TestExtractPrivateKeyBytes:
    """_extract_private_key_bytesのテストクラス"""

    def test_extract_private_key_bytes_success(self):
        # モックの秘密鍵オブジェクトを作成
        mock_private_key = Mock()
        mock_der_bytes = (
            b"\x00" * 16 + b"\x12\x34\x56\x78"
        )  # 16バイトのプレフィックス + 実際のデータ
        mock_private_key.private_bytes.return_value = mock_der_bytes

        result = shoestring_utils._extract_private_key_bytes(mock_private_key)

        # プレフィックス16バイト削除後の16進文字列を確認
        assert result == "12345678"
        # 呼び出されたかどうかの確認（引数の詳細比較はNoEncryptionインスタンスが異なるため省略）
        assert mock_private_key.private_bytes.call_count == 1


class TestGetKeyPair:
    """get_key_pairのテストクラス"""

    # 正常系のテスト（有効なPEMファイル）
    def test_get_key_pair_success(self):
        mock_pem_content = (
            b"-----BEGIN PRIVATE KEY-----\nvalidcontent\n-----END PRIVATE KEY-----"
        )
        mock_private_key_obj = Mock()
        mock_der_bytes = b"\x00" * 16 + b"\x12\x34\x56\x78"
        mock_private_key_obj.private_bytes.return_value = mock_der_bytes

        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.serialization.load_pem_private_key",
                return_value=mock_private_key_obj,
            ):
                with patch(
                    "src.utils.shoestring_utils.PrivateKey"
                ) as mock_private_key_class:
                    with patch(
                        "src.utils.shoestring_utils.KeyPair"
                    ) as mock_key_pair_class:
                        mock_key_pair_instance = Mock()
                        mock_key_pair_class.return_value = mock_key_pair_instance

                        result = shoestring_utils.get_key_pair("valid.pem")

                        assert result == mock_key_pair_instance
                        mock_private_key_class.assert_called_once_with("12345678")
                        mock_key_pair_class.assert_called_once()

    # 異常系のテスト（ファイルが存在しない場合）
    def test_get_key_pair_file_not_found(self):
        result = shoestring_utils.get_key_pair("not_exist.pem")
        assert result is None

    # 異常系のテスト（無効なPEMファイル - ValueError）
    def test_get_key_pair_invalid_pem_value_error(self):
        mock_pem_content = b"invalid pem content"
        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.serialization.load_pem_private_key",
                side_effect=ValueError("Invalid PEM"),
            ):
                result = shoestring_utils.get_key_pair("invalid.pem")
                assert result is None

    # 異常系のテスト（TypeError）
    def test_get_key_pair_type_error(self):
        mock_pem_content = b"some content"
        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.serialization.load_pem_private_key",
                side_effect=TypeError("Type error"),
            ):
                result = shoestring_utils.get_key_pair("type_error.pem")
                assert result is None

    # 異常系のテスト（OSError - ファイル読み込みエラー）
    def test_get_key_pair_os_error(self):
        with patch("builtins.open", side_effect=OSError("Permission denied")):
            result = shoestring_utils.get_key_pair("permission_denied.pem")
            assert result is None

    # 異常系のテスト（予期しないException）
    def test_get_key_pair_unexpected_error(self):
        mock_pem_content = b"some content"
        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.serialization.load_pem_private_key",
                side_effect=RuntimeError("Unexpected error"),
            ):
                result = shoestring_utils.get_key_pair("runtime_error.pem")
                assert result is None


class TestExtractPublicKeyHex:
    """_extract_public_key_hexのテストクラス"""

    def test_extract_public_key_hex_success(self):
        # モック証明書とモック公開鍵を作成
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_der_bytes = (
            b"\x00" * 12 + b"\xab\xcd\xef\x12"
        )  # 12バイトのプレフィックス + 実際のデータ

        mock_public_key.public_bytes.return_value = mock_der_bytes
        mock_cert.public_key.return_value = mock_public_key

        result = shoestring_utils._extract_public_key_hex(mock_cert)

        # プレフィックス12バイト削除後の16進文字列を確認
        assert result == "ABCDEF12"
        mock_public_key.public_bytes.assert_called_once_with(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class TestGetPublicKeysFromPemChain:
    """get_public_keys_from_pem_chainのテストクラス"""

    # 正常系のテスト（有効な証明書チェーン - node + main）
    def test_get_public_keys_from_pem_chain_success_two_certs(self):
        mock_pem_content = b"""-----BEGIN CERTIFICATE-----
node_cert_content
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
main_cert_content
-----END CERTIFICATE-----"""

        mock_node_cert = Mock()
        mock_main_cert = Mock()
        mock_node_public_key = Mock()
        mock_main_public_key = Mock()

        # node証明書のモック設定
        mock_node_public_key.public_bytes.return_value = b"\x00" * 12 + b"\x11\x22"
        mock_node_cert.public_key.return_value = mock_node_public_key

        # main証明書のモック設定
        mock_main_public_key.public_bytes.return_value = b"\x00" * 12 + b"\x33\x44"
        mock_main_cert.public_key.return_value = mock_main_public_key

        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.x509.load_pem_x509_certificate",
                side_effect=[mock_node_cert, mock_main_cert],
            ):
                result = shoestring_utils.get_public_keys_from_pem_chain(
                    "valid_chain.pem"
                )

                expected = {"node": "1122", "main": "3344"}
                assert result == expected

    # 正常系のテスト（node証明書のみ）
    def test_get_public_keys_from_pem_chain_success_one_cert(self):
        mock_pem_content = b"""-----BEGIN CERTIFICATE-----
node_cert_content
-----END CERTIFICATE-----"""

        mock_cert = Mock()
        mock_public_key = Mock()
        mock_public_key.public_bytes.return_value = b"\x00" * 12 + b"\x55\x66"
        mock_cert.public_key.return_value = mock_public_key

        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.x509.load_pem_x509_certificate",
                return_value=mock_cert,
            ):
                result = shoestring_utils.get_public_keys_from_pem_chain(
                    "single_cert.pem"
                )

                expected = {"node": "5566"}
                assert result == expected

    # 正常系のテスト（3つ以上の証明書がある場合、3つ目以降は無視）
    def test_get_public_keys_from_pem_chain_success_three_certs(self):
        mock_pem_content = b"""-----BEGIN CERTIFICATE-----
node_cert_content
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
main_cert_content
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
ignored_cert_content
-----END CERTIFICATE-----"""

        mock_node_cert = Mock()
        mock_main_cert = Mock()
        mock_ignored_cert = Mock()

        mock_node_public_key = Mock()
        mock_main_public_key = Mock()
        mock_ignored_public_key = Mock()

        mock_node_public_key.public_bytes.return_value = b"\x00" * 12 + b"\x77\x88"
        mock_main_public_key.public_bytes.return_value = b"\x00" * 12 + b"\x99\xaa"
        mock_ignored_public_key.public_bytes.return_value = b"\x00" * 12 + b"\xbb\xcc"

        mock_node_cert.public_key.return_value = mock_node_public_key
        mock_main_cert.public_key.return_value = mock_main_public_key
        mock_ignored_cert.public_key.return_value = mock_ignored_public_key

        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.x509.load_pem_x509_certificate",
                side_effect=[mock_node_cert, mock_main_cert, mock_ignored_cert],
            ):
                result = shoestring_utils.get_public_keys_from_pem_chain(
                    "three_certs.pem"
                )

                # 3つ目の証明書は無視される
                expected = {"node": "7788", "main": "99AA"}
                assert result == expected

    # 異常系のテスト（証明書の解析でValueErrorが発生、続行）
    def test_get_public_keys_from_pem_chain_partial_failure(self):
        mock_pem_content = b"""-----BEGIN CERTIFICATE-----
invalid_cert_content
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
main_cert_content
-----END CERTIFICATE-----"""

        mock_main_cert = Mock()
        mock_main_public_key = Mock()
        mock_main_public_key.public_bytes.return_value = b"\x00" * 12 + b"\xdd\xee"
        mock_main_cert.public_key.return_value = mock_main_public_key

        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.x509.load_pem_x509_certificate",
                side_effect=[ValueError("Invalid certificate"), mock_main_cert],
            ):
                result = shoestring_utils.get_public_keys_from_pem_chain(
                    "partial_fail.pem"
                )

                # 1つ目は失敗、2つ目は成功（インデックス1なので"main"キー）
                expected = {"main": "DDEE"}
                assert result == expected

    # 異常系のテスト（ファイルが存在しない場合）
    def test_get_public_keys_from_pem_chain_file_not_found(self):
        result = shoestring_utils.get_public_keys_from_pem_chain("not_exist.pem")
        assert result is None

    # 異常系のテスト（OSError）
    def test_get_public_keys_from_pem_chain_os_error(self):
        with patch("builtins.open", side_effect=OSError("Permission denied")):
            result = shoestring_utils.get_public_keys_from_pem_chain(
                "permission_denied.pem"
            )
            assert result is None

    # 異常系のテスト（空のファイル）
    def test_get_public_keys_from_pem_chain_empty_file(self):
        mock_pem_content = b""
        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            result = shoestring_utils.get_public_keys_from_pem_chain("empty.pem")
            assert result is None

    # 異常系のテスト（有効な証明書が1つもない場合）
    def test_get_public_keys_from_pem_chain_no_valid_certs(self):
        mock_pem_content = b"""-----BEGIN CERTIFICATE-----
invalid_cert1
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
invalid_cert2
-----END CERTIFICATE-----"""

        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.x509.load_pem_x509_certificate",
                side_effect=ValueError("Invalid certificate"),
            ):
                result = shoestring_utils.get_public_keys_from_pem_chain(
                    "all_invalid.pem"
                )
                assert result is None

    # 異常系のテスト（予期しないException）
    def test_get_public_keys_from_pem_chain_unexpected_error(self):
        mock_pem_content = b"some content"
        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.x509.load_pem_x509_certificate",
                side_effect=RuntimeError("Unexpected error"),
            ):
                result = shoestring_utils.get_public_keys_from_pem_chain(
                    "runtime_error.pem"
                )
                assert result is None

    # エッジケース: 空白のみの証明書セクション
    def test_get_public_keys_from_pem_chain_empty_sections(self):
        mock_pem_content = b"""-----BEGIN CERTIFICATE-----
valid_cert_content
-----END CERTIFICATE-----

-----END CERTIFICATE-----
   
-----END CERTIFICATE-----"""

        mock_cert = Mock()
        mock_public_key = Mock()
        mock_public_key.public_bytes.return_value = b"\x00" * 12 + b"\xff\x00"
        mock_cert.public_key.return_value = mock_public_key

        with patch("builtins.open", mock_open(read_data=mock_pem_content)):
            with patch(
                "src.utils.shoestring_utils.x509.load_pem_x509_certificate",
                return_value=mock_cert,
            ):
                result = shoestring_utils.get_public_keys_from_pem_chain(
                    "empty_sections.pem"
                )

                # 空白セクションはスキップされ、有効な証明書のみ処理される
                expected = {"node": "FF00"}
                assert result == expected


class TestConstants:
    """定数のテストクラス"""

    def test_constants_values(self):
        """定数の値のテスト"""
        assert shoestring_utils.NODE_FULL_CERT_PEM_PATH == "/cert/node.full.crt.pem"
        assert shoestring_utils.NODE_KEY_PEM_PATH == "/cert/node.key.pem"
        assert shoestring_utils.REMOTE_KEY_PEM_PATH == "/remote.pem"
        assert shoestring_utils.VRF_KEY_PEM_PATH == "/vrf.pem"
        assert shoestring_utils.PKCS8_PRIVATE_KEY_PREFIX_SIZE == 16
        assert shoestring_utils.SUBJECT_PUBLIC_KEY_INFO_PREFIX_SIZE == 12


class TestPrivateHelperFunctions:
    """プライベートヘルパー関数のテストクラス"""

    def test_extract_private_key_bytes(self):
        """_extract_private_key_bytes関数のテスト"""
        # モックの秘密鍵オブジェクトを作成
        mock_private_key = Mock()
        mock_der_bytes = (
            b"\x00" * 16 + b"\xab\xcd\xef"
        )  # プレフィックス16バイト + 実際のキー
        mock_private_key.private_bytes.return_value = mock_der_bytes

        result = shoestring_utils._extract_private_key_bytes(mock_private_key)

        # プレフィックスが削除されて、残りが16進文字列になることを確認
        expected = "ABCDEF"
        assert result == expected

    def test_extract_public_key_hex(self):
        """_extract_public_key_hex関数のテスト"""
        # モック証明書の作成
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_der_bytes = (
            b"\x00" * 12 + b"\x12\x34\x56\x78"
        )  # プレフィックス12バイト + 実際のキー
        mock_public_key.public_bytes.return_value = mock_der_bytes
        mock_cert.public_key.return_value = mock_public_key

        result = shoestring_utils._extract_public_key_hex(mock_cert)

        # プレフィックスが削除されて、残りが16進文字列になることを確認
        expected = "12345678"
        assert result == expected


class TestErrorHandling:
    """エラーハンドリングのテストクラス"""

    def test_get_network_name_permission_error(self):
        """設定ファイルへのアクセス権限エラーのテスト"""
        with patch(
            "configparser.ConfigParser.read",
            side_effect=PermissionError("Permission denied"),
        ):
            result = shoestring_utils.get_network_name("protected.ini")
            assert result == "testnet"

    def test_get_network_name_encoding_error(self):
        """設定ファイルのエンコーディングエラーのテスト"""
        # UnicodeDecodeErrorは実際にはOSErrorとして扱われないので、
        # configparser.Errorをテストする
        with patch(
            "configparser.ConfigParser.get",
            side_effect=configparser.NoSectionError("network"),
        ):
            with patch("builtins.open", mock_open(read_data="invalid data")):
                result = shoestring_utils.get_network_name("invalid_encoding.ini")
                assert result == "testnet"

    def test_get_key_pair_file_not_found(self):
        """秘密鍵ファイルが存在しない場合のテスト"""
        with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
            result = shoestring_utils.get_key_pair("nonexistent.pem")
            assert result is None

    def test_get_key_pair_permission_error(self):
        """秘密鍵ファイルのアクセス権限エラーのテスト"""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            result = shoestring_utils.get_key_pair("protected.pem")
            assert result is None

    def test_get_key_pair_invalid_key_format(self):
        """無効な秘密鍵フォーマットのテスト"""
        invalid_pem = b"INVALID PEM DATA"
        with patch("builtins.open", mock_open(read_data=invalid_pem)):
            result = shoestring_utils.get_key_pair("invalid.pem")
            assert result is None

    def test_get_public_keys_from_pem_chain_file_not_found(self):
        """証明書ファイルが存在しない場合のテスト"""
        with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
            result = shoestring_utils.get_public_keys_from_pem_chain("nonexistent.pem")
            assert result is None

    def test_get_public_keys_from_pem_chain_permission_error(self):
        """証明書ファイルのアクセス権限エラーのテスト"""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            result = shoestring_utils.get_public_keys_from_pem_chain("protected.pem")
            assert result is None

    def test_get_public_keys_from_pem_chain_io_error(self):
        """証明書ファイルのI/Oエラーのテスト"""
        with patch("builtins.open", side_effect=IOError("IO Error")):
            result = shoestring_utils.get_public_keys_from_pem_chain("error.pem")
            assert result is None


class TestEdgeCases:
    """エッジケースのテストクラス"""

    def test_get_network_name_empty_file(self):
        """空の設定ファイルのテスト"""
        with patch("builtins.open", mock_open(read_data="")):
            result = shoestring_utils.get_network_name("empty.ini")
            assert result == "testnet"

    def test_get_network_name_only_whitespace(self):
        """空白のみの設定ファイルのテスト"""
        with patch("builtins.open", mock_open(read_data="   \n\t  \n")):
            result = shoestring_utils.get_network_name("whitespace.ini")
            assert result == "testnet"

    def test_get_key_pair_empty_file(self):
        """空の秘密鍵ファイルのテスト"""
        with patch("builtins.open", mock_open(read_data=b"")):
            result = shoestring_utils.get_key_pair("empty.pem")
            assert result is None

    def test_get_public_keys_from_pem_chain_empty_file(self):
        """空の証明書ファイルのテスト"""
        with patch("builtins.open", mock_open(read_data=b"")):
            result = shoestring_utils.get_public_keys_from_pem_chain("empty.pem")
            assert result is None

    def test_get_public_keys_from_pem_chain_only_whitespace(self):
        """空白のみの証明書ファイルのテスト"""
        with patch("builtins.open", mock_open(read_data=b"   \n\t  \n")):
            result = shoestring_utils.get_public_keys_from_pem_chain("whitespace.pem")
            assert result is None

    def test_get_key_pair_with_password_protected_key(self):
        """パスワード保護された秘密鍵のテスト"""
        # パスワードが必要な場合のシミュレーション
        mock_pem = b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nencrypted_content\n-----END ENCRYPTED PRIVATE KEY-----"
        with patch("builtins.open", mock_open(read_data=mock_pem)):
            with patch(
                "src.utils.shoestring_utils.serialization.load_pem_private_key",
                side_effect=TypeError("Password required"),
            ):
                result = shoestring_utils.get_key_pair("encrypted.pem")
                assert result is None


class TestIntegration:
    """統合テストクラス"""

    def test_full_workflow_simulation(self):
        """フルワークフローのシミュレーションテスト"""
        # 設定ファイル読み込みから鍵取得まで一連の流れをテスト

        # 1. ネットワーク名取得
        config_content = """
[network]
name = mainnet
"""
        with patch("builtins.open", mock_open(read_data=config_content)):
            network_name = shoestring_utils.get_network_name("config.ini")
            assert network_name == "mainnet"

        # 2. 秘密鍵取得
        mock_private_key = Mock()
        mock_private_key.private_bytes.return_value = b"\x00" * 16 + b"test_key"

        mock_pem = (
            b"-----BEGIN PRIVATE KEY-----\ntest_content\n-----END PRIVATE KEY-----"
        )
        with patch("builtins.open", mock_open(read_data=mock_pem)):
            with patch(
                "src.utils.shoestring_utils.serialization.load_pem_private_key",
                return_value=mock_private_key,
            ) as mock_load:
                with patch(
                    "src.utils.shoestring_utils.PrivateKey"
                ) as mock_private_key_cls:
                    with patch(
                        "src.utils.shoestring_utils.KeyPair"
                    ) as mock_keypair_class:
                        mock_keypair_instance = Mock()
                        mock_keypair_class.return_value = mock_keypair_instance

                        key_pair = shoestring_utils.get_key_pair("private.pem")
                        assert key_pair is not None
                        assert (
                            key_pair == mock_keypair_instance
                        )  # 3. 公開鍵取得（モック）
        mock_cert = Mock()
        mock_public_key = Mock()
        mock_public_key.public_bytes.return_value = b"\x00" * 12 + b"test_pub"
        mock_cert.public_key.return_value = mock_public_key

        cert_pem = b"-----BEGIN CERTIFICATE-----\ntest_cert\n-----END CERTIFICATE-----"
        with patch("builtins.open", mock_open(read_data=cert_pem)):
            with patch(
                "src.utils.shoestring_utils.x509.load_pem_x509_certificate",
                return_value=mock_cert,
            ):
                public_keys = shoestring_utils.get_public_keys_from_pem_chain(
                    "cert.pem"
                )
                assert public_keys is not None
                assert "node" in public_keys


class TestLogging:
    """ログ機能のテストクラス"""

    @patch("src.utils.shoestring_utils.logger")
    def test_logging_calls(self, mock_logger):
        """ログ出力の呼び出しテスト"""
        # エラーケースでログが呼ばれることを確認

        # ファイル読み込みエラーのログ
        with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
            result = shoestring_utils.get_key_pair("nonexistent.pem")
            assert result is None
            # エラーログが呼ばれたことを確認
            mock_logger.error.assert_called()

        # 設定ファイルエラーのログ
        mock_logger.reset_mock()
        with patch("builtins.open", side_effect=OSError("File error")):
            result = shoestring_utils.get_network_name("error.ini")
            assert result == "testnet"  # デフォルト値
            mock_logger.warning.assert_called()
            # 警告ログが呼ばれたことを確認
            mock_logger.warning.assert_called()


if __name__ == "__main__":
    pytest.main([__file__])
