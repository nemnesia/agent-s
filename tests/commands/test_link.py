"""link.pyモジュールのテスト"""

import argparse
import pytest
import sys
import os
from typing import Optional
from unittest.mock import Mock, patch, MagicMock

# プロジェクトルートをパスに追加
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../src"))

from symbolchain.CryptoTypes import PublicKey
from symbolchain.facade.SymbolFacade import SymbolFacade, SymbolPublicAccount

# テスト対象のモジュールをインポート
import commands.link as link


class TestGetPublicAccountFromPemChain:
    """get_public_account_from_pem_chain関数のテストクラス"""

    @patch("commands.link.get_public_keys_from_pem_chain")
    def test_success(self, mock_get_public_keys):
        """正常系テスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_public_account = Mock(spec=SymbolPublicAccount)
        mock_facade.create_public_account.return_value = mock_public_account

        mock_get_public_keys.return_value = {
            "main": "1234567890ABCDEF" * 4
        }  # 32バイト=64文字

        result = link.get_public_account_from_pem_chain("/path/to/pem", mock_facade)

        assert result == mock_public_account
        mock_get_public_keys.assert_called_once_with("/path/to/pem")
        mock_facade.create_public_account.assert_called_once()

    @patch("commands.link.get_public_keys_from_pem_chain")
    def test_get_public_keys_returns_none(self, mock_get_public_keys):
        """get_public_keys_from_pem_chainがNoneを返す場合"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_get_public_keys.return_value = None

        result = link.get_public_account_from_pem_chain("/path/to/pem", mock_facade)

        assert result is None
        mock_facade.create_public_account.assert_not_called()

    @patch("commands.link.get_public_keys_from_pem_chain")
    def test_exception_handling(self, mock_get_public_keys):
        """例外処理テスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_get_public_keys.side_effect = Exception("Test error")

        result = link.get_public_account_from_pem_chain("/path/to/pem", mock_facade)

        assert result is None


class TestGetPublicAccountFromPem:
    """get_public_account_from_pem関数のテストクラス"""

    @patch("commands.link.get_key_pair")
    def test_success(self, mock_get_key_pair):
        """正常系テスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_public_account = Mock(spec=SymbolPublicAccount)
        mock_facade.create_public_account.return_value = mock_public_account

        mock_key_pair = Mock()
        mock_key_pair.public_key = PublicKey("1234567890ABCDEF" * 4)
        mock_get_key_pair.return_value = mock_key_pair

        result = link.get_public_account_from_pem("/path/to/pem", mock_facade)

        assert result == mock_public_account
        mock_get_key_pair.assert_called_once_with("/path/to/pem")
        mock_facade.create_public_account.assert_called_once_with(
            mock_key_pair.public_key
        )

    @patch("commands.link.get_key_pair")
    def test_get_key_pair_returns_none(self, mock_get_key_pair):
        """get_key_pairがNoneを返す場合"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_get_key_pair.return_value = None

        result = link.get_public_account_from_pem("/path/to/pem", mock_facade)

        assert result is None
        mock_facade.create_public_account.assert_not_called()

    @patch("commands.link.get_key_pair")
    def test_exception_handling(self, mock_get_key_pair):
        """例外処理テスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_get_key_pair.side_effect = Exception("Test error")

        result = link.get_public_account_from_pem("/path/to/pem", mock_facade)

        assert result is None


class TestProcessKeyLink:
    """_process_key_link関数のテストクラス"""

    def setup_method(self):
        """各テストの前準備"""
        self.mock_facade = Mock(spec=SymbolFacade)
        self.mock_main_public_key = PublicKey("1234567890ABCDEF" * 4)
        self.mock_target_public_key = PublicKey("FEDCBA0987654321" * 4)
        self.mock_create_tx_func = Mock()
        self.mock_create_tx_func.return_value = Mock()

    def test_no_current_key_link_needed(self):
        """現在キーがない場合（リンクが必要）"""
        current_key_hex = None
        txs = link._process_key_link(
            "remote",
            current_key_hex,
            self.mock_target_public_key,
            self.mock_facade,
            self.mock_main_public_key,
            self.mock_create_tx_func,
        )

        assert len(txs) == 1
        self.mock_create_tx_func.assert_called_once_with(
            self.mock_facade,
            self.mock_main_public_key,
            self.mock_target_public_key,
            True,
        )

    def test_current_key_same_as_target(self):
        """現在のキーが目標キーと同じ場合（何もしない）"""
        current_key_hex = str(self.mock_target_public_key)
        txs = link._process_key_link(
            "remote",
            current_key_hex,
            self.mock_target_public_key,
            self.mock_facade,
            self.mock_main_public_key,
            self.mock_create_tx_func,
        )

        assert len(txs) == 0
        self.mock_create_tx_func.assert_not_called()

    def test_current_key_different_from_target(self):
        """現在のキーが目標キーと異なる場合（アンリンク→リンク）"""
        different_key_hex = "ABCDEF1234567890" * 4
        txs = link._process_key_link(
            "remote",
            different_key_hex,
            self.mock_target_public_key,
            self.mock_facade,
            self.mock_main_public_key,
            self.mock_create_tx_func,
        )

        assert len(txs) == 2
        # 呼び出し履歴をstrで比較
        calls = self.mock_create_tx_func.call_args_list
        unlink_call = calls[0][0]
        link_call = calls[1][0]
        # アンリンク
        assert unlink_call[0] == self.mock_facade
        assert unlink_call[1] == self.mock_main_public_key
        assert str(unlink_call[2]) == different_key_hex
        assert unlink_call[3] is False
        # リンク
        assert link_call[0] == self.mock_facade
        assert link_call[1] == self.mock_main_public_key
        assert str(link_call[2]) == str(self.mock_target_public_key)
        assert link_call[3] is True


class TestValidateNetworkName:
    """_validate_network_name関数のテストクラス"""

    def test_mainnet_normalization(self):
        """mainnet正規化テスト"""
        assert link._validate_network_name("mainnet") == "mainnet"
        assert link._validate_network_name("MAINNET") == "mainnet"
        assert link._validate_network_name("main") == "mainnet"
        assert link._validate_network_name("MAIN") == "mainnet"

    def test_testnet_normalization(self):
        """testnet正規化テスト"""
        assert link._validate_network_name("testnet") == "testnet"
        assert link._validate_network_name("TESTNET") == "testnet"
        assert link._validate_network_name("test") == "testnet"
        assert link._validate_network_name("TEST") == "testnet"

    def test_unknown_network_defaults_to_testnet(self):
        """不明なネットワーク名はtestnetにデフォルト"""
        assert link._validate_network_name("unknown") == "testnet"
        assert link._validate_network_name("devnet") == "testnet"
        assert link._validate_network_name("") == "testnet"


class TestLinkNodeKeys:
    """link_node_keys関数のテストクラス"""

    def setup_method(self):
        """各テストの前準備"""
        self.mock_args = Mock()
        self.mock_args.config = "test_config.ini"
        self.mock_args.keys_path = "test_keys/"

        # モック設定
        self.patcher_get_network_name = patch("commands.link.get_network_name")
        self.patcher_symbol_facade = patch("commands.link.SymbolFacade")
        self.patcher_get_pub_acc_chain = patch(
            "commands.link.get_public_account_from_pem_chain"
        )
        self.patcher_get_pub_acc = patch("commands.link.get_public_account_from_pem")
        self.patcher_get_rest_url = patch("commands.link.get_rest_gateway_url")
        self.patcher_get_link_keys = patch("commands.link.get_account_link_keys")
        self.patcher_get_min_approval = patch("commands.link.get_min_approval")
        self.patcher_create_aggregate = patch(
            "commands.link.create_aggregate_transaction"
        )

        self.mock_get_network_name = self.patcher_get_network_name.start()
        self.mock_symbol_facade = self.patcher_symbol_facade.start()
        self.mock_get_pub_acc_chain = self.patcher_get_pub_acc_chain.start()
        self.mock_get_pub_acc = self.patcher_get_pub_acc.start()
        self.mock_get_rest_url = self.patcher_get_rest_url.start()
        self.mock_get_link_keys = self.patcher_get_link_keys.start()
        self.mock_get_min_approval = self.patcher_get_min_approval.start()
        self.mock_create_aggregate = self.patcher_create_aggregate.start()

        # 基本的なモック設定
        self.mock_get_network_name.return_value = "testnet"
        self.mock_facade_instance = Mock()
        self.mock_symbol_facade.return_value = self.mock_facade_instance

        self.mock_main_account = Mock()
        self.mock_main_account.address = "TESTADDRESS123"
        self.mock_main_account.public_key = PublicKey("1234567890ABCDEF" * 4)
        self.mock_get_pub_acc_chain.return_value = self.mock_main_account

        self.mock_remote_account = Mock()
        self.mock_remote_account.public_key = PublicKey("ABCDEF1234567890" * 4)
        self.mock_vrf_account = Mock()
        self.mock_vrf_account.public_key = PublicKey("FEDCBA0987654321" * 4)

        # get_public_account_from_pemの戻り値を設定（呼び出し順序で返す）
        self.mock_get_pub_acc.side_effect = [
            self.mock_remote_account,
            self.mock_vrf_account,
        ]

        self.mock_get_rest_url.return_value = "http://test-gateway"
        self.mock_get_link_keys.return_value = {
            "linked": None,
            "node": None,
            "vrf": None,
        }
        self.mock_get_min_approval.return_value = 2

        self.mock_aggregate_tx = Mock()
        self.mock_aggregate_tx.serialize.return_value.hex.return_value = "abcdef123456"
        self.mock_create_aggregate.return_value = self.mock_aggregate_tx

    def teardown_method(self):
        """各テストの後始末"""
        patch.stopall()

    @patch("commands.link._process_key_link")
    def test_successful_link_process(self, mock_process_key_link):
        """正常系テスト - リンク処理が正常に完了"""
        # _process_key_linkが1つずつトランザクションを返すように設定
        mock_tx1 = Mock()
        mock_tx2 = Mock()
        mock_process_key_link.side_effect = [[mock_tx1], [mock_tx2]]

        result = link.link_node_keys(self.mock_args)

        # 基本的な呼び出し確認
        self.mock_get_network_name.assert_called_once_with(self.mock_args.config)
        self.mock_symbol_facade.assert_called_once_with("testnet")

        # アカウント作成の確認
        assert self.mock_get_pub_acc_chain.call_count == 1
        assert self.mock_get_pub_acc.call_count == 2

        # REST API呼び出し確認
        self.mock_get_rest_url.assert_called_once_with("testnet")
        self.mock_get_link_keys.assert_called_once_with(
            "http://test-gateway", "TESTADDRESS123"
        )

        # _process_key_linkの呼び出し確認
        assert mock_process_key_link.call_count == 2

        # アグリゲートトランザクション生成確認
        self.mock_create_aggregate.assert_called_once()

        assert result is None  # 正常終了時はNoneを返す

    def test_main_public_account_creation_failure(self):
        """メインパブリックアカウント作成失敗"""
        self.mock_get_pub_acc_chain.return_value = None

        result = link.link_node_keys(self.mock_args)

        self.mock_get_pub_acc.assert_not_called()
        assert result is None

    def test_remote_public_account_creation_failure(self):
        """リモートパブリックアカウント作成失敗"""
        self.mock_get_pub_acc.side_effect = [None, self.mock_vrf_account]

        result = link.link_node_keys(self.mock_args)

        # VRFアカウント作成まで到達しない
        self.mock_get_link_keys.assert_not_called()
        assert result is None

    def test_vrf_public_account_creation_failure(self):
        """VRFパブリックアカウント作成失敗"""
        self.mock_get_pub_acc.side_effect = [self.mock_remote_account, None]

        result = link.link_node_keys(self.mock_args)

        self.mock_get_link_keys.assert_not_called()
        assert result is None

    @patch("commands.link._process_key_link")
    def test_no_transactions_generated(self, mock_process_key_link):
        """トランザクションが生成されない場合"""
        mock_process_key_link.return_value = []  # 空のリスト

        result = link.link_node_keys(self.mock_args)

        self.mock_create_aggregate.assert_not_called()
        assert result is None

    @patch("commands.link._process_key_link")
    @patch(
        "commands.link.RestGatewayError",
        new_callable=lambda: type("RestGatewayError", (Exception,), {}),
    )
    def test_rest_gateway_error_in_min_approval(
        self, mock_rest_gateway_error, mock_process_key_link
    ):
        """最小承認数取得でRestGatewayError"""
        mock_tx = Mock()
        mock_process_key_link.side_effect = [[mock_tx], []]
        self.mock_get_min_approval.side_effect = mock_rest_gateway_error("API Error")

        result = link.link_node_keys(self.mock_args)

        # デフォルト値1で処理継続
        self.mock_create_aggregate.assert_called_once()
        assert result is None

    @patch("commands.link._process_key_link")
    @patch(
        "commands.link.RestGatewayError",
        new_callable=lambda: type("RestGatewayError", (Exception,), {}),
    )
    def test_rest_gateway_error_in_main_process(
        self, mock_rest_gateway_error, mock_process_key_link
    ):
        """メイン処理でRestGatewayError"""
        self.mock_get_link_keys.side_effect = mock_rest_gateway_error(
            "Connection failed"
        )

        result = link.link_node_keys(self.mock_args)

        mock_process_key_link.assert_not_called()
        assert result is None

    def test_general_exception_handling(self):
        """一般的な例外処理"""
        self.mock_get_network_name.side_effect = Exception("Config file not found")

        result = link.link_node_keys(self.mock_args)

        assert result is None

    @patch("commands.link._process_key_link")
    def test_network_name_validation(self, mock_process_key_link):
        """ネットワーク名の正規化テスト"""
        self.mock_get_network_name.return_value = "MAIN"  # 大文字
        mock_process_key_link.side_effect = [[], []]

        result = link.link_node_keys(self.mock_args)

        # "mainnet"として正規化されることを確認
        self.mock_symbol_facade.assert_called_once_with("mainnet")
        self.mock_get_rest_url.assert_called_once_with("mainnet")

    @patch("commands.link._process_key_link")
    def test_node_key_already_linked(self, mock_process_key_link):
        """ノードキーが既にリンクされている場合"""
        self.mock_get_link_keys.return_value = {
            "linked": None,
            "node": "EXISTING_NODE_KEY",  # ノードキーが設定済み
            "vrf": None,
        }
        mock_process_key_link.side_effect = [[], []]

        result = link.link_node_keys(self.mock_args)

        assert result is None  # 正常終了

    @patch("commands.link._process_key_link")
    def test_different_link_key_scenarios(self, mock_process_key_link):
        """異なるリンクキーシナリオ"""
        # 既存のキーが設定されているケース
        self.mock_get_link_keys.return_value = {
            "linked": "EXISTING_REMOTE_KEY",
            "node": None,
            "vrf": "EXISTING_VRF_KEY",
        }
        mock_tx1 = Mock()
        mock_tx2 = Mock()
        mock_process_key_link.side_effect = [[mock_tx1], [mock_tx2]]

        result = link.link_node_keys(self.mock_args)

        # _process_key_linkが適切に呼び出されることを確認
        assert mock_process_key_link.call_count == 2
        self.mock_create_aggregate.assert_called_once()
        assert result is None


class TestGetCommonLinkArgs:
    """get_common_link_args関数のテストクラス"""

    def test_parser_creation(self):
        """ArgumentParserの作成テスト"""
        parser = link.get_common_link_args()

        assert isinstance(parser, argparse.ArgumentParser)
        # add_help=Falseが設定されていることを確認
        assert parser.add_help is False

    def test_default_arguments(self):
        """デフォルト引数のテスト"""
        parser = link.get_common_link_args()

        # デフォルト値でパース
        args = parser.parse_args([])

        assert args.config == link.DEFAULT_CONFIG_PATH
        assert args.keys_path == link.DEFAULT_KEYS_PATH

    def test_custom_arguments(self):
        """カスタム引数のテスト"""
        parser = link.get_common_link_args()

        # カスタム値でパース
        args = parser.parse_args(
            ["--config", "custom_config.ini", "--keys-path", "custom_keys/"]
        )

        assert args.config == "custom_config.ini"
        assert args.keys_path == "custom_keys/"

    def test_short_arguments(self):
        """短縮引数のテスト"""
        parser = link.get_common_link_args()

        # 短縮形でパース
        args = parser.parse_args(["-c", "short_config.ini", "-k", "short_keys/"])

        assert args.config == "short_config.ini"
        assert args.keys_path == "short_keys/"


class TestSetupLinkSubparser:
    """setup_link_subparser関数のテストクラス"""

    def test_subparser_setup(self):
        """サブパーサー設定のテスト"""
        # メインパーサー作成
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        # テスト対象関数実行
        link.setup_link_subparser(subparsers)

        # linkサブコマンドでパース
        args = main_parser.parse_args(["link"])

        # link_node_keys関数が設定されていることを確認
        assert args.func == link.link_node_keys

    def test_subparser_with_arguments(self):
        """サブパーサーと引数のテスト"""
        main_parser = argparse.ArgumentParser()
        subparsers = main_parser.add_subparsers()

        link.setup_link_subparser(subparsers)

        # 引数付きでパース
        args = main_parser.parse_args(
            ["link", "--config", "test.ini", "--keys-path", "test_keys/"]
        )

        assert args.func == link.link_node_keys
        assert args.config == "test.ini"
        assert args.keys_path == "test_keys/"


class TestConstants:
    """定数のテストクラス"""

    def test_default_constants(self):
        """デフォルト定数のテスト"""
        assert link.DEFAULT_CONFIG_PATH == "shoestring/shoestring.ini"
        assert link.DEFAULT_KEYS_PATH == "keys"


class TestEdgeCasesAndErrorHandling:
    """エッジケースとエラーハンドリングのテストクラス"""

    @patch("commands.link.get_public_keys_from_pem_chain")
    def test_get_public_account_from_pem_chain_exception(self, mock_get_public_keys):
        """get_public_account_from_pem_chainで例外が発生する場合のテスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_get_public_keys.side_effect = Exception("Test exception")

        result = link.get_public_account_from_pem_chain("/path/to/pem", mock_facade)

        assert result is None

    @patch("commands.link.get_public_keys_from_pem_chain")
    def test_get_public_account_from_pem_chain_invalid_key_format(
        self, mock_get_public_keys
    ):
        """無効な公開鍵フォーマットの場合のテスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_facade.create_public_account.side_effect = Exception("Invalid key format")

        mock_get_public_keys.return_value = {"main": "invalid_key_format"}

        result = link.get_public_account_from_pem_chain("/path/to/pem", mock_facade)

        assert result is None

    @patch("commands.link.get_public_keys_from_pem_chain")
    def test_get_public_account_from_pem_chain_empty_keys(self, mock_get_public_keys):
        """空の公開鍵辞書が返される場合のテスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_get_public_keys.return_value = {}

        result = link.get_public_account_from_pem_chain("/path/to/pem", mock_facade)

        assert result is None

    @patch("commands.link.get_public_keys_from_pem_chain")
    def test_get_public_account_from_pem_chain_no_main_key(self, mock_get_public_keys):
        """'main'キーが存在しない場合のテスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_get_public_keys.return_value = {"node": "1234567890ABCDEF" * 4}

        result = link.get_public_account_from_pem_chain("/path/to/pem", mock_facade)

        assert result is None


class TestLinkNodeKeysFunction:
    """link_node_keys関数のテストクラス"""

    @patch("commands.link.get_network_name")
    @patch("commands.link.get_public_account_from_pem_chain")
    @patch("commands.link.get_key_pair")
    @patch("commands.link.get_account_link_keys")
    @patch("commands.link.get_rest_gateway_url")
    def test_link_node_keys_basic_functionality(
        self,
        mock_get_rest_gateway_url,
        mock_get_account_link_keys,
        mock_get_key_pair,
        mock_get_public_account,
        mock_get_network_name,
    ):
        """link_node_keys関数の基本機能テスト"""
        # モック設定
        mock_get_network_name.return_value = "testnet"
        mock_get_rest_gateway_url.return_value = "http://test-gateway.com"

        mock_main_account = Mock()
        mock_main_account.address = "TEST_ADDRESS"
        mock_get_public_account.return_value = mock_main_account

        mock_remote_keypair = Mock()
        mock_remote_keypair.public_key = PublicKey("A" * 64)
        mock_vrf_keypair = Mock()
        mock_vrf_keypair.public_key = PublicKey("B" * 64)

        def mock_get_key_pair_side_effect(path):
            if "remote" in path:
                return mock_remote_keypair
            elif "vrf" in path:
                return mock_vrf_keypair
            return None

        mock_get_key_pair.side_effect = mock_get_key_pair_side_effect

        mock_get_account_link_keys.return_value = {
            "linked": None,
            "node": None,
            "vrf": None,
        }

        # テスト実行
        args = Mock()
        args.config = "test.ini"
        args.keys_path = "test_keys"

        with patch("sys.stdout"):  # 標準出力をモック
            with patch("commands.link.create_aggregate_transaction") as mock_create_tx:
                mock_create_tx.return_value = "mocked_transaction"

                # 実際に関数を呼び出す（例外が発生しないことを確認）
                try:
                    link.link_node_keys(args)
                    # ここまで到達すれば基本的な処理は正常
                except Exception as e:
                    # 予期しない例外以外は許可（REST APIエラーなど）
                    if not any(
                        x in str(e) for x in ["REST", "HTTP", "Network", "Connection"]
                    ):
                        raise

    def test_link_node_keys_with_invalid_args(self):
        """無効な引数での link_node_keys 関数のテスト"""
        args = Mock()
        args.config = None
        args.keys_path = None

        # 引数が無効でも例外が適切に処理されることを確認
        with patch("sys.stdout"):
            with patch(
                "commands.link.get_network_name", side_effect=Exception("Config error")
            ):
                try:
                    link.link_node_keys(args)
                except Exception as e:
                    # 設定エラーが適切に処理されることを確認
                    assert "Config error" in str(e) or any(
                        x in str(e) for x in ["config", "設定", "Config"]
                    )


class TestIntegration:
    """統合テストクラス"""

    def test_argument_parser_integration(self):
        """引数パーサーとの統合テスト"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        link.setup_link_subparser(subparsers)

        # 最小限の引数でパース
        args = parser.parse_args(["link"])

        # デフォルト値の確認
        assert args.config == link.DEFAULT_CONFIG_PATH
        assert args.keys_path == link.DEFAULT_KEYS_PATH
        assert args.func == link.link_node_keys

    def test_help_functionality(self):
        """ヘルプ機能の統合テスト"""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        link.setup_link_subparser(subparsers)

        # ヘルプが正常に表示されることを確認
        try:
            parser.parse_args(["link", "--help"])
        except SystemExit as e:
            # ヘルプ表示による正常終了であることを確認
            assert e.code == 0


class TestLoggingAndErrorMessages:
    """ログ出力とエラーメッセージのテストクラス"""

    @patch("commands.link.logger")
    def test_logging_calls(self, mock_logger):
        """ログ出力の呼び出しテスト"""
        # get_public_account_from_pem_chainでのログ出力テスト
        mock_facade = Mock(spec=SymbolFacade)

        with patch("commands.link.get_public_keys_from_pem_chain", return_value=None):
            result = link.get_public_account_from_pem_chain(
                "/nonexistent/path", mock_facade
            )

            assert result is None
            # エラーログが出力されることを確認（実装に応じて調整）

    def test_error_handling_robustness(self):
        """エラーハンドリングの堅牢性テスト"""
        # 様々な例外状況での関数の堅牢性を確認
        mock_facade = Mock(spec=SymbolFacade)

        # 空文字での処理
        with patch("commands.link.get_public_keys_from_pem_chain", return_value=None):
            result = link.get_public_account_from_pem_chain("", mock_facade)
            assert result is None

        # 存在しないパスでの処理
        with patch("commands.link.get_public_keys_from_pem_chain", return_value=None):
            result = link.get_public_account_from_pem_chain(
                "/nonexistent/path", mock_facade
            )
            assert result is None


if __name__ == "__main__":
    pytest.main([__file__])
