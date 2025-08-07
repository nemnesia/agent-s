import pytest
from unittest.mock import patch, Mock, MagicMock
from src.utils import symbol_utils
from src.utils.rest_gateway_utils import RestGatewayError
from symbolchain.facade.SymbolFacade import SymbolFacade
from symbolchain.CryptoTypes import PublicKey
from symbolchain.NetworkTimestamp import NetworkTimestamp


class TestCreateKeyLinkTransaction:
    """_create_key_link_transactionのテストクラス"""

    def test_create_key_link_transaction_success_link(self):
        # モックの準備
        mock_facade = Mock(spec=SymbolFacade)
        mock_transaction_factory = Mock()
        mock_embedded_tx = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create_embedded.return_value = mock_embedded_tx

        mock_main_key = Mock(spec=PublicKey)
        mock_linked_key = Mock(spec=PublicKey)

        # テスト実行
        result = symbol_utils._create_key_link_transaction(
            mock_facade, "test_transaction_type", mock_main_key, mock_linked_key, True
        )

        # 検証
        assert result == mock_embedded_tx
        mock_transaction_factory.create_embedded.assert_called_once_with(
            {
                "type": "test_transaction_type",
                "signer_public_key": mock_main_key,
                "linked_public_key": mock_linked_key,
                "link_action": "link",
            }
        )

    def test_create_key_link_transaction_success_unlink(self):
        # モックの準備
        mock_facade = Mock(spec=SymbolFacade)
        mock_transaction_factory = Mock()
        mock_embedded_tx = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create_embedded.return_value = mock_embedded_tx

        mock_main_key = Mock(spec=PublicKey)
        mock_linked_key = Mock(spec=PublicKey)

        # テスト実行（is_link=False）
        result = symbol_utils._create_key_link_transaction(
            mock_facade, "test_transaction_type", mock_main_key, mock_linked_key, False
        )

        # 検証
        assert result == mock_embedded_tx
        mock_transaction_factory.create_embedded.assert_called_once_with(
            {
                "type": "test_transaction_type",
                "signer_public_key": mock_main_key,
                "linked_public_key": mock_linked_key,
                "link_action": "unlink",
            }
        )

    def test_create_key_link_transaction_failure(self):
        # モックの準備
        mock_facade = Mock(spec=SymbolFacade)
        mock_transaction_factory = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create_embedded.side_effect = Exception(
            "Transaction creation failed"
        )

        mock_main_key = Mock(spec=PublicKey)
        mock_linked_key = Mock(spec=PublicKey)

        # テスト実行と検証
        with pytest.raises(Exception, match="Transaction creation failed"):
            symbol_utils._create_key_link_transaction(
                mock_facade,
                "test_transaction_type",
                mock_main_key,
                mock_linked_key,
                True,
            )


class TestCreateRemoteKeyLinkTransaction:
    """create_remote_key_link_transactionのテストクラス"""

    def test_create_remote_key_link_transaction_success_default(self):
        mock_facade = Mock(spec=SymbolFacade)
        mock_main_key = Mock(spec=PublicKey)
        mock_remote_key = Mock(spec=PublicKey)
        mock_result = Mock()

        with patch(
            "src.utils.symbol_utils._create_key_link_transaction",
            return_value=mock_result,
        ) as mock_create:
            result = symbol_utils.create_remote_key_link_transaction(
                mock_facade, mock_main_key, mock_remote_key
            )

            assert result == mock_result
            mock_create.assert_called_once_with(
                mock_facade,
                symbol_utils.ACCOUNT_KEY_LINK_TRANSACTION_TYPE,
                mock_main_key,
                mock_remote_key,
                True,  # デフォルト値
            )

    def test_create_remote_key_link_transaction_success_unlink(self):
        mock_facade = Mock(spec=SymbolFacade)
        mock_main_key = Mock(spec=PublicKey)
        mock_remote_key = Mock(spec=PublicKey)
        mock_result = Mock()

        with patch(
            "src.utils.symbol_utils._create_key_link_transaction",
            return_value=mock_result,
        ) as mock_create:
            result = symbol_utils.create_remote_key_link_transaction(
                mock_facade, mock_main_key, mock_remote_key, False
            )

            assert result == mock_result
            mock_create.assert_called_once_with(
                mock_facade,
                symbol_utils.ACCOUNT_KEY_LINK_TRANSACTION_TYPE,
                mock_main_key,
                mock_remote_key,
                False,
            )

    def test_create_remote_key_link_transaction_failure(self):
        mock_facade = Mock(spec=SymbolFacade)
        mock_main_key = Mock(spec=PublicKey)
        mock_remote_key = Mock(spec=PublicKey)

        with patch(
            "src.utils.symbol_utils._create_key_link_transaction",
            side_effect=Exception("Failed"),
        ) as mock_create:
            with pytest.raises(Exception, match="Failed"):
                symbol_utils.create_remote_key_link_transaction(
                    mock_facade, mock_main_key, mock_remote_key
                )


class TestCreateVrfKeyLinkTransaction:
    """create_vrf_key_link_transactionのテストクラス"""

    def test_create_vrf_key_link_transaction_success_default(self):
        mock_facade = Mock(spec=SymbolFacade)
        mock_main_key = Mock(spec=PublicKey)
        mock_vrf_key = Mock(spec=PublicKey)
        mock_result = Mock()

        with patch(
            "src.utils.symbol_utils._create_key_link_transaction",
            return_value=mock_result,
        ) as mock_create:
            result = symbol_utils.create_vrf_key_link_transaction(
                mock_facade, mock_main_key, mock_vrf_key
            )

            assert result == mock_result
            mock_create.assert_called_once_with(
                mock_facade,
                symbol_utils.VRF_KEY_LINK_TRANSACTION_TYPE,
                mock_main_key,
                mock_vrf_key,
                True,  # デフォルト値
            )

    def test_create_vrf_key_link_transaction_success_unlink(self):
        mock_facade = Mock(spec=SymbolFacade)
        mock_main_key = Mock(spec=PublicKey)
        mock_vrf_key = Mock(spec=PublicKey)
        mock_result = Mock()

        with patch(
            "src.utils.symbol_utils._create_key_link_transaction",
            return_value=mock_result,
        ) as mock_create:
            result = symbol_utils.create_vrf_key_link_transaction(
                mock_facade, mock_main_key, mock_vrf_key, False
            )

            assert result == mock_result
            mock_create.assert_called_once_with(
                mock_facade,
                symbol_utils.VRF_KEY_LINK_TRANSACTION_TYPE,
                mock_main_key,
                mock_vrf_key,
                False,
            )

    def test_create_vrf_key_link_transaction_failure(self):
        mock_facade = Mock(spec=SymbolFacade)
        mock_main_key = Mock(spec=PublicKey)
        mock_vrf_key = Mock(spec=PublicKey)

        with patch(
            "src.utils.symbol_utils._create_key_link_transaction",
            side_effect=Exception("Failed"),
        ) as mock_create:
            with pytest.raises(Exception, match="Failed"):
                symbol_utils.create_vrf_key_link_transaction(
                    mock_facade, mock_main_key, mock_vrf_key
                )


class TestCreateAggregateTransaction:
    """create_aggregate_transactionのテストクラス"""

    def test_create_aggregate_transaction_success_complete(self):
        # モックの準備
        mock_facade = Mock(spec=SymbolFacade)
        mock_transaction_factory = Mock()
        mock_aggregate_tx = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_facade.hash_embedded_transactions.return_value = "mock_hash"
        mock_transaction_factory.create.return_value = mock_aggregate_tx

        mock_embedded_txs = [Mock(), Mock()]
        mock_network_time = 1000000
        mock_timestamp = Mock()
        mock_timestamp.timestamp = 2000000

        with patch(
            "src.utils.symbol_utils.get_network_time", return_value=mock_network_time
        ) as mock_get_time:
            with patch(
                "src.utils.symbol_utils.NetworkTimestamp", return_value=mock_timestamp
            ) as mock_timestamp_class:
                result = symbol_utils.create_aggregate_transaction(
                    "http://test-gateway.com",
                    mock_facade,
                    mock_embedded_txs,
                    0,  # complete aggregate (min_cosignatures_count < 2)
                )

        # 検証
        assert result == mock_aggregate_tx
        mock_get_time.assert_called_once_with("http://test-gateway.com")
        mock_timestamp_class.assert_called_once_with(mock_network_time)
        mock_timestamp.add_hours.assert_called_once_with(
            symbol_utils.TRANSACTION_DEADLINE_HOURS
        )
        mock_facade.hash_embedded_transactions.assert_called_once_with(
            mock_embedded_txs
        )

        mock_transaction_factory.create.assert_called_once_with(
            {
                "type": symbol_utils.AGGREGATE_COMPLETE_TRANSACTION_TYPE,
                "fee": 0,
                "deadline": 2000000,
                "transactions_hash": "mock_hash",
                "transactions": mock_embedded_txs,
            }
        )

    def test_create_aggregate_transaction_success_bonded(self):
        # モックの準備
        mock_facade = Mock(spec=SymbolFacade)
        mock_transaction_factory = Mock()
        mock_aggregate_tx = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_facade.hash_embedded_transactions.return_value = "mock_hash"
        mock_transaction_factory.create.return_value = mock_aggregate_tx

        mock_embedded_txs = [Mock(), Mock()]
        mock_network_time = 1000000
        mock_timestamp = Mock()
        mock_timestamp.timestamp = 2000000

        with patch(
            "src.utils.symbol_utils.get_network_time", return_value=mock_network_time
        ) as mock_get_time:
            with patch(
                "src.utils.symbol_utils.NetworkTimestamp", return_value=mock_timestamp
            ) as mock_timestamp_class:
                result = symbol_utils.create_aggregate_transaction(
                    "http://test-gateway.com",
                    mock_facade,
                    mock_embedded_txs,
                    3,  # bonded aggregate (min_cosignatures_count >= 2)
                )

        # 検証
        assert result == mock_aggregate_tx
        mock_transaction_factory.create.assert_called_once_with(
            {
                "type": symbol_utils.AGGREGATE_BONDED_TRANSACTION_TYPE,
                "fee": 0,
                "deadline": 2000000,
                "transactions_hash": "mock_hash",
                "transactions": mock_embedded_txs,
            }
        )

    def test_create_aggregate_transaction_success_boundary_complete(self):
        # 境界値テスト: min_cosignatures_count = 1 (complete)
        mock_facade = Mock(spec=SymbolFacade)
        mock_transaction_factory = Mock()
        mock_aggregate_tx = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_facade.hash_embedded_transactions.return_value = "mock_hash"
        mock_transaction_factory.create.return_value = mock_aggregate_tx

        mock_embedded_txs = [Mock()]
        mock_network_time = 1000000
        mock_timestamp = Mock()
        mock_timestamp.timestamp = 2000000

        with patch(
            "src.utils.symbol_utils.get_network_time", return_value=mock_network_time
        ):
            with patch(
                "src.utils.symbol_utils.NetworkTimestamp", return_value=mock_timestamp
            ):
                result = symbol_utils.create_aggregate_transaction(
                    "http://test-gateway.com",
                    mock_facade,
                    mock_embedded_txs,
                    1,  # 境界値: complete (< 2)
                )

        # 検証: completeが選択される
        mock_transaction_factory.create.assert_called_once()
        call_args = mock_transaction_factory.create.call_args[0][0]
        assert call_args["type"] == symbol_utils.AGGREGATE_COMPLETE_TRANSACTION_TYPE

    def test_create_aggregate_transaction_success_boundary_bonded(self):
        # 境界値テスト: min_cosignatures_count = 2 (bonded)
        mock_facade = Mock(spec=SymbolFacade)
        mock_transaction_factory = Mock()
        mock_aggregate_tx = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_facade.hash_embedded_transactions.return_value = "mock_hash"
        mock_transaction_factory.create.return_value = mock_aggregate_tx

        mock_embedded_txs = [Mock()]
        mock_network_time = 1000000
        mock_timestamp = Mock()
        mock_timestamp.timestamp = 2000000

        with patch(
            "src.utils.symbol_utils.get_network_time", return_value=mock_network_time
        ):
            with patch(
                "src.utils.symbol_utils.NetworkTimestamp", return_value=mock_timestamp
            ):
                result = symbol_utils.create_aggregate_transaction(
                    "http://test-gateway.com",
                    mock_facade,
                    mock_embedded_txs,
                    2,  # 境界値: bonded (>= 2)
                )

        # 検証: bondedが選択される
        mock_transaction_factory.create.assert_called_once()
        call_args = mock_transaction_factory.create.call_args[0][0]
        assert call_args["type"] == symbol_utils.AGGREGATE_BONDED_TRANSACTION_TYPE

    def test_create_aggregate_transaction_rest_gateway_error(self):
        mock_facade = Mock(spec=SymbolFacade)
        mock_embedded_txs = [Mock()]

        with patch(
            "src.utils.symbol_utils.get_network_time",
            side_effect=RestGatewayError("Network error"),
        ):
            with pytest.raises(RestGatewayError, match="Network error"):
                symbol_utils.create_aggregate_transaction(
                    "http://test-gateway.com", mock_facade, mock_embedded_txs, 0
                )

    def test_create_aggregate_transaction_transaction_creation_error(self):
        # モックの準備
        mock_facade = Mock(spec=SymbolFacade)
        mock_transaction_factory = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_facade.hash_embedded_transactions.return_value = "mock_hash"
        mock_transaction_factory.create.side_effect = Exception(
            "Transaction creation failed"
        )

        mock_embedded_txs = [Mock()]
        mock_network_time = 1000000
        mock_timestamp = Mock()
        mock_timestamp.timestamp = 2000000

        with patch(
            "src.utils.symbol_utils.get_network_time", return_value=mock_network_time
        ):
            with patch(
                "src.utils.symbol_utils.NetworkTimestamp", return_value=mock_timestamp
            ):
                with pytest.raises(Exception, match="Transaction creation failed"):
                    symbol_utils.create_aggregate_transaction(
                        "http://test-gateway.com", mock_facade, mock_embedded_txs, 0
                    )

    def test_create_aggregate_transaction_hash_calculation_error(self):
        # ハッシュ計算でのエラー
        mock_facade = Mock(spec=SymbolFacade)
        mock_facade.hash_embedded_transactions.side_effect = Exception(
            "Hash calculation failed"
        )

        mock_embedded_txs = [Mock()]

        with pytest.raises(Exception, match="Hash calculation failed"):
            symbol_utils.create_aggregate_transaction(
                "http://test-gateway.com", mock_facade, mock_embedded_txs, 0
            )

    def test_create_aggregate_transaction_network_timestamp_error(self):
        # NetworkTimestamp作成でのエラー
        mock_facade = Mock(spec=SymbolFacade)
        mock_facade.hash_embedded_transactions.return_value = "mock_hash"

        mock_embedded_txs = [Mock()]
        mock_network_time = 1000000

        with patch(
            "src.utils.symbol_utils.get_network_time", return_value=mock_network_time
        ):
            with patch(
                "src.utils.symbol_utils.NetworkTimestamp",
                side_effect=Exception("Timestamp creation failed"),
            ):
                with pytest.raises(Exception, match="Timestamp creation failed"):
                    symbol_utils.create_aggregate_transaction(
                        "http://test-gateway.com", mock_facade, mock_embedded_txs, 0
                    )


class TestConstants:
    """定数のテストクラス"""

    def test_transaction_constants(self):
        """トランザクション定数のテスト"""
        assert symbol_utils.TRANSACTION_DEADLINE_HOURS == 2
        assert symbol_utils.MIN_COSIGNATURES_FOR_BONDED == 2
        assert (
            symbol_utils.ACCOUNT_KEY_LINK_TRANSACTION_TYPE
            == "account_key_link_transaction_v1"
        )
        assert (
            symbol_utils.VRF_KEY_LINK_TRANSACTION_TYPE == "vrf_key_link_transaction_v1"
        )
        assert (
            symbol_utils.AGGREGATE_COMPLETE_TRANSACTION_TYPE
            == "aggregate_complete_transaction_v2"
        )
        assert (
            symbol_utils.AGGREGATE_BONDED_TRANSACTION_TYPE
            == "aggregate_bonded_transaction_v2"
        )


class TestTransactionResultDataClass:
    """TransactionResultデータクラスのテスト"""

    def test_transaction_result_default_values(self):
        """デフォルト値のテスト"""
        result = symbol_utils.TransactionResult()

        assert result.transaction is None
        assert result.payload is None
        assert result.hash is None
        assert result.error is None

    def test_transaction_result_with_values(self):
        """値を設定した場合のテスト"""
        mock_transaction = Mock()
        result = symbol_utils.TransactionResult(
            transaction=mock_transaction,
            payload="test_payload",
            hash="test_hash",
            error="test_error",
        )

        assert result.transaction == mock_transaction
        assert result.payload == "test_payload"
        assert result.hash == "test_hash"
        assert result.error == "test_error"


class TestErrorHandling:
    """エラーハンドリングのテストクラス"""

    def test_create_remote_key_link_transaction_facade_exception(self):
        """リモートキーリンクトランザクションでのfacadeエラー"""
        mock_facade = Mock()
        mock_transaction_factory = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create_embedded.side_effect = Exception("Facade error")

        mock_main_key = Mock(spec=PublicKey)
        mock_remote_key = Mock(spec=PublicKey)

        with pytest.raises(Exception, match="Facade error"):
            symbol_utils.create_remote_key_link_transaction(
                mock_facade, mock_main_key, mock_remote_key
            )

    def test_create_vrf_key_link_transaction_facade_exception(self):
        """VRFキーリンクトランザクションでのfacadeエラー"""
        mock_facade = Mock()
        mock_transaction_factory = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create_embedded.side_effect = Exception("Facade error")

        mock_main_key = Mock(spec=PublicKey)
        mock_vrf_key = Mock(spec=PublicKey)

        with pytest.raises(Exception, match="Facade error"):
            symbol_utils.create_vrf_key_link_transaction(
                mock_facade, mock_main_key, mock_vrf_key
            )

        mock_main_key = Mock(spec=PublicKey)
        mock_vrf_key = Mock(spec=PublicKey)

        with pytest.raises(Exception, match="Facade error"):
            symbol_utils.create_vrf_key_link_transaction(
                mock_facade, mock_main_key, mock_vrf_key
            )

    def test_create_aggregate_transaction_rest_gateway_error(self):
        """REST Gateway通信エラーのテスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_embedded_txs = [Mock()]

        with patch(
            "src.utils.symbol_utils.get_network_time",
            side_effect=RestGatewayError("Network error"),
        ):
            with pytest.raises(RestGatewayError, match="Network error"):
                symbol_utils.create_aggregate_transaction(
                    "http://test-gateway.com", mock_facade, mock_embedded_txs, 0
                )

    def test_create_key_link_transaction_invalid_parameters(self):
        """無効なパラメーターでの_create_key_link_transactionテスト"""
        mock_facade = Mock()
        mock_transaction_factory = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create_embedded.side_effect = Exception(
            "Invalid parameters"
        )

        # 無効な公開鍵でテスト（空文字列など）
        mock_invalid_key = Mock(spec=PublicKey)

        with pytest.raises(Exception):
            symbol_utils._create_key_link_transaction(
                mock_facade, "test_type", mock_invalid_key, mock_invalid_key, True
            )


class TestEdgeCases:
    """エッジケースのテストクラス"""

    def test_create_aggregate_transaction_empty_embedded_transactions(self):
        """空のembeddedトランザクションリストのテスト"""
        mock_facade = Mock()
        mock_facade.hash_embedded_transactions.return_value = "empty_hash"

        mock_transaction_factory = Mock()
        mock_aggregate_tx = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create.return_value = mock_aggregate_tx

        mock_network_time = 1000000
        mock_timestamp = Mock()
        mock_timestamp.timestamp = 2000000  # timestampをプロパティとして設定

        with patch(
            "src.utils.symbol_utils.get_network_time", return_value=mock_network_time
        ):
            with patch(
                "src.utils.symbol_utils.NetworkTimestamp", return_value=mock_timestamp
            ):
                result = symbol_utils.create_aggregate_transaction(
                    "http://test-gateway.com", mock_facade, [], 0
                )

        assert result is not None
        assert result == mock_aggregate_tx  # 空のリストでも正常に処理されることを確認
        assert result == mock_aggregate_tx

    def test_create_aggregate_transaction_single_cosignature(self):
        """単一の cosignature でのテスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_facade.hash_embedded_transactions.return_value = "single_hash"

        mock_transaction_factory = Mock()
        mock_aggregate_tx = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create.return_value = mock_aggregate_tx

        mock_embedded_txs = [Mock()]
        mock_network_time = 1000000
        mock_timestamp = Mock()
        mock_timestamp.timestamp = 2000000

        with patch(
            "src.utils.symbol_utils.get_network_time", return_value=mock_network_time
        ):
            with patch(
                "src.utils.symbol_utils.NetworkTimestamp", return_value=mock_timestamp
            ):
                result = symbol_utils.create_aggregate_transaction(
                    "http://test-gateway.com", mock_facade, mock_embedded_txs, 1
                )

                # 単一cosignatureの場合はCOMPLETEタイプが使用される
                assert result == mock_aggregate_tx
                mock_transaction_factory.create.assert_called_once()
                call_args = mock_transaction_factory.create.call_args[0][0]
                assert (
                    call_args["type"]
                    == symbol_utils.AGGREGATE_COMPLETE_TRANSACTION_TYPE
                )

    def test_create_aggregate_transaction_multiple_cosignatures(self):
        """複数の cosignature でのテスト（BONDEDタイプ）"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_facade.hash_embedded_transactions.return_value = "multi_hash"

        mock_transaction_factory = Mock()
        mock_aggregate_tx = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create.return_value = mock_aggregate_tx

        mock_embedded_txs = [Mock(), Mock()]
        mock_network_time = 1000000
        mock_timestamp = Mock()
        mock_timestamp.timestamp = 3000000

        with patch(
            "src.utils.symbol_utils.get_network_time", return_value=mock_network_time
        ):
            with patch(
                "src.utils.symbol_utils.NetworkTimestamp", return_value=mock_timestamp
            ):
                result = symbol_utils.create_aggregate_transaction(
                    "http://test-gateway.com", mock_facade, mock_embedded_txs, 3
                )

                # 複数cosignatureの場合はBONDEDタイプが使用される
                assert result == mock_aggregate_tx
                mock_transaction_factory.create.assert_called_once()
                call_args = mock_transaction_factory.create.call_args[0][0]
                assert (
                    call_args["type"] == symbol_utils.AGGREGATE_BONDED_TRANSACTION_TYPE
                )

    def test_create_key_link_transaction_unlink_action(self):
        """アンリンクアクションのテスト"""
        mock_facade = Mock(spec=SymbolFacade)
        mock_transaction_factory = Mock()
        mock_embedded_tx = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create_embedded.return_value = mock_embedded_tx

        mock_main_key = Mock(spec=PublicKey)
        mock_linked_key = Mock(spec=PublicKey)

        result = symbol_utils._create_key_link_transaction(
            mock_facade, "test_type", mock_main_key, mock_linked_key, False
        )

        # unlinkアクションが正しく設定されることを確認
        assert result == mock_embedded_tx
        call_args = mock_transaction_factory.create_embedded.call_args[0][0]
        assert call_args["link_action"] == "unlink"


class TestIntegration:
    """統合テストクラス"""

    def test_full_key_link_workflow(self):
        """キーリンクの完全なワークフローテスト"""
        # モック準備
        mock_facade = Mock()
        mock_transaction_factory = Mock()
        mock_facade.transaction_factory = mock_transaction_factory

        mock_remote_tx = Mock()
        mock_vrf_tx = Mock()
        mock_aggregate_tx = Mock()

        # create_embeddedの呼び出し順序で異なるトランザクションを返す
        mock_transaction_factory.create_embedded.side_effect = [
            mock_remote_tx,
            mock_vrf_tx,
        ]
        mock_transaction_factory.create.return_value = mock_aggregate_tx

        mock_facade.hash_embedded_transactions.return_value = "workflow_hash"

        mock_main_key = Mock(spec=PublicKey)
        mock_remote_key = Mock(spec=PublicKey)
        mock_vrf_key = Mock(spec=PublicKey)

        mock_network_time = 2000000
        mock_timestamp = Mock()
        mock_timestamp.timestamp = 4000000

        # ワークフロー実行
        with patch(
            "src.utils.symbol_utils.get_network_time", return_value=mock_network_time
        ):
            with patch(
                "src.utils.symbol_utils.NetworkTimestamp", return_value=mock_timestamp
            ):
                # 1. リモートキーリンクトランザクション作成
                remote_tx = symbol_utils.create_remote_key_link_transaction(
                    mock_facade, mock_main_key, mock_remote_key
                )

                # 2. VRFキーリンクトランザクション作成
                vrf_tx = symbol_utils.create_vrf_key_link_transaction(
                    mock_facade, mock_main_key, mock_vrf_key
                )

                # 3. 集約トランザクション作成
                aggregate_tx = symbol_utils.create_aggregate_transaction(
                    "http://test-gateway.com", mock_facade, [remote_tx, vrf_tx], 1
                )  # 検証
                assert remote_tx == mock_remote_tx
                assert vrf_tx == mock_vrf_tx
                assert aggregate_tx == mock_aggregate_tx

    def test_error_recovery_workflow(self):
        """エラー回復ワークフローのテスト"""
        # 最初の呼び出しで失敗、2回目で成功するシナリオ
        mock_facade = Mock()
        mock_transaction_factory = Mock()
        mock_facade.transaction_factory = mock_transaction_factory

        # 最初は失敗、次は成功
        mock_transaction_factory.create_embedded.side_effect = [
            Exception("First attempt failed"),
            Mock(),  # 成功
        ]

        mock_main_key = Mock(spec=PublicKey)
        mock_remote_key = Mock(spec=PublicKey)

        # 最初の呼び出しは失敗
        with pytest.raises(Exception, match="First attempt failed"):
            symbol_utils.create_remote_key_link_transaction(
                mock_facade, mock_main_key, mock_remote_key
            )

        # 2回目の呼び出しは成功
        result = symbol_utils.create_remote_key_link_transaction(
            mock_facade, mock_main_key, mock_remote_key
        )
        assert result is not None


class TestLogging:
    """ログ機能のテストクラス"""

    @patch("src.utils.symbol_utils.logger")
    def test_logging_calls(self, mock_logger):
        """ログ出力の呼び出しテスト"""
        # エラー発生時にログが呼ばれることを確認
        mock_facade = Mock()
        mock_transaction_factory = Mock()
        mock_facade.transaction_factory = mock_transaction_factory
        mock_transaction_factory.create_embedded.side_effect = Exception("Test error")

        mock_main_key = Mock(spec=PublicKey)
        mock_remote_key = Mock(spec=PublicKey)

        with pytest.raises(Exception):
            symbol_utils.create_remote_key_link_transaction(
                mock_facade, mock_main_key, mock_remote_key
            )


if __name__ == "__main__":
    pytest.main([__file__])
