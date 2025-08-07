"""
Symbol blockchain transaction utility functions
"""

import logging
from typing import List, Optional, Union, Any
from dataclasses import dataclass

from symbolchain.NetworkTimestamp import NetworkTimestamp
from symbolchain.facade.SymbolFacade import SymbolFacade
from symbolchain.CryptoTypes import PublicKey

from .rest_gateway_utils import get_network_time, RestGatewayError

# ログ設定
logger = logging.getLogger(__name__)

# 定数の定義
TRANSACTION_DEADLINE_HOURS = 2
MIN_COSIGNATURES_FOR_BONDED = 2

# トランザクションタイプ定数
ACCOUNT_KEY_LINK_TRANSACTION_TYPE = "account_key_link_transaction_v1"
VRF_KEY_LINK_TRANSACTION_TYPE = "vrf_key_link_transaction_v1"
AGGREGATE_COMPLETE_TRANSACTION_TYPE = "aggregate_complete_transaction_v2"
AGGREGATE_BONDED_TRANSACTION_TYPE = "aggregate_bonded_transaction_v2"


@dataclass
class TransactionResult:
    """トランザクション生成結果を格納するデータクラス"""

    transaction: Optional[Any] = None
    payload: Optional[str] = None
    hash: Optional[str] = None
    error: Optional[str] = None


def _create_key_link_transaction(
    facade: SymbolFacade,
    transaction_type: str,
    main_public_key: PublicKey,
    linked_public_key: PublicKey,
    is_link: bool = True,
):
    """キーリンクトランザクションを生成する共通関数

    Args:
        facade: SymbolFacadeインスタンス
        transaction_type: トランザクションタイプ
        main_public_key: メインアカウントの公開鍵
        linked_public_key: リンクする公開鍵
        is_link: リンクする場合True、アンリンクする場合False

    Returns:
        生成されたembeddedトランザクション

    Raises:
        Exception: トランザクション生成に失敗した場合
    """
    try:
        link_action = "link" if is_link else "unlink"
        embedded_tx = facade.transaction_factory.create_embedded(
            {
                "type": transaction_type,
                "signer_public_key": main_public_key,
                "linked_public_key": linked_public_key,
                "link_action": link_action,
            }
        )
        return embedded_tx
    except Exception as e:
        logger.error(f"キーリンクトランザクションの生成に失敗しました: {e}")
        raise


def create_remote_key_link_transaction(
    facade: SymbolFacade,
    main_public_key: PublicKey,
    remote_public_key: PublicKey,
    is_link: bool = True,
):
    """リモートキーをリンクするトランザクションを生成する

    Args:
        facade: SymbolFacadeインスタンス
        main_public_key: メインアカウントの公開鍵
        remote_public_key: リモートアカウントの公開鍵
        is_link: リンクする場合True、アンリンクする場合False（デフォルト: True）

    Returns:
        リモートキーリンクのembeddedトランザクション

    Raises:
        Exception: トランザクション生成に失敗した場合
    """
    return _create_key_link_transaction(
        facade,
        ACCOUNT_KEY_LINK_TRANSACTION_TYPE,
        main_public_key,
        remote_public_key,
        is_link,
    )


def create_vrf_key_link_transaction(
    facade: SymbolFacade,
    main_public_key: PublicKey,
    vrf_public_key: PublicKey,
    is_link: bool = True,
):
    """VRFキーリンクトランザクションを生成する

    Args:
        facade: SymbolFacadeインスタンス
        main_public_key: メインアカウントの公開鍵
        vrf_public_key: VRF公開鍵
        is_link: リンクする場合True、アンリンクする場合False（デフォルト: True）

    Returns:
        VRFキーリンクのembeddedトランザクション

    Raises:
        Exception: トランザクション生成に失敗した場合
    """
    return _create_key_link_transaction(
        facade,
        VRF_KEY_LINK_TRANSACTION_TYPE,
        main_public_key,
        vrf_public_key,
        is_link,
    )


def create_aggregate_transaction(
    rest_gateway_url: str,
    facade: SymbolFacade,
    embedded_txs: List,
    min_cosignatures_count: int = 0,
):
    """アグリゲートトランザクションを生成する

    Args:
        rest_gateway_url: REST GatewayのベースURL
        facade: SymbolFacadeインスタンス
        embedded_txs: embeddedトランザクションのリスト
        min_cosignatures_count: 最小コサイン数（デフォルト: 0）

    Returns:
        生成されたアグリゲートトランザクション

    Raises:
        RestGatewayError: ネットワーク時間の取得に失敗した場合
        Exception: トランザクション生成に失敗した場合
    """
    try:
        # Embeddedトランザクションのハッシュ計算
        embedded_tx_hash = facade.hash_embedded_transactions(embedded_txs)

        # ネットワーク時間の取得とデッドライン設定
        network_time = get_network_time(rest_gateway_url)
        network_timestamp = NetworkTimestamp(network_time)
        network_timestamp.add_hours(TRANSACTION_DEADLINE_HOURS)

        # アグリゲートタイプの決定
        aggregate_type = (
            "complete"
            if min_cosignatures_count < MIN_COSIGNATURES_FOR_BONDED
            else "bonded"
        )

        transaction_type = (
            AGGREGATE_COMPLETE_TRANSACTION_TYPE
            if aggregate_type == "complete"
            else AGGREGATE_BONDED_TRANSACTION_TYPE
        )

        # アグリゲートトランザクションの生成
        aggregate_transaction = facade.transaction_factory.create(
            {
                "type": transaction_type,
                "fee": 0,
                "deadline": int(network_timestamp.timestamp),
                "transactions_hash": embedded_tx_hash,
                "transactions": embedded_txs,
            }
        )

        logger.info(
            f"アグリゲートトランザクション生成完了: タイプ={aggregate_type}, 埋込数={len(embedded_txs)}"
        )
        return aggregate_transaction

    except RestGatewayError as e:
        logger.error(f"ネットワーク時間の取得に失敗しました: {e}")
        raise
    except Exception as e:
        logger.error(f"アグリゲートトランザクションの生成に失敗しました: {e}")
        raise
