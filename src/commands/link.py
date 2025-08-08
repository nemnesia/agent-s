import argparse
import logging
from typing import List, Literal, Optional

from symbolchain.CryptoTypes import PublicKey
from symbolchain.facade.SymbolFacade import SymbolFacade, SymbolPublicAccount

from utils.rest_gateway_utils import (
    RestGatewayError,
    get_account_link_keys,
    get_min_approval,
    get_rest_gateway_url,
)
from utils.shoestring_utils import (
    NODE_FULL_CERT_PEM_PATH,
    REMOTE_KEY_PEM_PATH,
    VRF_KEY_PEM_PATH,
    get_key_pair,
    get_network_name,
    get_public_keys_from_pem_chain,
)
from utils.symbol_utils import (
    create_aggregate_transaction,
    create_node_key_link_transaction,
    create_remote_key_link_transaction,
    create_vrf_key_link_transaction,
)

# ログ設定
logger = logging.getLogger(__name__)

# 定数の定義
DEFAULT_CONFIG_PATH = "shoestring/shoestring.ini"
DEFAULT_KEYS_PATH = "keys"


def get_public_account_from_pem_chain(
    pem_path: str, facade: SymbolFacade
) -> Optional[SymbolPublicAccount]:
    """チェーン証明書PEMファイルからメインパブリックアカウントを取得する

    Args:
        pem_path: PEM証明書チェーンファイルのパス
        facade: SymbolFacadeインスタンス

    Returns:
        メインパブリックアカウント、失敗時はNone
    """
    try:
        main_public_keys_hex = get_public_keys_from_pem_chain(pem_path)
        if main_public_keys_hex is None:
            logger.error(f"チェーン証明書の取得に失敗しました: {pem_path}")
            return None

        main_public_account = facade.create_public_account(PublicKey(main_public_keys_hex["main"]))
        return main_public_account

    except Exception as e:
        logger.error(f"メインパブリックアカウントの作成に失敗しました: {e}")
        return None


def get_public_account_from_pem(
    pem_path: str, facade: SymbolFacade
) -> Optional[SymbolPublicAccount]:
    """PEMファイルから公開アカウントを取得する

    Args:
        pem_path: PEMファイルのパス
        facade: SymbolFacadeインスタンス

    Returns:
        公開アカウント、失敗時はNone
    """
    try:
        public_key_pair = get_key_pair(pem_path)
        if public_key_pair is None:
            logger.error(f"PEMファイルの取得に失敗しました: {pem_path}")
            return None

        public_account = facade.create_public_account(public_key_pair.public_key)
        return public_account

    except Exception as e:
        logger.error(f"パブリックアカウントの作成に失敗しました: {e}")
        return None


def _process_key_link(
    key_type: str,
    current_key_hex: Optional[str],
    target_public_key: PublicKey,
    facade: SymbolFacade,
    main_public_key: PublicKey,
    create_transaction_func,
) -> List:
    """キーリンク処理の共通ロジック

    Args:
        account_link_keys: アカウントリンクキーの辞書
        key_type: キーの種類（"remote" または "vrf"）
        current_key_hex: 現在リンクされているキーの16進文字列
        target_public_key: 目標となる公開鍵
        facade: SymbolFacadeインスタンス
        main_public_key: メインアカウントの公開鍵
        create_transaction_func: トランザクション作成関数

    Returns:
        生成されたトランザクションのリスト
    """
    txs = []

    if current_key_hex is None:
        logger.info(f"{key_type}キーはリンクされていないのでリンクします。")
        tx = create_transaction_func(
            facade,
            main_public_key,
            target_public_key,
            True,
        )
        txs.append(tx)
    else:
        if current_key_hex == str(target_public_key):
            logger.info(f"{key_type}キーはすでにリンクされているので何もしません。")
        else:
            logger.info(
                f"{key_type}キーは異なるキーでリンクされているのでアンリンクして再リンクします。"
            )
            # アンリンク
            tx = create_transaction_func(
                facade,
                main_public_key,
                PublicKey(current_key_hex),
                False,
            )
            txs.append(tx)
            # リンク
            tx = create_transaction_func(
                facade,
                main_public_key,
                target_public_key,
                True,
            )
            txs.append(tx)

    return txs


def _validate_network_name(network_name: str) -> Literal["mainnet", "testnet"]:
    """ネットワーク名を検証し、適切な値に正規化する

    Args:
        network_name: 設定ファイルから取得したネットワーク名

    Returns:
        正規化されたネットワーク名（"mainnet" または "testnet"）
    """
    normalized = network_name.lower()
    if normalized in ["mainnet", "main"]:
        return "mainnet"
    elif normalized in ["testnet", "test"]:
        return "testnet"
    else:
        logger.warning(f"不明なネットワーク名: {network_name}, testnetを使用します")
        return "testnet"


def link_node_keys(args):
    """ノードキーをリンクする機能

    Args:
        args: コマンドライン引数
    """
    try:
        # ネットワーク名の取得と正規化
        raw_network_name = get_network_name(args.config)
        network_name = _validate_network_name(raw_network_name)
        facade = SymbolFacade(network_name)

        # メインパブリックアカウント
        main_public_account = get_public_account_from_pem_chain(
            args.keys_path + NODE_FULL_CERT_PEM_PATH,
            facade,
        )
        if main_public_account is None:
            logger.error("メインパブリックアカウントの取得に失敗しました。")
            return

        # リモートパブリックアカウント生成
        remote_public_account = get_public_account_from_pem(
            args.keys_path + REMOTE_KEY_PEM_PATH,
            facade,
        )
        if remote_public_account is None:
            logger.error("リモートパブリックアカウントの取得に失敗しました。")
            return

        # VRFパブリックアカウント生成
        vrf_public_account = get_public_account_from_pem(
            args.keys_path + VRF_KEY_PEM_PATH,
            facade,
        )
        if vrf_public_account is None:
            logger.error("VRFパブリックアカウントの取得に失敗しました。")
            return

        # 現在のリンク状況取得
        rest_gateway_url = get_rest_gateway_url(network_name)
        account_link_keys = get_account_link_keys(
            rest_gateway_url,
            main_public_account.address,
        )

        # トランザクションリスト
        txs = []

        # リモートキーの処理
        remote_txs = _process_key_link(
            "リモート",
            account_link_keys.get("linked"),  # 注意: "remote"ではなく"linked"
            remote_public_account.public_key,
            facade,
            main_public_account.public_key,
            create_remote_key_link_transaction,
        )
        txs.extend(remote_txs)

        # VRFキーの処理
        vrf_txs = _process_key_link(
            "VRF",
            account_link_keys.get("vrf"),
            vrf_public_account.public_key,
            facade,
            main_public_account.public_key,
            create_vrf_key_link_transaction,
        )
        txs.extend(vrf_txs)

        # ノードキー（ノードのアカウントはリンクしない）
        if account_link_keys.get("node") is not None:
            node_tx = _process_key_link(
                "ノード",
                account_link_keys.get("node"),
                main_public_account.public_key,
                facade,
                main_public_account.public_key,
                create_node_key_link_transaction,
            )
            txs.extend(node_tx)

        # アグリゲートトランザクションを生成
        if not txs:
            logger.info("リンクするキーがないため、アグリゲートトランザクションは生成されません。")
            return

        try:
            min_cosignatures_count = get_min_approval(rest_gateway_url, main_public_account.address)
            logger.info(f"マルチシグ最小承認数: {min_cosignatures_count}")
        except RestGatewayError as e:
            logger.warning(f"最小承認数の取得に失敗、デフォルト値1を使用: {e}")
            min_cosignatures_count = 1

        aggregate_tx = create_aggregate_transaction(
            rest_gateway_url,
            facade,
            txs,
            min_cosignatures_count,
        )

        logger.info(f"アグリゲートトランザクションを生成しました: {aggregate_tx}")
        print(f"シリアライズ化Tx: {aggregate_tx.serialize().hex()}")

    except RestGatewayError as e:
        logger.error(f"REST Gateway エラー: {e}")
        return
    except Exception as e:
        logger.error(f"ノードキーリンク処理中にエラーが発生しました: {e}")
        return


def get_common_link_args() -> argparse.ArgumentParser:
    """共通の引数を定義するヘルパー関数

    Returns:
        共通引数を定義したArgumentParser
    """
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-c",
        "--config",
        type=str,
        default=DEFAULT_CONFIG_PATH,
        help=f"ノードコンフィグパス [default: {DEFAULT_CONFIG_PATH}]",
    )
    parent.add_argument(
        "-k",
        "--keys-path",
        type=str,
        default=DEFAULT_KEYS_PATH,
        help=f"keysディレクトリパス [default: {DEFAULT_KEYS_PATH}]",
    )
    return parent


def setup_link_subparser(subparsers) -> None:
    """linkサブコマンドの設定を行う

    Args:
        subparsers: argparseのサブパーサー
    """
    # サブコマンド: link
    link_common_args = [get_common_link_args()]
    link_parser = subparsers.add_parser(
        "link", help="ハーベスティングリンク", parents=link_common_args
    )
    link_parser.set_defaults(func=link_node_keys)
