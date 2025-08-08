import argparse
import configparser
import logging
from typing import List, Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.facade.SymbolFacade import SymbolFacade, SymbolPublicAccount
from symbolchain.symbol.KeyPair import KeyPair

# ログ設定
logger = logging.getLogger(__name__)

# 定数の定義
NODE_KEY_PEM = "/cert/node.key.pem"
REMOTE_KEY_PEM = "/remote.pem"
VRF_KEY_PEM = "/vrf.pem"
NODE_FULL_CERT_PEM = "/cert/node.full.crt.pem"
DEFAULT_CONFIG_PATH = "shoestring/shoestring.ini"
DEFAULT_CA_KEY_PATH = "ca.key.pem"
DEFAULT_KEYS_PATH = "keys"

# DER形式での削除バイト数定数
DER_PUBLIC_KEY_HEADER_SIZE = 12
DER_PRIVATE_KEY_HEADER_SIZE = 16


def get_network_name(config_path: str) -> str:
    """設定ファイルからネットワーク名を取得する

    Args:
        config_path: 設定ファイルのパス

    Returns:
        ネットワーク名（デフォルト: "testnet"）
    """
    try:
        config = configparser.ConfigParser()
        config.read(config_path, encoding="utf-8")
        network_name = config.get("network", "name", fallback="testnet")
        logger.debug(f"ネットワーク名を取得: {network_name}")
        return network_name
    except Exception as e:
        logger.warning(f"設定ファイルの読み込みに失敗、デフォルトを使用: {e}")
        return "testnet"


def _extract_public_key_from_cert(cert: x509.Certificate) -> bytes:
    """証明書から公開鍵のDERバイトを抽出する

    Args:
        cert: X.509証明書

    Returns:
        公開鍵のDERバイト（ヘッダ削除済み）
    """
    der_bytes = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return der_bytes[DER_PUBLIC_KEY_HEADER_SIZE:]  # ヘッダを削除


def read_public_keys_from_pem_chain(cert_path: str) -> List[bytes]:
    """PEM証明書チェーンファイルから公開鍵を取得する

    Args:
        cert_path: PEM証明書チェーンファイルのパス

    Returns:
        公開鍵のバイトリスト
    """
    try:
        with open(cert_path, "rb") as cert_file:
            pem_data = cert_file.read()

        # PEM証明書ごとに分割
        certs = pem_data.split(b"-----END CERTIFICATE-----")
        public_keys = []

        for cert_pem in certs:
            cert_pem = cert_pem.strip()
            if cert_pem:
                cert_pem += b"\n-----END CERTIFICATE-----\n"
                try:
                    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                    public_key_bytes = _extract_public_key_from_cert(cert)
                    public_keys.append(public_key_bytes)
                except Exception as cert_error:
                    logger.warning(f"証明書の解析に失敗: {cert_error}")
                    continue

        logger.debug(f"{len(public_keys)}個の公開鍵を取得: {cert_path}")
        return public_keys

    except FileNotFoundError:
        logger.error(f"PEM証明書ファイルが見つかりません: {cert_path}")
        return []
    except Exception as e:
        logger.error(f"PEM証明書チェーンの読み込みに失敗: {e}")
        return []


def read_private_key_from_pem(pem_path: str) -> Optional[str]:
    """PEMファイルから秘密鍵を取得し、16進文字列で返す

    Args:
        pem_path: PEMファイルのパス

    Returns:
        秘密鍵の16進文字列、失敗時はNone
    """
    try:
        with open(pem_path, "rb") as key_file:
            key_data = key_file.read()

        private_key_obj = serialization.load_pem_private_key(
            key_data, password=None, backend=default_backend()
        )

        der_bytes = private_key_obj.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # ヘッダを削除して16進文字列に変換
        private_key_hex = der_bytes[DER_PRIVATE_KEY_HEADER_SIZE:].hex().upper()
        logger.debug(f"秘密鍵を取得: {pem_path}")
        return private_key_hex

    except FileNotFoundError:
        logger.error(f"秘密鍵ファイルが見つかりません: {pem_path}")
        return None
    except Exception as e:
        logger.error(f"秘密鍵の読み込みに失敗: {e}")
        return None


def _create_facade_and_keypair(
    config_path: str, private_key_path: str
) -> tuple[SymbolFacade, Optional[KeyPair]]:
    """ファサードとキーペアを作成する

    Args:
        config_path: 設定ファイルのパス
        private_key_path: 秘密鍵ファイルのパス

    Returns:
        (SymbolFacadeインスタンス, KeyPairインスタンスまたはNone)
    """
    facade = SymbolFacade(get_network_name(config_path))

    private_key_hex = read_private_key_from_pem(private_key_path)
    if private_key_hex is not None:
        key_pair = KeyPair(PrivateKey(private_key_hex))
        return facade, key_pair

    return facade, None


def _get_cert_public_key_info(
    keys_path: str, cert_index: int, label: str, facade: SymbolFacade
) -> tuple[Optional[PublicKey], Optional[SymbolPublicAccount]]:
    """証明書から公開鍵情報を取得する

    Args:
        keys_path: keysディレクトリのパス
        cert_index: 証明書チェーン内のインデックス
        label: ラベル（ログ用）
        facade: SymbolFacadeインスタンス

    Returns:
        (公開鍵, パブリックアカウント)
    """
    cert_path = keys_path + NODE_FULL_CERT_PEM
    cert_public_keys = read_public_keys_from_pem_chain(cert_path)

    if not cert_public_keys or len(cert_public_keys) <= cert_index:
        logger.error(f"証明書から{label}公開鍵の取得に失敗")
        return None, None

    cert_public_key = PublicKey(cert_public_keys[cert_index])
    cert_public_account = facade.create_public_account(cert_public_key)

    return cert_public_key, cert_public_account


def _validate_key_consistency(
    private_public_key: Optional[PublicKey],
    cert_public_key: Optional[PublicKey],
    label: str,
) -> bool:
    """秘密鍵と証明書の公開鍵の整合性をチェックする

    Args:
        private_public_key: 秘密鍵から生成した公開鍵
        cert_public_key: 証明書の公開鍵
        label: ラベル（ログ用）

    Returns:
        整合性があるか
    """
    if private_public_key is not None and cert_public_key is not None:
        if private_public_key != cert_public_key:
            logger.error(f"{label}証明書の秘密鍵と公開鍵が一致しません")
            return False
    return True


def _display_account_info(
    label: str,
    cert_public_account: Optional[SymbolPublicAccount],
    cert_public_key: Optional[PublicKey],
    private_public_key: Optional[PublicKey],
    private_key_hex: Optional[str],
    show_private_key: bool,
    facade: SymbolFacade,
) -> None:
    """アカウント情報を表示する

    Args:
        label: 表示用ラベル
        cert_public_account: 証明書由来のパブリックアカウント
        cert_public_key: 証明書由来の公開鍵
        private_public_key: 秘密鍵由来の公開鍵
        private_key_hex: 秘密鍵の16進文字列
        show_private_key: 秘密鍵を表示するか
        facade: SymbolFacadeインスタンス
    """
    print(f"{label}アカウント情報:")

    if cert_public_account and cert_public_key:
        print(f"  アドレス: {cert_public_account.address}")
        print(f"  公開鍵  : {cert_public_key}")
    elif private_public_key is not None:
        # remote/vrfは証明書がないので秘密鍵から生成
        account = facade.create_public_account(private_public_key)
        print(f"  アドレス: {account.address}")
        print(f"  公開鍵  : {private_public_key}")
    else:
        print(f"{label}キーの秘密鍵が読み込めませんでした。")
        return

    if show_private_key and private_key_hex is not None:
        print(f"  秘密鍵  : {private_key_hex}")


def show_account_info(
    args,
    account_type: str,
    private_key_path: str,
    cert_index: Optional[int],
    label: str,
) -> None:
    """アカウント情報を表示する共通関数

    Args:
        args: コマンドライン引数
        account_type: アカウントタイプ（"main", "node", "remote", "vrf"）
        private_key_path: 秘密鍵ファイルのパス
        cert_index: 証明書チェーン内のインデックス（main/nodeのみ）
        label: 表示用ラベル
    """
    try:
        # ファサードとキーペアを作成
        facade, key_pair = _create_facade_and_keypair(args.config, private_key_path)
        private_public_key = key_pair.public_key if key_pair else None
        private_key_hex = key_pair.private_key.bytes.hex().upper() if key_pair else None

        cert_public_key = None
        cert_public_account = None

        # 証明書から公開鍵を取得（main/nodeのみ）
        if account_type in ("main", "node") and cert_index is not None:
            cert_public_key, cert_public_account = _get_cert_public_key_info(
                args.keys_path, cert_index, label, facade
            )

            if cert_public_key is None:
                print(f"証明書から{label}公開鍵の取得に失敗しました。")
                return

            # 秘密鍵と証明書の公開鍵の整合性をチェック
            if not _validate_key_consistency(private_public_key, cert_public_key, label):
                print(f"{label}証明書の秘密鍵と公開鍵が一致しません。")
                return

        # アカウント情報を表示
        _display_account_info(
            label,
            cert_public_account,
            cert_public_key,
            private_public_key,
            private_key_hex,
            args.show_private_key,
            facade,
        )

    except Exception as e:
        logger.error(f"{label}アカウント情報の表示に失敗: {e}")
        print(f"{label}アカウント情報の取得に失敗しました。")


def show_main(args) -> None:
    """メインアカウントの情報を表示する

    Args:
        args: コマンドライン引数
    """
    show_account_info(args, "main", args.ca_key_path, 1, "メイン")


def show_node(args) -> None:
    """ノードアカウントの情報を表示する

    Args:
        args: コマンドライン引数
    """
    show_account_info(args, "node", args.keys_path + NODE_KEY_PEM, 0, "ノード")


def show_remote(args) -> None:
    """リモートアカウントの情報を表示する

    Args:
        args: コマンドライン引数
    """
    show_account_info(args, "remote", args.keys_path + REMOTE_KEY_PEM, None, "リモート")


def show_vrf(args) -> None:
    """VRFアカウントの情報を表示する

    Args:
        args: コマンドライン引数
    """
    show_account_info(args, "vrf", args.keys_path + VRF_KEY_PEM, None, "VRF")


def get_common_showkey_args() -> argparse.ArgumentParser:
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
        "-ca",
        "--ca-key-path",
        type=str,
        default=DEFAULT_CA_KEY_PATH,
        help=f"CA証明書パス [default: {DEFAULT_CA_KEY_PATH}]",
    )
    parent.add_argument(
        "-k",
        "--keys-path",
        type=str,
        default=DEFAULT_KEYS_PATH,
        help=f"keysディレクトリパス [default: {DEFAULT_KEYS_PATH}]",
    )
    parent.add_argument(
        "-p",
        "--show-private-key",
        action="store_true",
        help="プライベートキーを表示する",
    )
    return parent


def _create_subparser(
    subparsers,
    name: str,
    help_text: str,
    func,
    common_args: List[argparse.ArgumentParser],
) -> None:
    """サブパーサーを作成するヘルパー関数

    Args:
        subparsers: サブパーサーオブジェクト
        name: サブコマンド名
        help_text: ヘルプテキスト
        func: 実行する関数
        common_args: 共通引数のリスト
    """
    parser = subparsers.add_parser(name, help=help_text, parents=common_args)
    parser.set_defaults(func=func)


def setup_show_key_subparser(subparsers) -> None:
    """show-keyサブコマンドの設定を行う

    Args:
        subparsers: argparseのサブパーサー
    """
    # サブコマンド: show-key
    show_parser = subparsers.add_parser("show-key", help="ノードキー参照")
    show_subparsers = show_parser.add_subparsers(
        title="サブコマンド", metavar="ノードキー参照", dest="target", required=True
    )

    # 共通引数の定義
    show_common_args = [get_common_showkey_args()]

    # 各サブコマンドの設定
    subcommands = [
        ("main", "メインキー情報を表示", show_main),
        ("node", "ノードキー情報を表示", show_node),
        ("remote", "リモートキー情報を表示", show_remote),
        ("vrf", "VRFキー情報を表示", show_vrf),
    ]

    for name, help_text, func in subcommands:
        _create_subparser(show_subparsers, name, help_text, func, show_common_args)
