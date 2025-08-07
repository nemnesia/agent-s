import configparser
import logging
from typing import Optional, Dict

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from symbolchain.CryptoTypes import PrivateKey
from symbolchain.symbol.KeyPair import KeyPair

# ログ設定
logger = logging.getLogger(__name__)

# 定数の定義
NODE_FULL_CERT_PEM_PATH = "/cert/node.full.crt.pem"
NODE_KEY_PEM_PATH = "/cert/node.key.pem"
REMOTE_KEY_PEM_PATH = "/remote.pem"
VRF_KEY_PEM_PATH = "/vrf.pem"

# DERバイト処理用の定数
PKCS8_PRIVATE_KEY_PREFIX_SIZE = 16
SUBJECT_PUBLIC_KEY_INFO_PREFIX_SIZE = 12


def get_network_name(config_path: str) -> str:
    """コンフィグファイルからネットワーク名を取得する

    Args:
        config_path: 設定ファイルのパス

    Returns:
        ネットワーク名（デフォルト: "testnet"）
    """
    try:
        config = configparser.ConfigParser()
        read_files = config.read(config_path, encoding="utf-8")
        if not read_files:
            raise FileNotFoundError(f"設定ファイルが見つかりません: {config_path}")
        return config.get("network", "name", fallback="testnet")
    except (configparser.Error, OSError) as e:
        logger.warning(f"設定ファイルの読み込みに失敗しました: {e}")
        return "testnet"


def _extract_private_key_bytes(private_key_obj) -> str:
    """秘密鍵オブジェクトからDERバイトを抽出し、16進文字列に変換する

    Args:
        private_key_obj: 暗号化された秘密鍵オブジェクト

    Returns:
        16進文字列の秘密鍵
    """
    der_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # PKCS8形式のプレフィックスを削除
    return der_bytes[PKCS8_PRIVATE_KEY_PREFIX_SIZE:].hex().upper()


def get_key_pair(key_pem_path: str) -> Optional[KeyPair]:
    """PEMファイルから秘密鍵を読み込み、キーペアを生成する

    Args:
        key_pem_path: PEM形式の秘密鍵ファイルのパス

    Returns:
        キーペアオブジェクト、失敗時はNone
    """
    try:
        with open(key_pem_path, "rb") as key_pem_file:
            key_pem_data = key_pem_file.read()

        private_key_obj = serialization.load_pem_private_key(
            key_pem_data, password=None, backend=default_backend()
        )

        private_key_hex = _extract_private_key_bytes(private_key_obj)

        # キーペア生成
        private_key = PrivateKey(private_key_hex)
        return KeyPair(private_key)

    except (OSError, ValueError, TypeError) as e:
        logger.error(
            f"PEMファイルから秘密鍵の読み込みに失敗しました ({key_pem_path}): {e}"
        )
        return None
    except Exception as e:
        logger.error(f"予期しないエラーが発生しました ({key_pem_path}): {e}")
        return None


def _extract_public_key_hex(cert: x509.Certificate) -> str:
    """証明書から公開鍵を16進文字列として抽出する

    Args:
        cert: X.509証明書オブジェクト

    Returns:
        16進文字列の公開鍵
    """
    der_bytes = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # SubjectPublicKeyInfoのプレフィックスを削除
    return der_bytes[SUBJECT_PUBLIC_KEY_INFO_PREFIX_SIZE:].hex().upper()


def get_public_keys_from_pem_chain(cert_path: str) -> Optional[Dict[str, str]]:
    """PEMチェーンファイルから公開鍵を取得し、辞書で返す

    Args:
        cert_path: PEM形式の証明書チェーンファイルのパス

    Returns:
        公開鍵の辞書 {'node': '...', 'main': '...'}、失敗時はNone
    """
    try:
        with open(cert_path, "rb") as cert_file:
            pem_data = cert_file.read()

        # PEM証明書ごとに分割
        cert_sections = pem_data.split(b"-----END CERTIFICATE-----")
        keys = {}

        for idx, cert_pem in enumerate(cert_sections):
            cert_pem = cert_pem.strip()
            if not cert_pem:
                continue

            # 証明書の終端を復元
            cert_pem += b"\n-----END CERTIFICATE-----\n"

            try:
                cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                public_key_hex = _extract_public_key_hex(cert)

                # インデックスに基づいてキーを分類
                if idx == 0:
                    keys["node"] = public_key_hex
                elif idx == 1:
                    keys["main"] = public_key_hex

            except ValueError as e:
                logger.warning(f"証明書 {idx} の解析に失敗しました: {e}")
                continue

        return keys if keys else None

    except OSError as e:
        logger.error(f"PEMチェーンファイルの読み込みに失敗しました ({cert_path}): {e}")
        return None
    except Exception as e:
        logger.error(f"予期しないエラーが発生しました ({cert_path}): {e}")
        return None
