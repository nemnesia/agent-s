import argparse
import configparser

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.facade.SymbolFacade import SymbolFacade
from symbolchain.symbol.KeyPair import KeyPair

NODE_KEY_PEM = "/cert/node.key.pem"
REMOTE_KEY_PEM = "/remote.pem"
VRF_KEY_PEM = "/vrf.pem"


def get_network_name(config_path):
    """コンフィグファイルからネットワーク名を取得する"""
    config = configparser.ConfigParser()
    config.read(config_path, encoding="utf-8")
    return config.get("network", "name", fallback="testnet")


def read_public_keys_from_pem_chain(cert_path):
    """PEMファイルから公開鍵を取得し、リストで返す"""
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
                    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
                    # 16進文字列で表示
                    der_bytes = cert.public_key().public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    der_bytes = der_bytes[12:]  # 先頭12バイトを削除
                    public_keys.append(der_bytes)
            return public_keys
    except Exception as e:
        print(f"Error reading public keys from PEM chain: {e}")
        return []


def read_private_key_from_pem(pem_path):
    """PEMファイルから秘密鍵を取得し、16進文字列で返す"""
    try:
        with open(pem_path, "rb") as ca_key_file:
            ca_key_data = ca_key_file.read()
            private_key_obj = serialization.load_pem_private_key(
                ca_key_data, password=None, backend=default_backend()
            )
            der_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            der_bytes = der_bytes[16:]  # 先頭16バイトを削除
            return der_bytes.hex().upper()
    except Exception as e:
        print(f"Error reading private key from PEM: {e}")
        return None


def show_account_info(args, account_type, private_key_path, cert_index, label):
    """アカウント情報を表示する共通関数"""
    facade = SymbolFacade(get_network_name(args.config))

    # 秘密鍵を読み込む
    private_key_hex = read_private_key_from_pem(private_key_path)
    if private_key_hex is not None:
        key_pair = KeyPair(PrivateKey(private_key_hex))
        private_public_key = key_pair.public_key
    else:
        private_public_key = None

    # 証明書から公開鍵を取得（main/nodeのみ）
    cert_public_key = None
    cert_public_account = None
    if account_type in ("main", "node"):
        cert_public_keys = read_public_keys_from_pem_chain(
            args.keys_path + "/cert/node.full.crt.pem"
        )
        if not cert_public_keys or len(cert_public_keys) <= cert_index:
            print(f"証明書から{label}公開鍵の取得に失敗しました。")
            return
        cert_public_key = PublicKey(cert_public_keys[cert_index])
        cert_public_account = facade.create_public_account(cert_public_key)

        # 秘密鍵と証明書の公開鍵が一致するかチェック
        if private_public_key is not None and private_public_key != cert_public_key:
            print(f"{label}証明書の秘密鍵と公開鍵が一致しません。")
            return

    # アカウント情報を表示
    print(f"{label}アカウント情報:")
    if cert_public_account:
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

    if args.show_private_key and private_key_hex is not None:
        print(f"  秘密鍵  : {private_key_hex}")


def show_main(args):
    """メインアカウントの情報を表示する"""
    show_account_info(args, "main", args.ca_key_path, 1, "メイン")


def show_node(args):
    """ノードアカウントの情報を表示する"""
    show_account_info(args, "node", args.keys_path + NODE_KEY_PEM, 0, "ノード")


def show_remote(args):
    """リモートアカウントの情報を表示する"""
    show_account_info(args, "remote", args.keys_path + REMOTE_KEY_PEM, None, "リモート")


def show_vrf(args):
    """VRFアカウントの情報を表示する"""
    show_account_info(args, "vrf", args.keys_path + VRF_KEY_PEM, None, "VRF")


def get_common_showkey_args():
    """共通の引数を定義するヘルパー関数"""
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-c",
        "--config",
        type=str,
        default="shoestring/shoestring.ini",
        help="ノードコンフィグパス[default: shoestring/shoestring.ini]",
    )
    parent.add_argument(
        "-ca",
        "--ca-key-path",
        type=str,
        default="ca.key.pem",
        help="CA証明書パス[default: ca.key.pem]",
    )
    parent.add_argument(
        "-k",
        "--keys-path",
        type=str,
        default="keys",
        help="keysディレクトリパス[default: keys]",
    )
    parent.add_argument(
        "-p",
        "--show-private-key",
        action="store_true",
        help="プライベートキーを表示する",
    )
    return parent


def get_common_link_args():
    """共通の引数を定義するヘルパー関数"""
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-c",
        "--config",
        type=str,
        default="shoestring/shoestring.ini",
        help="ノードコンフィグパス[default: shoestring/shoestring.ini]",
    )
    parent.add_argument(
        "-k",
        "--keys-path",
        type=str,
        default="keys",
        help="keysディレクトリパス[default: keys]",
    )
    return parent


def link_node_keys(args):
    print("ノードキーをリンクする機能はまだ実装されていません。")


def unlink_node_keys(args):
    print("ノードキーをアンリンクする機能はまだ実装されていません。")


def main():
    parser = argparse.ArgumentParser(description="エージェントS")
    subparsers = parser.add_subparsers(
        title="サブコマンド", metavar="", dest="command", required=True
    )

    # サブコマンド: show-key
    show_parser = subparsers.add_parser("show-key", help="ノードキー参照")
    show_subparsers = show_parser.add_subparsers(
        title="サブコマンド", metavar="ノードキー参照", dest="target", required=True
    )
    # サブコマンド: show-key main
    show_common_args = [get_common_showkey_args()]
    show_main_parser = show_subparsers.add_parser(
        "main", help="メインキー情報を表示", parents=show_common_args
    )
    show_main_parser.set_defaults(func=show_main)
    # サブコマンド: show-key node
    show_node_parser = show_subparsers.add_parser(
        "node", help="ノードキー情報を表示", parents=show_common_args
    )
    show_node_parser.set_defaults(func=show_node)
    # サブコマンド: show-key remote
    show_remote_parser = show_subparsers.add_parser(
        "remote", help="リモートキー情報を表示", parents=show_common_args
    )
    show_remote_parser.set_defaults(func=show_remote)
    # サブコマンド: show-key vrf
    show_vrf_parser = show_subparsers.add_parser(
        "vrf", help="VRFキー情報を表示", parents=show_common_args
    )
    show_vrf_parser.set_defaults(func=show_vrf)

    # # サブコマンド: link
    # link_common_args = [get_common_link_args()]
    # link_parser = subparsers.add_parser(
    #     "link", help="ハーベスティングリンク", parents=link_common_args
    # )
    # link_parser.set_defaults(func=link_node_keys)

    # # サブコマンド: unlink
    # unlink_parser = subparsers.add_parser(
    #     "unlink", help="ハーベスティングアンリンク", parents=link_common_args
    # )
    # unlink_parser.set_defaults(func=unlink_node_keys)

    # 実行
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
