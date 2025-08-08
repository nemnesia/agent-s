import argparse
import getpass
import logging
import os
import re
import shutil
import tempfile

import pexpect

# ログ設定
logger = logging.getLogger(__name__)

# 定数の定義
DEFAULT_CONFIG_PATH = "shoestring"
DEFAULT_KEYS_PATH = "keys"
DEFAULT_CA_KEY_PATH = "ca.key.pem"
DEFAULT_OUTPUT_PATH = "age.sandcat"

# パスワード要件
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 32
PASSWORD_MIN_CATEGORIES = 3


def backup_node_keys(args):
    """ノードキーをバックアップする関数

    Args:
        args: コマンドライン引数
    """
    # パスワード入力・検証
    password = _get_validated_password()

    # 一時ディレクトリでバックアップファイル作成
    with tempfile.TemporaryDirectory() as tmpdir:
        # ファイル・ディレクトリをコピー
        _copy_backup_files(args, tmpdir)

        # tarアーカイブ作成と暗号化
        _create_encrypted_backup(tmpdir, args.output, password)


def _get_validated_password() -> str:
    """パスワードの入力・検証を行う

    Returns:
        str: 検証されたパスワード
    """
    while True:
        password = getpass.getpass("バックアップ用パスワードを入力してください: ")
        if not _validate_password(password):
            print(
                f"パスワードは{PASSWORD_MIN_LENGTH}文字以上{PASSWORD_MAX_LENGTH}文字以下で"
                f"大文字・小文字・数字・記号のうち{PASSWORD_MIN_CATEGORIES}種類以上を含めてください。"
            )
            continue

        password_confirm = getpass.getpass("確認のためもう一度入力してください: ")
        if password != password_confirm:
            print("パスワードが一致しません。")
            continue

        return password


def _validate_password(password: str) -> bool:
    """パスワードの強度を検証する

    Args:
        password: 検証するパスワード

    Returns:
        bool: パスワードが要件を満たす場合True
    """
    if not (PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH):
        return False

    categories = 0
    if re.search(r"[A-Z]", password):
        categories += 1
    if re.search(r"[a-z]", password):
        categories += 1
    if re.search(r"[0-9]", password):
        categories += 1
    if re.search(r"[^A-Za-z0-9]", password):
        categories += 1

    return categories >= PASSWORD_MIN_CATEGORIES


def _copy_backup_files(args, tmpdir: str) -> None:
    """バックアップ対象ファイルを一時ディレクトリにコピーする

    Args:
        args: コマンドライン引数
        tmpdir: 一時ディレクトリパス
    """
    # コンフィグディレクトリ/ファイルをコピー
    config_dst = os.path.join(tmpdir, os.path.basename(args.config))
    if os.path.isdir(args.config):
        shutil.copytree(args.config, config_dst)
    else:
        shutil.copy2(args.config, config_dst)

    # CA証明書をコピー
    ca_dst = os.path.join(tmpdir, os.path.basename(args.ca_key_path))
    shutil.copy2(args.ca_key_path, ca_dst)

    # keysディレクトリ/ファイルをコピー
    keys_dst = os.path.join(tmpdir, os.path.basename(args.keys_path))
    if os.path.isdir(args.keys_path):
        shutil.copytree(args.keys_path, keys_dst)
    else:
        shutil.copy2(args.keys_path, keys_dst)


def _create_encrypted_backup(tmpdir: str, output_path: str, password: str) -> None:
    """tarアーカイブを作成しage暗号化する

    Args:
        tmpdir: バックアップファイルがある一時ディレクトリ
        output_path: 出力ファイルパス
        password: 暗号化パスワード
    """
    # tarアーカイブ作成
    tar_path = os.path.join(tmpdir, "backup.tar")
    shutil.make_archive(base_name=tar_path[:-4], format="tar", root_dir=tmpdir)

    # age暗号化
    try:
        _encrypt_with_age(tar_path, output_path, password)
        print(f"バックアップファイルを作成しました: {output_path}")

        # ファイルを最終位置に移動
        final_output = os.path.abspath(output_path)
        shutil.move(output_path, final_output)
        print(f"バックアップファイルを保存しました: {final_output}")

    except Exception as e:
        logger.error(f"バックアップ作成に失敗しました: {e}")
        print("バックアップ作成に失敗しました。")
        raise


def _encrypt_with_age(input_path: str, output_path: str, password: str) -> None:
    """ageを使用してファイルを暗号化する

    Args:
        input_path: 暗号化するファイルパス
        output_path: 暗号化後のファイルパス
        password: パスフレーズ

    Raises:
        RuntimeError: 暗号化に失敗した場合
    """
    cmd = f"age --passphrase --output {output_path} {input_path}"
    child = pexpect.spawn(cmd, encoding="utf-8", timeout=60)

    try:
        child.expect("Enter passphrase", timeout=10)
        child.sendline(password)
        child.expect("Confirm passphrase", timeout=10)
        child.sendline(password)
        child.expect(pexpect.EOF, timeout=30)
        child.close()

        if not os.path.exists(output_path):
            raise RuntimeError("暗号化ファイルが作成されませんでした")

    except Exception as e:
        logger.error(f"AGE暗号化に失敗しました: {e}")
        raise RuntimeError(f"AGE暗号化に失敗しました: {e}")


def get_common_backup_args() -> argparse.ArgumentParser:
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
        help=f"ノードコンフィグディレクトリパス [default: {DEFAULT_CONFIG_PATH}]",
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
        "-o",
        "--output",
        type=str,
        default=DEFAULT_OUTPUT_PATH,
        help=f"出力ファイルパス [default: {DEFAULT_OUTPUT_PATH}]",
    )
    return parent


def setup_backup_subparser(subparsers) -> None:
    """backupサブコマンドの設定を行う

    Args:
        subparsers: argparseのサブパーサー
    """
    backup_common_args = [get_common_backup_args()]
    backup_parser = subparsers.add_parser(
        "backup", help="ノードキーバックアップ", parents=backup_common_args
    )
    backup_parser.set_defaults(func=backup_node_keys)
