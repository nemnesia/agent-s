import argparse
import getpass
import logging
import os
import tarfile
import tempfile

import pexpect

# ログ設定
logger = logging.getLogger(__name__)

# 定数の定義
DEFAULT_INPUT_PATH = "age.sandcat"
DEFAULT_OUTPUT_PATH = "."


def restore_node_keys(args):
    """ノードキーをレストアする関数

    Args:
        args: コマンドライン引数
    """
    input_path = args.input
    output_path = args.output

    # パスフレーズ入力
    password = getpass.getpass("復号用パスフレーズを入力してください: ")

    # 一時ディレクトリを作成してage復号とtar展開を実行
    with tempfile.TemporaryDirectory() as tmpdir:
        decrypted_tar_path = os.path.join(tmpdir, "restored.tar")

        # age復号化処理
        if not _decrypt_age_file(input_path, decrypted_tar_path, password):
            return

        # tar展開処理
        _extract_tar_with_confirmation(decrypted_tar_path, output_path)


def _decrypt_age_file(input_path: str, output_path: str, password: str) -> bool:
    """ageファイルを復号化する

    Args:
        input_path: 暗号化されたファイルのパス
        output_path: 復号化後のファイルパス
        password: パスフレーズ

    Returns:
        bool: 成功した場合True、失敗した場合False
    """
    try:
        cmd = f"age -d --output {output_path} {input_path}"
        child = pexpect.spawn(cmd, encoding="utf-8", timeout=60)
        child.expect("Enter passphrase", timeout=10)
        child.sendline(password)
        child.expect(pexpect.EOF, timeout=30)
        child.close()

        if not os.path.exists(output_path):
            raise RuntimeError("復号化ファイルが作成されませんでした")

        return True
    except Exception as e:
        logger.error(f"AGE復号化に失敗しました: {e}")
        print("AGE復号化に失敗しました。")
        return False


def _extract_tar_with_confirmation(tar_path: str, output_path: str) -> None:
    """上書き確認付きでtarファイルを展開する

    Args:
        tar_path: tarファイルのパス
        output_path: 展開先のディレクトリパス
    """
    try:
        with tarfile.open(tar_path, "r") as tar:
            # 既存ファイルとの重複をチェック
            existing_files = _check_existing_files(tar, output_path)

            # 既存ファイルがある場合は確認
            if existing_files and not _confirm_overwrite(existing_files):
                print("レストアを中止しました。")
                return

            # 既存ファイルを削除
            if existing_files:
                _remove_existing_files(existing_files, output_path)

            # tarで展開
            tar.extractall(path=output_path)
            logger.info(f"Restored files to {output_path}")
            print(f"ファイルを復元しました: {output_path}")

    except Exception as e:
        logger.error(f"tar extract error: {e}")
        print("tar展開に失敗しました。")


def _check_existing_files(tar: tarfile.TarFile, output_path: str) -> list:
    """既存ファイルとの重複をチェックする

    Args:
        tar: tarファイルオブジェクト
        output_path: 出力先パス

    Returns:
        list: 既存ファイルのリスト
    """
    existing_files = []
    for member in tar.getmembers():
        if member.isfile():
            target_path = os.path.join(output_path, member.name)
            if os.path.exists(target_path):
                existing_files.append(member.name)
    return existing_files


def _confirm_overwrite(existing_files: list) -> bool:
    """上書きの確認を行う

    Args:
        existing_files: 既存ファイルのリスト

    Returns:
        bool: 上書きする場合True、しない場合False
    """
    print("\n以下のファイルが既に存在します:")
    for file in existing_files:
        print(f"  {file}")

    while True:
        response = input("\n上書きしますか？ (y/n): ").lower().strip()
        if response in ["y", "yes"]:
            return True
        elif response in ["n", "no"]:
            return False
        else:
            print("yまたはnを入力してください。")


def _remove_existing_files(existing_files: list, output_path: str) -> None:
    """既存ファイルを削除する

    Args:
        existing_files: 削除するファイルのリスト
        output_path: 出力先パス
    """
    print("既存ファイルを削除しています...")
    for file in existing_files:
        target_path = os.path.join(output_path, file)
        try:
            # 読み取り専用の場合は書き込み権限を付与してから削除
            os.chmod(target_path, 0o644)
            os.remove(target_path)
        except Exception as e:
            logger.warning(f"ファイル削除に失敗: {target_path}: {e}")


def get_common_restore_args() -> argparse.ArgumentParser:
    """共通の引数を定義するヘルパー関数

    Returns:
        共通引数を定義したArgumentParser
    """
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument(
        "-i",
        "--input",
        type=str,
        default=DEFAULT_INPUT_PATH,
        help=f"入力ファイルパス [default: {DEFAULT_INPUT_PATH}]",
    )
    parent.add_argument(
        "-o",
        "--output",
        type=str,
        default=DEFAULT_OUTPUT_PATH,
        help=f"出力ディレクトリパス [default: {DEFAULT_OUTPUT_PATH}]",
    )
    return parent


def setup_restore_subparser(subparsers) -> None:
    """restoreサブコマンドの設定を行う

    Args:
        subparsers: argparseのサブパーサー
    """
    restore_common_args = [get_common_restore_args()]
    restore_parser = subparsers.add_parser(
        "restore", help="ノードキーレストア", parents=restore_common_args
    )
    restore_parser.set_defaults(func=restore_node_keys)
