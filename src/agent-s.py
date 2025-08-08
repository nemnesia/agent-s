#!/usr/bin/env python3
"""
Agent-S: Symbol blockchain node key management tool
"""

import argparse
import logging
import sys
from typing import NoReturn

from commands.backup import setup_backup_subparser
from commands.restore import setup_restore_subparser
from commands.show_key import setup_show_key_subparser
from commands.link import setup_link_subparser


def setup_logging(verbose: bool = False) -> None:
    """ログ設定を初期化する

    Args:
        verbose: 詳細ログを有効にするかどうか
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def main() -> NoReturn:
    """メイン関数"""
    try:
        parser = argparse.ArgumentParser(
            description="エージェントS - Symbol ブロックチェーンノードキー管理ツール",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument(
            "-v", "--verbose", action="store_true", help="詳細ログを有効にする"
        )

        subparsers = parser.add_subparsers(
            title="サブコマンド",
            metavar="",
            dest="command",
            required=True,
            help="利用可能なサブコマンド",
        )

        # サブコマンド: show-key
        setup_show_key_subparser(subparsers)

        # サブコマンド: link
        setup_link_subparser(subparsers)

        # サブコマンド: backup
        setup_backup_subparser(subparsers)

        # サブコマンド: restore
        setup_restore_subparser(subparsers)

        # 引数解析
        args = parser.parse_args()

        # ログ設定
        setup_logging(args.verbose)

        # サブコマンド実行
        args.func(args)

    except KeyboardInterrupt:
        logging.info("処理が中断されました")
        sys.exit(1)
    except Exception as e:
        logging.error(f"予期しないエラーが発生しました: {e}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
