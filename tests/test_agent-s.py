"""
Agent-S メインモジュールのテストケース
"""

import pytest
import sys
import logging
import argparse
from unittest.mock import patch, Mock, MagicMock
from io import StringIO

# テスト対象のインポート
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

# agent-s.pyのインポート（直接的な方法）
import importlib.util

agent_s_path = os.path.join(os.path.dirname(__file__), "..", "src", "agent-s.py")
spec = importlib.util.spec_from_file_location("agent_s", agent_s_path)
if spec is not None and spec.loader is not None:
    agent_s = importlib.util.module_from_spec(spec)
    sys.modules["agent_s"] = agent_s
    spec.loader.exec_module(agent_s)
else:
    raise ImportError("Could not import agent-s.py")


class TestSetupLogging:
    """setup_logging関数のテストクラス"""

    def test_setup_logging_default(self):
        """デフォルト設定でのログ設定テスト"""
        # ログの状態をリセット
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.root.setLevel(logging.WARNING)

        agent_s.setup_logging()

        # basicConfigが呼ばれたことを確認（レベルの確認）
        # ルートロガーのハンドラーが追加されていることを確認
        assert len(logging.root.handlers) > 0

    def test_setup_logging_verbose(self):
        """詳細ログ設定テスト"""
        # ログの状態をリセット
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.root.setLevel(logging.WARNING)

        agent_s.setup_logging(verbose=True)

        # verboseモードでハンドラーが設定されていることを確認
        assert len(logging.root.handlers) > 0

    def test_setup_logging_false_verbose(self):
        """verbose=Falseの場合のログ設定テスト"""
        # ログの状態をリセット
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        logging.root.setLevel(logging.WARNING)

        agent_s.setup_logging(verbose=False)

        # デフォルト（INFO）レベルでハンドラーが設定されていることを確認
        assert len(logging.root.handlers) > 0

    @patch("logging.basicConfig")
    def test_setup_logging_calls_basicconfig(self, mock_basicconfig):
        """basicConfigが適切に呼ばれることのテスト"""
        agent_s.setup_logging(verbose=True)

        # basicConfigが呼ばれたことを確認
        mock_basicconfig.assert_called_once()

        # 呼び出し時の引数を確認
        call_args = mock_basicconfig.call_args
        assert "level" in call_args.kwargs
        assert call_args.kwargs["level"] == logging.DEBUG


class TestMain:
    """main関数のテストクラス"""

    def test_main_show_key_command(self):
        """show-keyサブコマンドの実行テスト"""
        # モック関数の設定
        mock_func = Mock()
        mock_args = Mock()
        mock_args.verbose = False
        mock_args.func = mock_func

        with patch("argparse.ArgumentParser.parse_args", return_value=mock_args):
            with patch.object(agent_s, "setup_show_key_subparser") as mock_setup_show:
                with patch.object(agent_s, "setup_link_subparser") as mock_setup_link:
                    with patch.object(agent_s, "setup_logging") as mock_setup_logging:
                        with pytest.raises(SystemExit) as exc_info:
                            agent_s.main()

                        # 正常終了（exit code 0）であることを確認
                        assert exc_info.value.code == 0

                        # サブパーサーが設定されたことを確認
                        mock_setup_show.assert_called_once()
                        mock_setup_link.assert_called_once()

                        # ログ設定が呼ばれたことを確認
                        mock_setup_logging.assert_called_once_with(False)

                        # サブコマンド関数が実行されたことを確認
                        mock_func.assert_called_once_with(mock_args)

    def test_main_verbose_option(self):
        """-vオプション（verbose）のテスト"""
        mock_func = Mock()
        mock_args = Mock()
        mock_args.verbose = True
        mock_args.func = mock_func

        with patch("argparse.ArgumentParser.parse_args", return_value=mock_args):
            with patch.object(agent_s, "setup_show_key_subparser"):
                with patch.object(agent_s, "setup_link_subparser"):
                    with patch.object(agent_s, "setup_logging") as mock_setup_logging:
                        with pytest.raises(SystemExit) as exc_info:
                            agent_s.main()

                        # 正常終了であることを確認
                        assert exc_info.value.code == 0

                        # verboseオプションでログ設定が呼ばれたことを確認
                        mock_setup_logging.assert_called_once_with(True)

    def test_main_keyboard_interrupt(self):
        """KeyboardInterruptの例外処理テスト"""
        with patch(
            "argparse.ArgumentParser.parse_args", side_effect=KeyboardInterrupt()
        ):
            with patch("logging.info") as mock_log_info:
                with pytest.raises(SystemExit) as exc_info:
                    agent_s.main()

                # エラー終了（exit code 1）であることを確認
                assert exc_info.value.code == 1

                # ログが出力されたことを確認
                mock_log_info.assert_called_once_with("処理が中断されました")

    def test_main_general_exception(self):
        """一般的な例外の処理テスト"""
        test_error = Exception("テストエラー")

        with patch("argparse.ArgumentParser.parse_args", side_effect=test_error):
            with patch("logging.error") as mock_log_error:
                with pytest.raises(SystemExit) as exc_info:
                    agent_s.main()

                # エラー終了（exit code 1）であることを確認
                assert exc_info.value.code == 1

                # エラーログが出力されたことを確認
                mock_log_error.assert_called_once_with(
                    f"予期しないエラーが発生しました: {test_error}"
                )

    def test_main_subcommand_exception(self):
        """サブコマンド実行時の例外処理テスト"""
        mock_func = Mock(side_effect=Exception("サブコマンドエラー"))
        mock_args = Mock()
        mock_args.verbose = False
        mock_args.func = mock_func

        with patch("argparse.ArgumentParser.parse_args", return_value=mock_args):
            with patch.object(agent_s, "setup_logging"):
                with patch("logging.error") as mock_log_error:
                    with pytest.raises(SystemExit) as exc_info:
                        agent_s.main()

                    # エラー終了であることを確認
                    assert exc_info.value.code == 1

                    # エラーログが出力されたことを確認
                    mock_log_error.assert_called_once()

    def test_main_help_option(self):
        """--helpオプションのテスト"""
        with patch("argparse.ArgumentParser.parse_args", side_effect=SystemExit(0)):
            with pytest.raises(SystemExit) as exc_info:
                agent_s.main()

            # ヘルプ表示による正常終了であることを確認
            assert exc_info.value.code == 0

    def test_main_no_subcommand(self):
        """サブコマンドが指定されていない場合のテスト"""
        with patch("argparse.ArgumentParser.parse_args", side_effect=SystemExit(2)):
            with pytest.raises(SystemExit) as exc_info:
                agent_s.main()

            # 引数エラーによる終了であることを確認
            assert exc_info.value.code == 2

    def test_main_argument_parser_configuration(self):
        """ArgumentParserの設定テスト"""
        with patch.object(agent_s, "setup_show_key_subparser") as mock_show_key_setup:
            with patch.object(agent_s, "setup_link_subparser") as mock_link_setup:
                with patch(
                    "argparse.ArgumentParser.parse_args", side_effect=SystemExit(0)
                ):
                    with pytest.raises(SystemExit):
                        agent_s.main()

                # サブパーサーセットアップ関数が呼ばれたことを確認
                mock_show_key_setup.assert_called_once()
                mock_link_setup.assert_called_once()


class TestModuleExecution:
    """__name__ == "__main__"のテストクラス"""

    def test_main_function_exists(self):
        """main関数が存在することのテスト"""
        # main関数が存在し、呼び出し可能であることを確認
        assert hasattr(agent_s, "main")
        assert callable(agent_s.main)

    def test_setup_logging_function_exists(self):
        """setup_logging関数が存在することのテスト"""
        # setup_logging関数が存在し、呼び出し可能であることを確認
        assert hasattr(agent_s, "setup_logging")
        assert callable(agent_s.setup_logging)


class TestIntegration:
    """統合テストクラス"""

    def test_argument_parser_creation(self):
        """ArgumentParser作成の統合テスト"""
        # ArgumentParserが正しく作成されることをテスト
        with patch.object(agent_s, "setup_show_key_subparser"):
            with patch.object(agent_s, "setup_link_subparser"):
                with patch(
                    "argparse.ArgumentParser.parse_args", side_effect=SystemExit(0)
                ):
                    with pytest.raises(SystemExit):
                        agent_s.main()

    def test_logging_integration(self):
        """ログ統合テスト"""
        # ログ設定が適切に動作することをテスト
        with patch("logging.basicConfig") as mock_basicconfig:
            agent_s.setup_logging(verbose=False)
            mock_basicconfig.assert_called_once()

            call_args = mock_basicconfig.call_args
            assert "level" in call_args.kwargs
            assert call_args.kwargs["level"] == logging.INFO

    def test_error_handling_integration(self):
        """エラーハンドリング統合テスト"""
        # 複数のエラーケースが適切に処理されることをテスト

        # KeyboardInterruptのテスト
        with patch(
            "argparse.ArgumentParser.parse_args", side_effect=KeyboardInterrupt()
        ):
            with patch("logging.info"):
                with pytest.raises(SystemExit) as exc_info:
                    agent_s.main()
                assert exc_info.value.code == 1

        # 一般的な例外のテスト
        with patch(
            "argparse.ArgumentParser.parse_args", side_effect=ValueError("Test error")
        ):
            with patch("logging.error"):
                with pytest.raises(SystemExit) as exc_info:
                    agent_s.main()
                assert exc_info.value.code == 1


if __name__ == "__main__":
    pytest.main([__file__])
