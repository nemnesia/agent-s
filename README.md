# agent-s

<img src="./agent-s-logo.png" alt="agent-s ロゴ" width="320" />

## 概要

`agent-s` は、Symbol ブロックチェーンノードの各種キー情報を表示するためのコマンドラインツールです。ノードのメインキー、ノードキー、リモートキー、VRF キーの情報を簡単に参照できます。

## 主な機能

- ノードの各種アカウント（メイン、ノード、リモート、VRF）のアドレス・公開鍵・秘密鍵（オプション）を表示
- 証明書や PEM ファイルからの鍵情報の抽出

## 使い方

### インストール

必要な Python パッケージをインストールしてください。

```
pip install -r requirements.txt
```

### コマンド例

```
python src/agent-s.py show-key main
python src/agent-s.py show-key node
python src/agent-s.py show-key remote
python src/agent-s.py show-key vrf
```

#### オプション

- `-c`, `--config` : ノードコンフィグファイルパス（デフォルト: shoestring/shoestring.ini）
- `-ca`, `--ca-key-path` : CA 秘密鍵ファイルパス（デフォルト: ca.key.pem）
- `-k`, `--keys-path` : 鍵ディレクトリパス（デフォルト: keys）
- `-p`, `--show-private-key` : 秘密鍵も表示

例：

```
python src/agent-s.py show-key main -p
```

## 必要なファイル

- 証明書や秘密鍵ファイル（PEM 形式）が必要です。
- デフォルトでは `keys/` ディレクトリ配下を参照します。

## ライセンス

本プロジェクトは Apache License 2.0 のもとで公開されています。
