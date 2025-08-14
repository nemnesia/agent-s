# agent-s

<img src="./agent-s-logo.png" alt="agent-s ロゴ" width="320" />

## 概要

`agent-s` は、Symbol ブロックチェーンノードの鍵管理・バックアップ・リンク・復元・情報表示を行うためのコマンドラインツールです。

## 主な機能

## 使い方

### 基本コマンド

```
python src/agent_s.py <サブコマンド> [オプション]
```

### サブコマンド詳細

---

#### show-key

ノードの各種鍵情報（メイン、ノード、リモート、VRF）を表示します。

**書式**

```
python src/agent_s.py show-key <main|node|remote|vrf> [オプション]
```

**主なオプション**

- `-p`, `--show-private-key` : 秘密鍵も表示（デフォルトは非表示）
- `-c`, `--config` : ノードコンフィグファイルパス（デフォルト: shoestring/shoestring.ini）
- `-k`, `--keys-path` : 鍵ディレクトリパス（デフォルト: keys）

**例**

- メインキー情報を表示：
  ```
  python src/agent_s.py show-key main
  ```
- ノードキー情報と秘密鍵も表示：
  ```
  python src/agent_s.py show-key node -p
  ```
- リモートキー情報を表示：
  ```
  python src/agent_s.py show-key remote
  ```
- VRF キー情報を表示：
  ```
  python src/agent_s.py show-key vrf
  ```
- ヘルプ表示：
  ```
  python src/agent_s.py show-key -h
  ```

---

#### backup

ノード鍵（メイン、ノード、リモート、VRF）を暗号化してバックアップファイルを作成します。バックアップファイルはパスフレーズで暗号化され、復元時に必要です。

**書式**

```
python src/agent_s.py backup [オプション]
```

**主なオプション**

- `-c`, `--config` : ノードコンフィグディレクトリパス（デフォルト: shoestring）
- `-ca`, `--ca-key-path` : CA 証明書パス（デフォルト: ca.key.pem）
- `-k`, `--keys-path` : 鍵ディレクトリパス（デフォルト: keys）
- `-o`, `--output` : 出力ファイルパス（デフォルト: age.sandcat）

実行時にパスフレーズの入力が求められます。

**例**

- バックアップファイルを作成（`age.sandcat`としてカレントディレクトリに出力）：
  ```
  python src/agent_s.py backup
  ```
- 出力先ファイルを指定：
  ```
  python src/agent_s.py backup -o mybackup.sandcat
  ```
- 設定ファイルや CA 鍵・鍵ディレクトリを指定：
  ```
  python src/agent_s.py backup -c myshoestring -ca myca.key.pem -k mykeys/
  ```

---

#### restore

バックアップファイル（age.sandcat）からノード鍵（メイン、ノード、リモート、VRF）を復元します。復元時にはバックアップ作成時のパスフレーズが必要です。

**書式**

```
python src/agent_s.py restore [オプション]
```

**主なオプション**

- `-i`, `--input` : 入力ファイルパス（デフォルト: age.sandcat）
- `-o`, `--output` : 出力ディレクトリパス（デフォルト: カレントディレクトリ `.`）

**例**

- バックアップファイルからカレントディレクトリに復元：
  ```
  python src/agent_s.py restore
  ```
- 入力ファイルと出力ディレクトリを指定：
  ```
  python src/agent_s.py restore -i mybackup.sandcat -o keys/
  ```

---

#### link

ノード、リモート、VRF 鍵のリンクトランザクションを生成します。必要なリンクトランザクション（ノード-リモート、リモート-VRF など）が一括で作成されます。

**書式**

```
python src/agent_s.py link [オプション]
```

**主なオプション**

- `-c`, `--config` : ノードコンフィグファイルパス（デフォルト: shoestring/shoestring.ini）
- `-k`, `--keys-path` : 鍵ディレクトリパス（デフォルト: keys）

**例**

- リンクトランザクションを生成：
  ```
  python src/agent_s.py link
  ```
- 設定ファイルや鍵ディレクトリを指定：
  ```
  python src/agent_s.py link -c myconfig.ini -k mykeys/
  ```

ノード、リモート、VRF 鍵のリンクトランザクションを生成します。
このコマンドを実行すると、必要なリンクトランザクション（ノード-リモート、リモート-VRF など）が一括で作成されます。

```
python src/agent_s.py link [オプション]
```

主なオプション：

- `-c`, `--config` : ノードコンフィグファイルパスを指定（デフォルト: shoestring/shoestring.ini）
- `-k`, `--keys-path` : 鍵ディレクトリパスを指定（デフォルト: keys）

##### 例

リンクトランザクションを生成：

```
python src/agent_s.py link
```

設定ファイルや鍵ディレクトリを指定：

```
python src/agent_s.py link -c myconfig.ini -k mykeys/
```

### 主なオプション

- `-c`, `--config` : ノードコンフィグファイルパス（デフォルト: shoestring/shoestring.ini）
- `-ca`, `--ca-key-path` : CA 秘密鍵ファイルパス（デフォルト: ca.key.pem）
- `-k`, `--keys-path` : 鍵ディレクトリパス（デフォルト: keys）
- `-p`, `--show-private-key` : 秘密鍵も表示
- `-o`, `--output` : バックアップ/復元時の出力先
- `-i`, `--input` : 復元時の入力ファイル

## バックアップ・復元について

バックアップファイルは暗号化されます。復元時にはパスフレーズが必要です。

## テスト・Lint・ビルド

テスト:

```
scripts/run_tests.sh
```

カバレッジ付きテスト:

```
scripts/run_tests_with_coverage.sh
```

Lint チェック:

```
scripts/run_lint_checks.sh
```

zipapp ビルド:

```
scripts/build_zipapp.sh
```

## 必要なファイル

- 証明書や秘密鍵ファイル（PEM 形式）が必要です。
- デフォルトでは `keys/` ディレクトリ配下を参照します。

## ライセンス

本プロジェクトは Apache License 2.0 のもとで公開されています。
