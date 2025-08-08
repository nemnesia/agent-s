"""
REST Gateway utility functions for Symbol blockchain
"""

import logging
import random
from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional

import requests

# ログ設定
logger = logging.getLogger(__name__)

# シンボルネットワークの統計サービスBASE URL（メインネット・テストネット）
MAIN_STATISTIC_SERVICE_BASE_URL = "https://symbol.services"
TEST_STATISTIC_SERVICE_BASE_URL = "https://testnet.symbol.services"

# HTTP設定
DEFAULT_TIMEOUT = 10
DEFAULT_MAX_RETRIES = 3


@dataclass
class AccountLinkKeys:
    """アカウントリンクキーを格納するデータクラス"""

    linked: Optional[str] = None
    node: Optional[str] = None
    vrf: Optional[str] = None


class RestGatewayError(Exception):
    """REST Gateway関連の例外"""

    pass


def get_account_link_keys(rest_gateway_url: str, address: str) -> Dict[str, Optional[str]]:
    """指定したアドレスのアカウントリンクキーを取得する

    Args:
        rest_gateway_url: REST GatewayのベースURL
        address: 取得対象のアカウントアドレス

    Returns:
        アカウントリンクキーの辞書 {'linked': '...', 'node': '...', 'vrf': '...'}
    """
    try:
        account_info = get_account_info(rest_gateway_url, address)

        # レスポンス形式の検証
        if not isinstance(account_info, dict) or "account" not in account_info:
            logger.warning(
                f"Account info response format is invalid for {address}, returning default values"
            )
            return {"linked": None, "node": None, "vrf": None}

        account = account_info["account"]
        account_link_keys = account.get("supplementalPublicKeys", {})

        return {
            "linked": account_link_keys.get("linked", {}).get("publicKey"),
            "node": account_link_keys.get("node", {}).get("publicKey"),
            "vrf": account_link_keys.get("vrf", {}).get("publicKey"),
        }

    except (ValueError, RestGatewayError) as e:
        logger.debug(f"Failed to get account link keys for {address}: {e}")
        return {"linked": None, "node": None, "vrf": None}


def get_account_info(rest_gateway_url: str, address: str) -> Dict[str, Any]:
    """指定したアドレスのアカウント情報を取得する

    Args:
        rest_gateway_url: REST GatewayのベースURL
        address: 取得対象のアカウントアドレス

    Returns:
        アカウント情報の辞書

    Raises:
        ValueError: アカウントが見つからない場合
        RestGatewayError: HTTP通信エラーまたはレスポンス形式エラーの場合
    """
    url = f"{rest_gateway_url.rstrip('/')}/accounts/{address}"

    for attempt in range(DEFAULT_MAX_RETRIES):
        try:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            data = response.json()

            if not isinstance(data, dict):
                raise RestGatewayError("Invalid response format from account info API.")

            return data

        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                raise ValueError("Account not found.")
            elif e.response is not None and e.response.status_code >= 500:
                # サーバーエラーの場合はリトライ
                if attempt < DEFAULT_MAX_RETRIES - 1:
                    logger.warning(f"Server error (attempt {attempt + 1}): {e}")
                    continue
            raise RestGatewayError(f"HTTP error: {e}")

        except requests.exceptions.RequestException as e:
            if attempt < DEFAULT_MAX_RETRIES - 1:
                logger.warning(f"Request error (attempt {attempt + 1}): {e}")
                continue
            raise RestGatewayError(f"Request error: {e}")
        except ValueError as e:
            raise RestGatewayError(f"JSON decode error: {e}")

    raise RestGatewayError(f"Failed to get account info after {DEFAULT_MAX_RETRIES} attempts")


def get_network_time(rest_gateway_url: str) -> int:
    """指定したRESTゲートウェイURLからネットワーク時間を取得する

    Args:
        rest_gateway_url: REST GatewayのベースURL

    Returns:
        ネットワークタイムスタンプ（整数）

    Raises:
        RestGatewayError: HTTP通信エラーまたはタイムスタンプが見つからない場合
    """
    url = f"{rest_gateway_url.rstrip('/')}/node/time"

    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        data = response.json()

        ts = data.get("communicationTimestamps", {}).get("sendTimestamp")
        if ts is None:
            raise RestGatewayError("sendTimestamp not found in response.")

        return int(ts)

    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            raise RestGatewayError("REST gateway URL is not valid or the service is down.")
        elif e.response is not None and e.response.status_code == 503:
            raise RestGatewayError("Service unavailable. Please try again later.")
        else:
            raise RestGatewayError(f"HTTP error: {e}")
    except requests.exceptions.RequestException as e:
        raise RestGatewayError(f"Request error: {e}")
    except (ValueError, TypeError) as e:
        raise RestGatewayError(f"Invalid timestamp format: {e}")


def get_min_approval(rest_gateway_url: str, address: str) -> int:
    """指定したアドレスのマルチシグの最小承認数を取得する

    Args:
        rest_gateway_url: REST GatewayのベースURL
        address: 取得対象のアカウントアドレス

    Returns:
        マルチシグの最小承認数（マルチシグでない場合は1）

    Raises:
        RestGatewayError: HTTP通信エラーの場合
    """
    url = f"{rest_gateway_url}/accounts/{address}/multisig"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        min_approval = data.get("multisig", {}).get("minApproval")
        return min_approval if min_approval is not None else 1
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            # アカウントが見つからない場合、または通常のアカウント（非マルチシグ）の場合
            logging.info(
                f"Account {address} is not a multisig account, using default min approval: 1"
            )
            return 1
        elif e.response is not None and e.response.status_code == 503:
            raise RestGatewayError("Service unavailable. Please try again later.")
        else:
            raise RestGatewayError(f"HTTP error: {e}")
    except requests.exceptions.RequestException as e:
        raise RestGatewayError(f"Request error: {e}")


def get_rest_gateway_url(network_name: Literal["mainnet", "testnet"]) -> str:
    """指定したネットワーク名に対応する稼働中のRESTゲートウェイURLをランダムに1つ取得する

    Args:
        network_name: ネットワーク名（"mainnet" または "testnet"）

    Returns:
        稼働中のRESTゲートウェイURL（負荷分散のためランダム選択）

    Raises:
        RestGatewayError: ノード一覧の取得に失敗した場合、または利用可能なURLが見つからない場合
    """
    if network_name == "mainnet":
        statistic_service_url = MAIN_STATISTIC_SERVICE_BASE_URL
    else:
        statistic_service_url = TEST_STATISTIC_SERVICE_BASE_URL

    # ノードリストAPIへアクセスし、SSL対応かつ最大50件のノード情報を取得
    url = f"{statistic_service_url}/nodes?ssl=true&limit=50"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        nodes = response.json()
    except requests.exceptions.RequestException as e:
        raise RestGatewayError(f"Failed to fetch node list: {e}")

    # APIノードとして稼働中（rolesにAPIフラグが立ち、apiNode/dbがup）のノードのみ抽出
    filtered_nodes = [
        node
        for node in nodes
        if isinstance(node, dict)
        and "apiStatus" in node
        and "nodeStatus" in node["apiStatus"]
        and node.get("roles", 0) & 2  # rolesのビットフラグ2はAPIノード
        and node["apiStatus"]["nodeStatus"].get("apiNode") == "up"
        and node["apiStatus"]["nodeStatus"].get("db") == "up"
    ]

    # 抽出したノードからRESTゲートウェイURLのみをリスト化
    rest_gateway_urls = [
        node["apiStatus"].get("restGatewayUrl")
        for node in filtered_nodes
        if node["apiStatus"].get("restGatewayUrl")
    ]

    # 利用可能なURLがなければ例外を投げる
    if not rest_gateway_urls:
        raise RestGatewayError("No available REST gateway URLs found.")
    # ランダムに1件選んで返す（負荷分散目的）
    return random.choice(rest_gateway_urls)
