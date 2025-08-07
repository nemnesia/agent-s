import pytest
from unittest.mock import patch, Mock

import requests
from src.utils import rest_gateway_utils


class TestGetAccountLinkKeys:
    """REST Gateway Utilsのテストクラス"""

    # get_account_link_keysの正常系テスト
    def test_get_account_link_keys_success(self):
        mock_account_info = {
            "account": {
                "supplementalPublicKeys": {
                    "linked": {"publicKey": "AAA"},
                    "node": {"publicKey": "BBB"},
                    "vrf": {"publicKey": "CCC"},
                }
            }
        }
        with patch(
            "src.utils.rest_gateway_utils.get_account_info",
            return_value=mock_account_info,
        ):
            keys = rest_gateway_utils.get_account_link_keys("http://dummy", "T...")
            assert keys == {"linked": "AAA", "node": "BBB", "vrf": "CCC"}

    # get_account_link_keysの異常系テスト（get_account_infoで例外）
    def test_get_account_link_keys_exception(self):
        with patch(
            "src.utils.rest_gateway_utils.get_account_info",
            side_effect=rest_gateway_utils.RestGatewayError("Error"),
        ):
            keys = rest_gateway_utils.get_account_link_keys("http://dummy", "T...")
            assert keys == {"linked": None, "node": None, "vrf": None}

    # get_account_link_keysの異常系テスト（account_infoのインスタンスなし）
    def test_get_account_link_keys_invalid_response(self):
        with patch(
            "src.utils.rest_gateway_utils.get_account_info", return_value="invalid"
        ):
            # 修正後の実装では例外ではなくデフォルト値を返す
            keys = rest_gateway_utils.get_account_link_keys("http://dummy", "T...")
            assert keys == {"linked": None, "node": None, "vrf": None}

    # get_account_link_keysの異常系テスト（ValueErrorの場合）
    def test_get_account_link_keys_value_error(self):
        with patch(
            "src.utils.rest_gateway_utils.get_account_info",
            side_effect=ValueError("Account not found."),
        ):
            keys = rest_gateway_utils.get_account_link_keys("http://dummy", "T...")
            assert keys == {"linked": None, "node": None, "vrf": None}

    # get_account_link_keysの異常系テスト（supplementalPublicKeysがない場合）
    def test_get_account_link_keys_no_supplemental_keys(self):
        mock_account_info = {
            "account": {"address": "T..."}
        }  # supplementalPublicKeysなし
        with patch(
            "src.utils.rest_gateway_utils.get_account_info",
            return_value=mock_account_info,
        ):
            keys = rest_gateway_utils.get_account_link_keys("http://dummy", "T...")
            assert keys == {"linked": None, "node": None, "vrf": None}


class TestGetAccountInfo:
    """REST Gateway Utilsのテストクラス"""

    # get_account_infoの正常系テスト
    def test_get_account_info_success(self):
        mock_response = {"account": {"address": "T..."}}
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: mock_response,
                raise_for_status=lambda: None,
            )
            result = rest_gateway_utils.get_account_info("http://dummy", "T...")
            assert result == mock_response

    # get_account_infoのその他の例外テスト(dataのインスタンスなし)
    def test_get_account_info_invalid_response(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200, json=lambda: "invalid", raise_for_status=lambda: None
            )
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_account_info("http://dummy", "T...")
            assert (
                str(exc_info.value) == "Invalid response format from account info API."
            )

    # get_account_infoの404例外テスト
    def test_get_account_info_404(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 404
            http_error = requests.exceptions.HTTPError("404")
            http_error.response = mock_resp
            mock_resp.raise_for_status.side_effect = http_error
            mock_get.return_value = mock_resp
            with pytest.raises(ValueError) as exc_info:
                rest_gateway_utils.get_account_info("http://dummy", "T...")
            assert str(exc_info.value) == "Account not found."

    # get_account_infoの404以外の例外テスト
    def test_get_account_info_other_exception(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
                "500"
            )
            mock_resp.status_code = 500
            mock_get.return_value = mock_resp
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_account_info("http://dummy", "T...")
            assert str(exc_info.value) == "HTTP error: 500"

    # get_account_infoの404以外の例外テスト(RequestException)
    def test_get_account_info_request_exception(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.side_effect = requests.exceptions.RequestException("Request error")
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_account_info("http://dummy", "T...")
            assert str(exc_info.value) == "Request error: Request error"


class TestGetNetworkTime:
    """REST Gateway Utilsのテストクラス"""

    # get_network_timeの正常系テスト
    def test_get_network_time_success(self):
        mock_response = {"communicationTimestamps": {"sendTimestamp": 1234567890}}
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: mock_response,
                raise_for_status=lambda: None,
            )
            result = rest_gateway_utils.get_network_time("http://dummy")
            assert result == 1234567890

    # get_network_timeの異常系テスト(tsがNoneの場合)
    def test_get_network_time_no_send_timestamp(self):
        mock_response = {"communicationTimestamps": {}}
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: mock_response,
                raise_for_status=lambda: None,
            )
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_network_time("http://dummy")
            assert str(exc_info.value) == "sendTimestamp not found in response."

    # get_network_timeの異常系テスト(404の場合)
    def test_get_network_time_404(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 404
            http_error = requests.exceptions.HTTPError("404")
            http_error.response = mock_resp
            mock_resp.raise_for_status.side_effect = http_error
            mock_get.return_value = mock_resp
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_network_time("http://dummy")
            assert (
                str(exc_info.value)
                == "REST gateway URL is not valid or the service is down."
            )

    # get_network_timeの異常系テスト(503の場合)
    def test_get_network_time_503(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 503
            http_error = requests.exceptions.HTTPError("503")
            http_error.response = mock_resp
            mock_resp.raise_for_status.side_effect = http_error
            mock_get.return_value = mock_resp
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_network_time("http://dummy")
            assert str(exc_info.value) == "Service unavailable. Please try again later."

    # get_network_timeの異常系テスト(404,503以外の場合)
    def test_get_network_time_other_exception(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
                "500"
            )
            mock_resp.status_code = 500
            mock_get.return_value = mock_resp
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_network_time("http://dummy")
            assert str(exc_info.value) == "HTTP error: 500"

    # get_network_timeのRequestExceptionテスト
    def test_get_network_time_request_exception(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.side_effect = requests.exceptions.RequestException("Request error")
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_network_time("http://dummy")
            assert str(exc_info.value) == "Request error: Request error"


class TestGetMinApproval:
    """REST Gateway Utilsのテストクラス"""

    # get_min_approvalの正常系テスト
    def test_get_min_approval_success(self):
        mock_response = {"multisig": {"minApproval": 2}}
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: mock_response,
                raise_for_status=lambda: None,
            )
            result = rest_gateway_utils.get_min_approval("http://dummy", "T...")
            assert result == 2

    # get_min_approvalの正常系テスト（minApprovalがNoneの場合）
    def test_get_min_approval_none(self):
        mock_response = {"multisig": {"minApproval": None}}
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: mock_response,
                raise_for_status=lambda: None,
            )
            result = rest_gateway_utils.get_min_approval("http://dummy", "T...")
            assert result == 1

    # get_min_approvalの正常系テスト（multisigセクションがない場合）
    def test_get_min_approval_no_multisig(self):
        mock_response = {"account": {"address": "T..."}}  # multisigセクションなし
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: mock_response,
                raise_for_status=lambda: None,
            )
            result = rest_gateway_utils.get_min_approval("http://dummy", "T...")
            assert result == 1

    # get_min_approvalの異常系テスト(404の場合)
    def test_get_min_approval_404(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 404
            http_error = requests.exceptions.HTTPError("404")
            http_error.response = mock_resp
            mock_resp.raise_for_status.side_effect = http_error
            mock_get.return_value = mock_resp
            # 修正後の実装では404エラーの場合、デフォルト値1を返す
            result = rest_gateway_utils.get_min_approval("http://dummy", "T...")
            assert result == 1

    # get_min_approvalの異常系テスト(503の場合)
    def test_get_min_approval_503(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 503
            http_error = requests.exceptions.HTTPError("503")
            http_error.response = mock_resp
            mock_resp.raise_for_status.side_effect = http_error
            mock_get.return_value = mock_resp
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_min_approval("http://dummy", "T...")
            assert "Service unavailable" in str(exc_info.value)

    # get_min_approvalの異常系テスト(404, 503以外の場合)
    def test_get_min_approval_other_exception(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
                "500"
            )
            mock_resp.status_code = 500
            mock_get.return_value = mock_resp
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_min_approval("http://dummy", "T...")
            assert str(exc_info.value) == "HTTP error: 500"

    # get_min_approvalの異常系テスト(RequestExceptionの場合)
    def test_get_min_approval_request_exception(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.side_effect = requests.exceptions.RequestException("Request error")
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_min_approval("http://dummy", "T...")
            assert str(exc_info.value) == "Request error: Request error"


class TestGetRestGatewayUrl:
    """REST Gateway URLの取得テストクラス"""

    # get_rest_gateway_urlの正常系テスト(mainnet)
    def test_get_rest_gateway_url_mainnet_success(self):
        mock_nodes = [
            {
                "apiStatus": {
                    "nodeStatus": {"apiNode": "up", "db": "up"},
                    "restGatewayUrl": "https://example.com",
                },
                "roles": 2,
            }
        ]
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200, json=lambda: mock_nodes, raise_for_status=lambda: None
            )
            url = rest_gateway_utils.get_rest_gateway_url("mainnet")
            assert url == "https://example.com"

    # get_rest_gateway_urlの正常系テスト(testnet)
    def test_get_rest_gateway_url_testnet_success(self):
        mock_nodes = [
            {
                "apiStatus": {
                    "nodeStatus": {"apiNode": "up", "db": "up"},
                    "restGatewayUrl": "https://test.example.com",
                },
                "roles": 2,
            }
        ]
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200, json=lambda: mock_nodes, raise_for_status=lambda: None
            )
            url = rest_gateway_utils.get_rest_gateway_url("testnet")
            assert url == "https://test.example.com"

    # get_rest_gateway_urlの異常系テスト(ノードリストAPIのリクエスト失敗)
    def test_get_rest_gateway_url_request_exception(self):
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.side_effect = requests.exceptions.RequestException("Request error")
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_rest_gateway_url("mainnet")
            assert str(exc_info.value) == "Failed to fetch node list: Request error"

    # 利用可能なURLが存在しない
    def test_get_rest_gateway_url_no_available_urls(self):
        mock_nodes = [
            {
                "apiStatus": {
                    "nodeStatus": {"apiNode": "up", "db": "up"},
                    "restGatewayUrl": None,
                },
                "roles": 2,
            }
        ]
        with patch("src.utils.rest_gateway_utils.requests.get") as mock_get:
            mock_get.return_value = Mock(
                status_code=200, json=lambda: mock_nodes, raise_for_status=lambda: None
            )
            with pytest.raises(rest_gateway_utils.RestGatewayError) as exc_info:
                rest_gateway_utils.get_rest_gateway_url("mainnet")
            assert str(exc_info.value) == "No available REST gateway URLs found."
