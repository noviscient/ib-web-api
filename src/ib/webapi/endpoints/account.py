from ib.webapi.models import SwitchAccountResponseModel, UpdatedPnLModel
from ib.webapi.session import LiveSessionTokenManager


class AccountClient(LiveSessionTokenManager):
    def __init__(self, credentials_path: str):
        super().__init__(credentials_path)

    def switch_account(
        self, live_session_token: str, account_id: str
    ) -> SwitchAccountResponseModel | None:
        """Request to switch the active account for how you request data.
        Only available for financial advisors and multi-account structures.
        https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#portfolio-accounts

        Args:
            live_session_token (str): Live Session Token
            account_id (str): Account ID

        Returns:
            SwitchAccountResponseModel | None: Switch Account Response
        """

        location = "/iserver/account"
        return self.make_request(
            method="POST",
            location=location,
            live_session_token=live_session_token,
            response_model=SwitchAccountResponseModel,
            json={"acctId": account_id},
        )

    def account_pnl(self, live_session_token: str) -> SwitchAccountResponseModel | None:
        """Returns an object containing PnL for the selected account and its models (if any).
        To retrieve PnL information for a specific account, clients must first query the /iserver/account endpoint to switch to the appropriate account.
        https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#account-pnl

        Args:
            live_session_token (str): Live Session Token

        Returns:
            SwitchAccountResponseModel | None: Switch Account Response
        """

        location = "/iserver/account/pnl/partitioned"
        return self.make_request(
            method="GET",
            location=location,
            live_session_token=live_session_token,
            response_model=UpdatedPnLModel,
        )
