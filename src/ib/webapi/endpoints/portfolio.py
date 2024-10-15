from typing import List

from ib.webapi.models import AccountModel, SubAccounts2ResponseModel, PositionModel
from ib.webapi.session import LiveSessionTokenManager


class PortfolioClient(LiveSessionTokenManager):
    def __init__(self, credentials_path: str):
        super().__init__(credentials_path)

    def portfolio_accounts(self, live_session_token: str) -> List[AccountModel] | None:
        """Request list of Portfolio Accounts
        https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#portfolio-accounts

        Args:
            live_session_token (str): Live Session Token

        Returns:
            List[AccountModel] | None: List of Portfolio Accounts
        """

        location = "/portfolio/accounts"
        return self.make_request(
            method="GET",
            location=location,
            live_session_token=live_session_token,
            response_model=List[AccountModel],
        )

    def portfolio_sub_accounts(
        self, live_session_token: str
    ) -> List[AccountModel] | None:
        """Request list of Portfolio Sub Accounts
        https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#portfolio-subaccounts

        Args:
            live_session_token (str): Live Session Token

        Returns:
            List[AccountModel] | None: List of Sub Accounts
        """

        location = "/portfolio/subaccounts"
        return self.make_request(
            method="GET",
            location=location,
            live_session_token=live_session_token,
            response_model=List[AccountModel],
        )

    def portfolio_sub_accounts2(
        self, live_session_token: str, page: int = 0
    ) -> List[AccountModel] | None:
        """Request list of Portfolio Sub Accounts, pagination supported
        https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#portfolio-subaccounts2

        Args:
            live_session_token (str): Live Session Token

        Returns:
            List[AccouontModel]: List of Sub Accounts
        """

        location = "/portfolio/subaccounts2"
        return self.make_request(
            method="GET",
            location=location,
            live_session_token=live_session_token,
            response_model=SubAccounts2ResponseModel,
            params={"page": page},
        )

    def account_positions(
        self,
        live_session_token: str,
        account_id: str,
        page: int = 0,
        direction: str = "a",
        period: str = "1W",
        sort: str = "position",
        model: str = "",
    ) -> List[PositionModel] | None:
        """Request list of positions for the account, pagination supported
        https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#positions

        Args:
            live_session_token (str): Live Session Token
            account_id (str): Account ID
            page (int, optional): Page Number. Defaults to 0.
            direction (str, optional): Direction, 'a' means asceding, 'd' - descending. Defaults to "a".
            period (str, optional): Period of PNL column, value format: 1D, 7D, 1M, Defaults to "1W".
            sort (str, optional): Declare the table to be sorted by which column, value format: position, mktValue, mktPrice, conid, contractDesc. Defaults to "position".
            model (str, optional): Code for the model portfolio to compare against. Defaults to "".

        Returns:
            List[AccountModel]: List of Positions
        """

        location = f"/portfolio/{account_id}/positions/{page}"
        return self.make_request(
            method="GET",
            location=location,
            live_session_token=live_session_token,
            response_model=List[PositionModel],
            params={
                "direction": direction,
                "period": period,
                "sort": sort,
                "model": model,
            },
        )

    def account_positions2(
        self,
        live_session_token: str,
        account_id: str,
        direction: str = "a",
        sort: str = "position",
    ) -> List[PositionModel] | None:
        """Request list of positions for the account, provides near-real time updates and removes caching
        https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#positions

        Args:
            live_session_token (str): Live Session Token
            account_id (str): Account ID
            page (int, optional): Page Number. Defaults to 0.
            direction (str, optional): Direction, 'a' means asceding, 'd' - descending. Defaults to "a".
            sort (str, optional): Declare the table to be sorted by which column, value format: position, mktValue, mktPrice, conid, contractDesc. Defaults to "position".

        Returns:
            List[AccountModel]: List of Positions
        """

        location = f"/portfolio2/{account_id}/positions"
        return self.make_request(
            method="GET",
            location=location,
            live_session_token=live_session_token,
            response_model=List[PositionModel],
            params={"direction": direction, "sort": sort},
        )
