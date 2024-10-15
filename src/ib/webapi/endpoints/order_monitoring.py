from ib.webapi.models import OrdersModel
from ib.webapi.session import LiveSessionTokenManager


class OrderMonitoringClient(LiveSessionTokenManager):
    def __init__(self, credentials_path: str):
        super().__init__(credentials_path)

    def live_orders(self, live_session_token: str) -> OrdersModel | None:
        """Request list orders for the selected account.
        To retrieve order information for a specific account, clients must first query the /iserver/account endpoint to switch to the appropriate account.
        https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#live-orders

        Args:
            live_session_token (str): Live Session Token

        Returns:
            OrdersModel | None: Object that contains list of orders
        """

        location = "/iserver/account/orders"
        return self.make_request(
            method="GET",
            location=location,
            live_session_token=live_session_token,
            response_model=OrdersModel,
        )
