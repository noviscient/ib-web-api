from typing import List, Dict
from ib.webapi.models import CurrencyEntryModel
from ib.webapi.session import LiveSessionTokenManager
from pydantic import RootModel


class ContractClient(LiveSessionTokenManager):
    def __init__(self, credentials_path: str):
        super().__init__(credentials_path)

    def currency_pairs(
        self, live_session_token: str, currency: str
    ) -> List[Dict[str, List[CurrencyEntryModel]]] | None:
        """Obtains available currency pairs corresponding to the given target currency.
        https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#get-currency-pairs

        Args:
            live_session_token (str): Live Session Token
            currency (str): Specify the target currency you would like to receive official pairs of. Valid Structure: “USD”

        Returns:
            List[Dict[str, List[CurrencyEntryModel]]] | None: List of currency pairs
        """

        CurrencyModel = RootModel[Dict[str, List[CurrencyEntryModel]]]

        location = "/iserver/currency/pairs"
        return self.make_request(
            method="GET",
            location=location,
            live_session_token=live_session_token,
            response_model=CurrencyModel,
            params={"currency": currency},
        )
