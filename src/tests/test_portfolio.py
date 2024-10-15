from ib.webapi.endpoints.portfolio import PortfolioClient
from ib.webapi.models import AccountModel
from typing import List

import logging

# Set up the logger
logging.basicConfig(
    level=logging.INFO,  # Set the lowest level to INFO
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",  # Format for the log messages
)

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    client = PortfolioClient("data/credentials.json")

    dh_random, oauth_params, prepend, lst_response = client.request_live_session_token()

    computed_live_session_token = client.compute_live_session_token(
        dh_random=dh_random,
        prepend=prepend,
        dh_response=lst_response["diffie_hellman_response"],
    )

    live_session_token = client.validate_live_session_token(
        lst_response["live_session_token_signature"],
        lst_response["live_session_token_expiration"],
        computed_live_session_token,
    )

    # Request Portfolio Accounts
    accounts: List[AccountModel] = client.portfolio_accounts(live_session_token)
    for account in accounts:
        logger.info(account)

    # Request Portfolio Sub Accounts
    sub_accounts: List[AccountModel] = client.portfolio_sub_accounts(live_session_token)
    for account in sub_accounts:
        logger.info(account)
