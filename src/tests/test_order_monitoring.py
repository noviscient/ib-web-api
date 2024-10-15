from ib.webapi.endpoints.account import AccountClient

import logging

# Set up the logger
logging.basicConfig(
    level=logging.INFO,  # Set the lowest level to INFO
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",  # Format for the log messages
)

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    client = AccountClient("data/credentials.json")

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

    r = client.init_brokerage_session(publish=True, compete=True)
    logger.info(f"Brokerage Session: {r}")

    switch_response = client.switch_account(live_session_token, "U8674826")
    logger.info(f"Switch Account: {switch_response}")

    pnl_response = client.account_pnl(live_session_token)
    logger.info(f"Account PnL: {pnl_response}")
