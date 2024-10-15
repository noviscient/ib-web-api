import json
import requests
import random
import base64
from urllib.parse import quote, quote_plus
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Hash import SHA256, HMAC, SHA1
from datetime import datetime
import pprint
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

from ib.webapi.constants import RESP_HEADERS_TO_PRINT
from typing import List, Union, Type, Optional, Tuple, Dict, get_origin, get_args
from pydantic import BaseModel, TypeAdapter

from ib.webapi.exceptions import LiveSessionTokenException
from ib.webapi.models import InitBrokerageSessionResponseModel, StatusResponseModel

from logging import getLogger

logger = getLogger(__name__)


class IBSession:
    def __init__(self, credentials_path: str):
        """Initializes the IBSession object

        Args:
            credentials_path (str): Path to the credentials file
        """

        self.credentials = self.load_credentials(credentials_path)
        self.encryption_key = self.load_key(self.credentials["encryption"])
        self.signature_key = self.load_key(self.credentials["signature"])
        self.dh_param = self.load_key(self.credentials["dhparam"])
        self.access_token = self.credentials["access_token"]
        self.access_token_secret = self.credentials["access_token_secret"]
        self.consumer_key = self.credentials["consumer_key"]
        self.realm = "test_realm" if self.consumer_key == "TESTCONS" else "limited_poa"
        self.baseUrl = "api.ibkr.com/v1/api"

    def load_credentials(self, path: str) -> Dict[str, any]:
        """Loads the credentials from the file

        Args:
            path (str): Path to the credentials file

        Returns:
            Dict[str, any]: The credentials
        """

        with open(path, "r") as f:
            return json.load(f)

    def load_key(self, path: str) -> RSA.RsaKey:
        """Load RSA key from the file

        Args:
            path (str): Path to the pem file

        Returns:
            RSA.RsaKey: RSA key
        """

        with open(path, "r") as f:
            return RSA.importKey(f.read())

    @staticmethod
    def pretty_request_response(resp: requests.Response) -> str:
        """Pretty prints the request and response

        Args:
            resp (requests.Response): The response object

        Returns:
            str: The pretty printed request and response
        """

        req = resp.request
        rqh = "\n".join(f"{k}: {v}" for k, v in req.headers.items())
        rqh = rqh.replace(", ", ",\n    ")
        rqb = f"\n{pprint.pformat(json.loads(req.body))}\n" if req.body else ""

        try:
            rsb = f"\n{pprint.pformat(resp.json())}\n" if resp.text else ""
        except json.JSONDecodeError:
            rsb = resp.text

        rsh = "\n".join(
            [f"{k}: {v}" for k, v in resp.headers.items() if k in RESP_HEADERS_TO_PRINT]
        )
        return_str = "\n".join(
            [
                80 * "-",
                "-----------REQUEST-----------",
                f"{req.method} {req.url}",
                rqh,
                f"{rqb}",
                "-----------RESPONSE-----------",
                f"{resp.status_code} {resp.reason}",
                rsh,
                f"{rsb}\n",
            ]
        )
        return return_str


class LiveSessionTokenManager(IBSession):
    def __init__(self, credentials_path: str):
        """Initializes the LiveSessionTokenManager object

        Args:
            credentials_path (str): Path to the credentials file
        """

        super().__init__(credentials_path)
        self.dh_prime = self.dh_param.n
        self.dh_generator = self.dh_param.e

        # Set up a session with retry logic
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
            allowed_methods=["HEAD", "GET", "OPTIONS"],  # Methods to retry
            backoff_factor=0.5,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def generate_dh_challenge(self) -> Tuple[int, int]:
        """Generates the Diffie-Hellman challenge

        Returns:
            Tuple[int, int]: The Diffie-Hellman random number and challenge
        """
        # Generate a random 256-bit integer
        dh_random = random.getrandbits(256)

        # Compute the Diffie-Hellman challenge:
        # generator ^ dh_random % dh_prime
        # Note that IB always uses generator = 2.
        # Convert result to hex and remove leading 0x chars.
        dh_challenge = hex(pow(self.dh_generator, dh_random, self.dh_prime))[2:]

        return dh_random, dh_challenge

    def generate_signature(self, dh_challenge: int, prepend: str) -> Dict[str, any]:
        """Generates the signature for the request

        Args:
            dh_challenge (int): The Diffie-Hellman challenge
            prepend (str): The decrypted access token

        Returns:
            Dict[str, any]: The OAuth signature for the request
        """

        method = "POST"
        url = f"https://{self.baseUrl}/oauth/live_session_token"
        oauth_params = {
            "oauth_consumer_key": self.consumer_key,
            "oauth_nonce": hex(random.getrandbits(128))[2:],
            "oauth_timestamp": str(int(datetime.now().timestamp())),
            "oauth_token": self.access_token,
            "oauth_signature_method": "RSA-SHA256",
            "diffie_hellman_challenge": dh_challenge,
        }

        params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])
        base_string = f"{prepend}{method}&{quote_plus(url)}&{quote(params_string)}"
        sha256_hash = SHA256.new(data=base_string.encode("utf-8"))
        signature = PKCS1_v1_5_Signature.new(self.signature_key).sign(sha256_hash)
        oauth_params["oauth_signature"] = quote_plus(
            base64.b64encode(signature).decode("utf-8")
        )
        oauth_params["realm"] = self.realm

        return oauth_params

    def request_live_session_token(
        self,
    ) -> Tuple[int, Dict[str, any], str, Dict[str, any]]:
        """Requests the Live Session Token

        Raises:
            Exception: If the LST request fails

        Returns:
            Tuple[int, Dict[str, any], str, Dict[str, any]]: The Diffie-Hellman random number, OAuth signature decrypted access token and the response data
        """

        dh_random, dh_challenge = self.generate_dh_challenge()

        bytes_decrypted_secret = PKCS1_v1_5_Cipher.new(key=self.encryption_key).decrypt(
            ciphertext=base64.b64decode(self.access_token_secret),
            sentinel=None,
        )
        prepend = bytes_decrypted_secret.hex()

        oauth_params = self.generate_signature(dh_challenge, prepend)

        headers = {
            "Authorization": "OAuth "
            + ", ".join([f'{k}="{v}"' for k, v in sorted(oauth_params.items())])
        }
        headers["User-Agent"] = "python/3.11"
        lst_request = requests.post(
            url=f"https://{self.baseUrl}/oauth/live_session_token", headers=headers
        )

        if not lst_request.ok:
            raise Exception("LST request failed")

        response_data = lst_request.json()
        return dh_random, oauth_params, prepend, response_data

    def compute_live_session_token(
        self, dh_random: int, prepend: str, dh_response: Dict[str, any]
    ) -> str:
        """Computes the Live Session Token

        Args:
            dh_random (int): The Diffie-Hellman random number
            prepend (str): The decrypted access token
            dh_response (Dict[str, any]): The Diffie-Hellman response

        Returns:
            str: The computed Live Session Token
        """

        # Generate bytestring from prepend hex str.
        prepend_bytes = bytes.fromhex(prepend)

        # Convert hex string response to integer and compute K=B^a mod p.
        # K will be used to hash the prepend bytestring (the decrypted
        # access token) to produce the LST.
        a = dh_random
        B = int(dh_response, 16)
        K = pow(B, a, self.dh_prime)

        # Generate hex string representation of integer K.
        hex_str_K = hex(K)[2:]

        # If hex string K has odd number of chars, add a leading 0,
        # because all Python hex bytes must contain two hex digits
        # (0x01 not 0x1).
        if len(hex_str_K) % 2:
            hex_str_K = "0" + hex_str_K

        # Generate hex bytestring from hex string K.
        hex_bytes_K = bytes.fromhex(hex_str_K)

        # Prepend a null byte to hex bytestring K if lacking sign bit.
        if len(bin(K)[2:]) % 8 == 0:
            hex_bytes_K = bytes(1) + hex_bytes_K

        # Generate bytestring HMAC hash of hex prepend bytestring.
        # Hash key is hex bytestring K, method is SHA1.
        bytes_hmac_hash_K = HMAC.new(
            key=hex_bytes_K,
            msg=prepend_bytes,
            digestmod=SHA1,
        ).digest()

        # The computed LST is the base64-encoded HMAC hash of the
        # hex prepend bytestring.
        # Converted here to str.
        computed_lst = base64.b64encode(bytes_hmac_hash_K).decode("utf-8")

        return computed_lst

    def validate_live_session_token(
        self, lst_signature: str, lst_expiration: int, computed_lst: str
    ) -> str:
        """Validate calculated Live Session Token matches the server response
        This is technically an optional step; however, future attempted requests might otherwise

        Args:
            lst_signature (str):
            lst_expiration (int): _description_
            computed_lst (str): _description_

        Raises:
            Exception: _description_

        Returns:
            str: _description_
        """

        # Generate hex-encoded str HMAC hash of consumer key bytestring.
        # Hash key is base64-decoded LST bytestring, method is SHA1.
        hex_str_hmac_hash_lst = HMAC.new(
            key=base64.b64decode(computed_lst),
            msg=self.consumer_key.encode("utf-8"),
            digestmod=SHA1,
        ).hexdigest()

        if hex_str_hmac_hash_lst != lst_signature:
            raise LiveSessionTokenException()

        # If our hex hash of our computed LST matches the LST signature
        # received in response, we are successful.
        live_session_token = computed_lst

        logger.info("Live session token computation and validation successful.")
        logger.info(
            f"LST: {live_session_token}; expires: {datetime.fromtimestamp(lst_expiration/1000)}\n"
        )

        return live_session_token

    def generate_oauth_headers(
        self, live_session_token: str, location: str
    ) -> Dict[str, str]:
        oauth_params = {
            "oauth_consumer_key": self.consumer_key,
            "oauth_nonce": hex(random.getrandbits(128))[2:],
            "oauth_signature_method": "HMAC-SHA256",
            "oauth_timestamp": str(int(datetime.now().timestamp())),
            "oauth_token": self.access_token,
        }
        params_string = "&".join([f"{k}={v}" for k, v in sorted(oauth_params.items())])
        # base_string = f"GET&{quote_plus(f'https://{self.baseUrl}/portfolio/subaccounts')}&{quote(params_string)}"
        base_string = f"GET&{quote_plus(f'https://{self.baseUrl}{location}')}&{quote(params_string)}"
        bytes_hmac_hash = HMAC.new(
            key=base64.b64decode(live_session_token),
            msg=base_string.encode("utf-8"),
            digestmod=SHA256,
        ).digest()
        oauth_params["oauth_signature"] = quote_plus(
            base64.b64encode(bytes_hmac_hash).decode("utf-8")
        )
        oauth_params["realm"] = self.realm
        oauth_header = "OAuth " + ", ".join(
            [f'{k}="{v}"' for k, v in sorted(oauth_params.items())]
        )

        return {"Authorization": oauth_header, "User-Agent": "python/3.11"}

    def make_request(
        self,
        method: str,
        location: str,
        live_session_token: str,
        response_model: Union[Type[BaseModel], Type[List[BaseModel]]],
        params: dict | None = None,
        data: dict | None = None,
        json: dict | None = None,
    ) -> Optional[Union[BaseModel, List[BaseModel]]]:
        """
        Generic method for making API requests, handling both single and list responses.

        Args:
            method (str): HTTP method (e.g., 'GET', 'POST')
            location (str): API endpoint location (e.g., '/portfolio/subaccounts')
            live_session_token (str): OAuth live session token
            response_model (Union[Type[BaseModel], Type[List[BaseModel]]]): Pydantic model or list of models to parse the response
            params (dict): Query parameters for the request (used in 'GET' requests)
            data (dict): Form data for the request body (used in 'POST' requests)
            json (dict): JSON payload for the request body (used in 'POST' requests)

        Returns:
            Optional[Union[BaseModel, List[BaseModel]]]: Parsed response model(s) or None if an error occurs
        """
        url = f"https://{self.baseUrl}{location}"
        headers = self.generate_oauth_headers(live_session_token, location)

        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json,
                timeout=10,
            )

            response.raise_for_status()
            response_json = response.json()

            if get_origin(response_model) is list:
                model = get_args(response_model)[0]
                type_adapter = TypeAdapter(List[model])
                return type_adapter.validate_python(response_json)
            else:
                return response_model(**response_json)

        except requests.Timeout as timeout_exc:
            logger.exception(f"Request timed out: {timeout_exc}")
        except requests.RequestException as req_exc:
            logger.exception(f"Error parsing response: {req_exc}")
        except Exception as parse_exc:
            logger.exception(f"Error parsing response: {parse_exc}")

        return None

    def init_brokerage_session(
        self, publish: bool, compete: bool
    ) -> InitBrokerageSessionResponseModel:
        """Initializes the brokerage session

        Args:
            publish (bool): Determines if the request should be sent immediately. Users should always pass true. Otherwise, a 500 response will be returned.
            compete (bool): Determines if other brokerage sessions should be disconnected to prioritize this connection.

        Returns:
            InitBrokerageSessionResponseModel: The response data
        """

        location = "/iserver/auth/ssodh/init"
        return self.make_request(
            method="POST",
            location=location,
            live_session_token=self.access_token_secret,
            response_model=InitBrokerageSessionResponseModel,
            json={"publish": publish, "compete": compete},
        )

    def logout(self) -> StatusResponseModel:
        """Logs the user out of the gateway session. Any further activity requires re-authentication."""

        location = "/logout"
        return self.make_request(
            method="POST",
            location=location,
            live_session_token=self.access_token_secret,
            response_model=StatusResponseModel,
            json={},
        )

    def tickle(self) -> StatusResponseModel:
        """If the gateway has not received any requests for several minutes an open session will automatically timeout.
        The tickle endpoint pings the server to prevent the session from ending.
        It is expected to call this endpoint approximately every 60 seconds to maintain the connection to the brokerage session.
        """

        location = "/tickle"
        return self.make_request(
            method="POST",
            location=location,
            live_session_token=self.access_token_secret,
            response_model=StatusResponseModel,
            json={},
        )
