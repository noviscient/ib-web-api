from logging import getLogger

logger = getLogger(__name__)


class LiveSessionTokenException(Exception):
    def __init__(self):
        message = "Live Session Token validation failed"
        logger.error(message)
        super().__init__(message)
