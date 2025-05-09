import logging
from colorlog import ColoredFormatter
from threading import Lock

_log_lock = Lock()
_initialized = False

def setup_logging(level=logging.INFO):
    global _initialized
    with _log_lock:
        if _initialized:
            return logging.getLogger("app")  # consistent named logger

        formatter = ColoredFormatter(
            fmt="%(asctime)s [%(log_color)s%(levelname)s%(reset)s] %(module)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                'DEBUG':    'cyan',
                'INFO':     'green',
                'WARNING':  'yellow',
                'ERROR':    'red',
                'CRITICAL': 'bold_red',
            },
            secondary_log_colors={},
            style='%'
        )

        handler = logging.StreamHandler()
        handler.setFormatter(formatter)

        logger = logging.getLogger("app")
        logger.setLevel(level)
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.propagate = False  # don't bubble to root logger

        _initialized = True
        return logger
