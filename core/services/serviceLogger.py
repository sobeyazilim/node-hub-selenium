import logging
import socket
import sys

# class
from core.schemas import app_stream_mode, app_log_path

# extra = {'hostname': socket.gethostname(), 'ip': socket.gethostbyname(socket.gethostname())}

# Logging Options
def service_logger(stream_mode=None):
    extra = {'hostname': socket.gethostname()}
    app_logger = logging.getLogger(__name__)

    # Clear old handlers to avoid duplicate logging
    if app_logger.hasHandlers():
        app_logger.handlers.clear()

    # Select the appropriate handler based on the mode
    if stream_mode is None:
        stream_mode = app_stream_mode

    if stream_mode:
        handler = logging.StreamHandler()
    else:
        handler = logging.FileHandler(app_log_path, mode='a')

    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s | fapim | %(levelname)s | hostname=%(hostname)s | message=%(message)s',
    datefmt='%Y/%m/%d %I:%M:%S')
    handler.setFormatter(formatter)

    # add new handler
    app_logger.addHandler(handler)
    app_logger.setLevel(logging.INFO)
    app_logger = logging.LoggerAdapter(app_logger, extra)
    
    return app_logger


def service_logger_debug():
    extra = {'hostname': socket.gethostname()}
    app_logger = logging.getLogger(__name__)

    # Clear old handlers to avoid duplicate logging
    if app_logger.hasHandlers():
        app_logger.handlers.clear()

    # Select the appropriate handler based on the mode
    handler = logging.StreamHandler()

    # Select the appropriate handler based on the mode
    handler = logging.StreamHandler()

    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s | fapim | %(levelname)s | hostname=%(hostname)s | %(funcName)s = %(message)s',
    datefmt='%Y/%m/%d %I:%M:%S')
    handler.setFormatter(formatter)

    # add new handler
    app_logger.addHandler(handler)
    app_logger.setLevel(logging.DEBUG)
    app_logger = logging.LoggerAdapter(app_logger, extra)
    
    return app_logger