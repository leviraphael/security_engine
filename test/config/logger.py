import logging
import logging.config
import os

logging.config.fileConfig(os.path.join(os.path.dirname(__file__), "logging_config.ini"))


def get_logger():
    return logging.getLogger()
