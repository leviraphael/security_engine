import logging
import logging.config
import os

logging.config.fileConfig(os.path.join(os.path.dirname(__file__), 'logging_config.ini'))

logging.info('This is an informational message')


def get_logger():
    return logging.getLogger()