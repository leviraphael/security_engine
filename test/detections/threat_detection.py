import abc

from config.logger import get_logger


class ThreatDetection(abc.ABC):
    def __init__(self):
        self.logging = get_logger()

    @abc.abstractmethod
    def analyse(self, *args, **kwargs):
        raise NotImplementedError()
