import sys
import logging
from termcolor import colored
from logging.handlers import RotatingFileHandler


class CheckrAdapter(logging.LoggerAdapter):
    def __init__(self, verbose=False, logger_name="checkr"):
        self.logger = logging.getLogger(logger_name)
        level = logging.INFO
        if verbose:
            level = logging.DEBUG

        self.logger.setLevel(level)
        formatter = logging.Formatter(
            f"%(asctime)s :: [{logger_name}] %(levelname)s :: %(message)s"
        )

        file_handler = RotatingFileHandler("checkr.log", "a", 1000000, 1)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(level)
        stream_formatter = logging.Formatter("%(message)s")
        stream_handler.setFormatter(stream_formatter)
        self.logger.addHandler(stream_handler)
        super().__init__(self.logger, {})

    def title(self, msg, *args, **kwargs):
        self.logger.info(colored(f"[+] {msg}", "blue", attrs=[]), *args, **kwargs)

    def item(self, msg, *args, **kwargs):
        self.logger.info(msg, *args, **kwargs)
