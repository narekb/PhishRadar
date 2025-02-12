import logging
from .abstractoutputsink import AbstractOutputSink

class LogOutputSink(AbstractOutputSink):
    def __init__(self, logger):
        self.logger = logger

    def send_output(self, domain, output_matches):
        self.logger.info(f"[+] {domain} likely contains the following keywords: {output_matches}")