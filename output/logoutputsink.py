import logging
from .abstractoutputsink import AbstractOutputSink

class LogOutputSink(AbstractOutputSink):
    def send_output(self, output_config, domain, output_matches):
        logging.info(f"[!] {domain} likely contains the following keywords: {output_matches}")