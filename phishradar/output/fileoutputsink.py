from .abstractoutputsink import AbstractOutputSink
from ..constants import *


class FileOutputSink(AbstractOutputSink):

    def __init__(self, log_filename):
        # Check if file can be written to during initialization
        try:
            open(log_filename, "a+").close()
            self.logfile = log_filename
        except OSError as e:
            raise RuntimeError(
                f"[!] Failed to open {log_filename} for logging! {e}"
            ) from e

    def send_output(self, domain, output_matches):
        try:
            with open(self.logfile, "a+") as f:
                f.write(
                    f"[+] {domain} likely contains the following keywords: {output_matches}\r\n"
                )
        except OSError as e:
            raise RuntimeError(
                f"[!] Failed to open {self.logfile} for logging! {e}"
            ) from e
