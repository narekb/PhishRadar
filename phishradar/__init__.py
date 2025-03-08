import sys
import ssl
import yaml
import logging
import asyncio
import argparse
import certstream
from .processor import Processor
from .constants import *
from .output.logoutputsink import LogOutputSink
from .output.fileoutputsink import FileOutputSink
from .output.weboutputsink import WebOutputSink

proc = None  # Populated within main()
config = {}  # Populated after YAML file parsing
output_sinks = []  # Populated after init_output_sinks()

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def cert_callback(message, context):
    """CertStream main callback function"""
    domain = message["data"]["leaf_cert"]["all_domains"][0]

    # Skip whitelisted keywords
    for wl_keyword in config[ATTR_WHITELIST]:
        if wl_keyword in domain:
            return

    result = proc.process(domain)
    if result is not None:
        for sink in output_sinks:
            # Special case for WebOutputSink - the send_output() method is declared as async, 
            # in order to issue a non-blocking request
            if isinstance(sink, WebOutputSink): 
                asyncio.run(sink.send_output(domain, result))
            else:
                sink.send_output(domain, result)


def on_error(instance, exception=None):
    logging.error("[!] CertStream error: {}".format(exception))


def read_config(filename=DEFAULT_CONFIG):
    """Parses YAML file for configuration"""
    try:
        with open(filename, "r") as f:
            new_config = yaml.safe_load(f)
            new_config["keywords"] = set(new_config["keywords"])
            return new_config

    except Exception as e:
        logging.error("[!] Failed to open {}. {}".format(filename, e))
        sys.exit(1)


def validate_config(config):
    """Checks whether required attributes are set and inserts defaults where possible"""
    if ATTR_KEYWORDS not in config or len(config[ATTR_KEYWORDS]) == 0:
        logging.error("[!] Keywords not configured.".format(ATTR_KEYWORDS))
        sys.exit(1)

    # By default, whitelist is empty
    if ATTR_WHITELIST not in config:
        config[ATTR_WHITELIST] = []

    # If a certstream server URL is not set, use the one hosted by Calidog
    if ATTR_CERTSTREAM_URL not in config:
        config[ATTR_CERTSTREAM_URL] = DEFAULT_CERTSTREAM

    # If an output sink isn't configured, just enable console logging
    if ATTR_OUTPUT not in config:
        console_config = {ATTR_OUTPUT_CONSOLE: True}
        config[ATTR_OUTPUT] = console_config

    # If a webhook sink is specified, make sure it has at least a URL
    if ATTR_OUTPUT_WEBHOOK in config and ATTR_OUTPUT_WEBHOOK_URL not in config[ATTR_OUTPUT_WEBHOOK]:
        logging.error("[!] URL not specified for webhook sink.")
        sys.exit(1)

    # Default threshold is 1
    if ATTR_THRESHOLD not in config or int(config[ATTR_THRESHOLD]) <= 0:
        config[ATTR_THRESHOLD] = DEFAULT_THRESHOLD

    # Be default, verify secure connection with certstream-server
    if ATTR_DISABLE_TLS not in config:
        config[ATTR_DISABLE_TLS] = False

    return config


def init_output_sinks(config):
    """Creates output sinks according to configuration file"""
    sinks = []

    # Type 1: Console log output
    if ATTR_OUTPUT_CONSOLE in config[ATTR_OUTPUT]:
        sinks.append(LogOutputSink(logger))

    # Type 2: File output
    if ATTR_OUTPUT_FILE in config[ATTR_OUTPUT]:
        try:
            filename = config[ATTR_OUTPUT][ATTR_OUTPUT_FILE]
            sinks.append(FileOutputSink(filename))
        except RuntimeError as e:
            logger.error(e)
            sys.exit(1)

    # Type 3: Webhook output
    if ATTR_OUTPUT_WEBHOOK in config[ATTR_OUTPUT]:
        url = config[ATTR_OUTPUT][ATTR_OUTPUT_WEBHOOK][ATTR_OUTPUT_WEBHOOK_URL]
        body = config[ATTR_OUTPUT][ATTR_OUTPUT_WEBHOOK][ATTR_OUTPUT_WEBHOOK_BODY] if ATTR_OUTPUT_WEBHOOK_BODY in config[ATTR_OUTPUT][ATTR_OUTPUT_WEBHOOK] else None
        sinks.append(WebOutputSink(url, body))

    return sinks


def show_banner():
    banner = r'''
  _____  _     _     _     _____           _            
 |  __ \| |   (_)   | |   |  __ \         | |           
 | |__) | |__  _ ___| |__ | |__) |__ _  __| | __ _ _ __ 
 |  ___/| '_ \| / __| '_ \|  _  // _` |/ _` |/ _` | '__|
 | |    | | | | \__ \ | | | | \ \ (_| | (_| | (_| | |   
 |_|    |_| |_|_|___/_| |_|_|  \_\__,_|\__,_|\__,_|_|   
                                                        
                                                                                                          
(c) 2025 Narek Babajanyan
'''
    print(banner)


def main(arguments=()):
    """Program entry point. Reads config file and connects to the CertStream server"""
    show_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="configuration YAML file path", required=True)
    args = parser.parse_args()

    config_file = args.config if args.config else DEFAULT_CONFIG
    logger.info("[*] Retrieving configurations from {}".format(config_file))

    global config
    config = validate_config(read_config(config_file))

    global proc
    proc = Processor(config[ATTR_THRESHOLD], config[ATTR_KEYWORDS])

    global output_sinks
    output_sinks = init_output_sinks(config)

    logger.info(
        "[*] Begin monitoring for the following keywords: {}".format(
            config[ATTR_KEYWORDS]
        )
    )

    # Disable SSL/TLS verification, if configured.
    ssl_opt = {"cert_reqs":ssl.CERT_NONE} if config[ATTR_DISABLE_TLS] else None

    certstream.listen_for_events(
        cert_callback, on_error=on_error, url=config[ATTR_CERTSTREAM_URL], sslopt=ssl_opt
    )


if __name__ == "__main__":
    main(sys.argv[1:])
