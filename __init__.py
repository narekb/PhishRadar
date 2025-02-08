import sys
import yaml
import logging
import argparse
import certstream
from .processor import Processor
from .constants import *
from .output.logoutputsink import LogOutputSink

proc = None         # Populated within main()
config = {}         # Populated after YAML file parsing
output_sinks = []   # Populated after init_output_sinks()

def cert_callback(message, context):
    """CertStream main callback function"""
    domain = message["data"]["leaf_cert"]["all_domains"][0]

    result = proc.process(domain)
    if result is not None:
        for sink in output_sinks:
            sink.send_output(config[ATTR_OUTPUT], domain, result)    

def on_error(instance, exception):
    logging.error("[!] CertStream error: {}".format(exception))

def read_config(filename=DEFAULT_CONFIG):
    """Parses YAML file for configuration"""
    try:
        with open(filename, 'r') as f:
            new_config = yaml.safe_load(f)
            new_config["keywords"] = set(new_config["keywords"])
            return new_config

    except Exception as e:
        logging.error("[!] Failed to open {}. {}".format(filename, e))
        sys.exit(1)

def validate_config(config):
    """Checks whether required attributes are set and inserts defaults where possible"""
    if ATTR_KEYWORDS not in config or len(config[ATTR_KEYWORDS]) == 0:
        logging.error("{} not found in configuration file.".format(ATTR_KEYWORDS))
        sys.exit(1)

    # If a certstream server URL is not set, use the one hosted by Calidog
    if ATTR_CERTSTREAM_URL not in config:
        config[ATTR_CERTSTREAM_URL] = DEFAULT_CERTSTREAM

    # If an output sink isn't configured, just enable console logging
    if ATTR_OUTPUT not in config:
        console_config = {ATTR_OUTPUT_CONSOLE: True}
        config[ATTR_OUTPUT] = console_config

    # Default threshold is 1
    if ATTR_THRESHOLD not in config or int(config[ATTR_THRESHOLD]) <= 0:
        config[ATTR_THRESHOLD] = DEFAULT_THRESHOLD


def init_output_sinks(config):
    """Creates output sinks according to configuration file"""
    sinks = []

    # Type 1: Console log output
    if config[ATTR_OUTPUT][ATTR_OUTPUT_CONSOLE]:
        sinks.append(LogOutputSink())

    # TODO: Implement file and webhook sinks
    return sinks

def main(arguments=()):
    """Program entry point. Reads config file and connects to the CertStream server"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="configuration YAML file path", required=True)
    args = parser.parse_args()
    
    config_file = args.config if args.config else DEFAULT_CONFIG
    logging.info("[*] Retrieving configurations from {}".format(config_file))

    global config
    config = read_config(config_file)

    global proc
    proc = Processor(config[ATTR_THRESHOLD], config[ATTR_KEYWORDS])

    global output_sinks
    output_sinks = init_output_sinks(config)

    logging.info("[*] Begin monitoring for the following keywords: {}".format(config[ATTR_KEYWORDS]))
    certstream.listen_for_events(cert_callback, on_error=on_error, url=config[ATTR_CERTSTREAM_URL])

if __name__ == "__main__":
    main(sys.argv[1:])