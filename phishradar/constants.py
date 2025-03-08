DEFAULT_CONFIG = "config.yaml"
DEFAULT_CERTSTREAM = "wss://certstream.calidog.io/"
DEFAULT_THRESHOLD = 1

# Configuration attributes
ATTR_CERTSTREAM_URL = "certstream_url"
ATTR_KEYWORDS = "keywords"
ATTR_WHITELIST = "whitelist"
ATTR_OUTPUT = "output"
ATTR_OUTPUT_CONSOLE = "console"
ATTR_OUTPUT_FILE = "file"
ATTR_OUTPUT_WEBHOOK = "webhook"
ATTR_OUTPUT_WEBHOOK_URL = "url"
ATTR_OUTPUT_WEBHOOK_BODY = "body"
ATTR_THRESHOLD = "threshold"
ATTR_DISABLE_TLS = "disable_tls"

# This value was discovered experimentally by comparing scores of common and rare words (e.g. brand names)
RARE_KW_SCORE = 0.0000000005
