# PhishRadar
Detect phishing/scam domains from [Certificate Transparency](https://certificate.transparency.dev/) logs. Can be useful for internal security teams for monitoring company-specific domains, as well as for sectorial/national CERTs for monitoring the domains of their constituents. 

Logs are retrieved via [Certstream](https://certstream.calidog.io/). Keywords are set in a YAML configuration file and detected via two methods:
* for common subwords, results from [WordSegment](https://github.com/grantjenks/python-wordsegment) are scanned
* for rarer words (e.g. brand names), we simply check if the domain contains the keyword - this is because WordSegment may not correctly separate unknown subwords.

For better customization, a minimal threshold of matching keywords can be set. 

The idea was born after encountering phishing attacks and malware Command-and-Control communication involving domains impersonating Armenian government bodies ([1](https://k3yp0d.blogspot.com/2024/10/something-phishy-is-happening-in-armenia.html), [2](https://research.checkpoint.com/2023/operation-silent-watch-desktop-surveillance-in-azerbaijan-and-armenia/)).

## Installation and usage
```
pip install phishradar
phishradar --config ./config.yaml
```

## Sample configuration
```yaml
certstream_url: wss://certstream.calidog.io/
keywords:
  - test
  - keyword
  - yourbrand
whitelist:
  - exclude
  - these
threshold: 1  # Number of matched keywords to alert for
output:
  console: True
  file: output.log
  # Example use case of a webhook sink - a Telegram bot for alerting
  # The following templates are supported in messages (URL and body):
  #   $domain - defanged domain name
  #   $matches_list - bullet point list of matched keywords
  #   $matches_comma - comma-separated string of matched keywords
  webhook:
    url: "https://api.telegram.org/bot<INSERT_YOUR_BOT_TOKEN>/sendMessage"
    body: '{"chat_id": "<INSERT_YOUR_CHAT_ID>", "parse_mode": "html", "text": "<b>$domain</b> contains: <i>$matches_list</i>"}'
```

## Further work
- [ ] Try out alternative threshold mechanism (e.g. weighted keywords)
- [ ] Experiment with word segmentation via a Small Language Model