from .abstractoutputsink import AbstractOutputSink
from string import Template
import aiohttp

class WebOutputSink(AbstractOutputSink):
    def __init__(self, url, body):
        self.url = url
        self.body = body

    def bulleted_list(self, matches):
        list_str = ""
        for match in matches:
            list_str += ("\r\n• " + match)
        return list_str

    async def send_output(self, domain, output_matches):
        # Defang the domain so that it's not clickable in other environments
        domain = domain.replace(".", "[.]")

        # Provide multiple template formats for matches - comma-separated and bulleted list
        matches_comma = ", ".join(output_matches)
        matches_list = self.bulleted_list(output_matches)

        # Insert specified templates into the URL and request body

        url_template = Template(self.url)
        body_template = Template(self.body)

        url = url_template.substitute(domain=domain, matches_comma=matches_comma, matches_list=matches_list)
        body = body_template.substitute(domain=domain, matches_comma=matches_comma, matches_list=matches_list)
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url=url, data=body, headers={"Content-Type": "application/json"}) as response:
                await response.release()