from ..processor import Processor

# "Testarossa" is a known keyword, retrieved via Wordsegment
def test_process_common_keywords():
    threshold = 1
    keywords = ["test", "testarossa"]
    domain = "ferraritestarossa.it"
    proc = Processor(threshold, keywords)
    assert "testarossa" in proc.process(domain)

# "Testarosso" is not a known keyword and is not recognized by Wordsegment
def test_process_rare_keywords():
    threshold = 1
    keywords = ["test", "testarosso"]
    domain = "ferraritestarosso.it"
    proc = Processor(threshold, keywords)
    assert "testarosso" in proc.process(domain)