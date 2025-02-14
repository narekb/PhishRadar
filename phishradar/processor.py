from .constants import RARE_KW_SCORE
import wordsegment


class Processor(object):
    threshold = 1
    keyword_scores = {}

    def __init__(self, threshold, keywords):
        wordsegment.load()
        self.threshold = threshold

        # The wordsegment package does not publicly expose the score() method,
        # but we need it in order to determine rare words.
        # This violation of private variable convention is a necessary evil.
        for keyword in keywords:
            self.keyword_scores[keyword] = wordsegment._segmenter.score(keyword)

    def process(self, domain):
        matches = set()

        # For rare keywords, just check if the domain contains them
        for keyword in self.keyword_scores:
            if self.keyword_scores[keyword] <= RARE_KW_SCORE and keyword in domain:
                matches.add(keyword)

        # ...otherwise, proceed with Wordsegment
        segments = wordsegment.segment(
            str(domain).lower().replace(".", " ").replace("-", " ")
        )
        
        matches = matches.union(set(self.keyword_scores.keys()).intersection(set(segments)))
        if len(matches) >= self.threshold:
            return matches
        else:
            return None
