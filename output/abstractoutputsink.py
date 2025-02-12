from abc import ABC, abstractmethod

class AbstractOutputSink(ABC):

    @abstractmethod
    def send_output(self, domain, output_matches):
        pass

    