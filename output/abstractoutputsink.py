from abc import ABC, abstractmethod

class AbstractOutputSink(ABC):

    @abstractmethod
    def send_output(self, output_config, domain, output_matches):
        pass

    