from abc import ABC, abstractmethod

class BaseAgent(ABC):
    @abstractmethod
    def execute(self, case):
        """Run the agent on an investigation case."""
        pass