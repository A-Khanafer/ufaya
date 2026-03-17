from abc import ABC, abstractmethod


class FirewallDriver(ABC):

    @abstractmethod
    def get_rules(self):
        pass

    @abstractmethod
    def create_rule(self, rule):
        pass

    @abstractmethod
    def delete_rule(self, rule_id):
        pass

    @abstractmethod
    def commit(self):
        pass
