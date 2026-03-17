from ..firewall.base import FirewallDriver


class PaloAltoDriver(FirewallDriver):

    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password

    def get_rules(self):
        return []

    def create_rule(self, rule):
        pass

    def delete_rule(self, rule_id):
        pass

    def commit(self):
        pass
