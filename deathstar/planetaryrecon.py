import asyncio
from collections import defaultdict

class PlanetaryRecon:
    def __init__(self):
        self.data = defaultdict(
            lambda: {
                "recon_performed" : asyncio.Event(),
                "domain_sid": "",
                "domain_admins": [],
                "enterprise_admins": []
            }
        )

    @property
    def all_admins(self):
        all_admins = []

        for domain in self.data:
            all_admins.extend(self.domain_admins(domain))
            all_admins.extend(self.enterprise_admins(domain))

        return all_admins

    def get_admins_for_domain(self, admin_type, domain):
        admins = []
        for entry in self.data[domain][admin_type]:
            domain = entry["MemberDomain"].split('.', 1)[0].upper()
            username = entry['MemberName']
            admins.append(f"{domain}\\{username}")

        return admins

    def domain_admins(self, domain):
        return self.get_admins_for_domain("domain_admins", domain)

    def enterprise_admins(self, domain):
        return self.get_admins_for_domain("enterprise_admins", domain)

    def domain_sid(self, domain):
        return self.data[domain]["domain_sid"]

    def has_been_performed(self, domain):
        return self.data[domain]["recon_performed"].is_set()

    def set_performed(self, domain):
        self.data[domain]["recon_performed"].set()

    def event(self, domain):
        return self.data[domain]["recon_performed"]
