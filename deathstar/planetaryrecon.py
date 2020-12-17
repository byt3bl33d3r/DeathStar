import asyncio
from collections import defaultdict


class PlanetaryRecon:
    def __init__(self):
        self.data = defaultdict(
            lambda: {
                "recon_performed": asyncio.Event(),
                "domain_sid": "",
                "domain_controllers": [],
                "domain_admins": [],
                "enterprise_admins": [],
                "priority_targets": set(),  # Hosts with an admin logged in/session
            }
        )

    @property
    def all_admins(self):
        all_admins = []

        for domain in self.data:
            all_admins.extend(self.get_domain_admins(domain))
            all_admins.extend(self.get_enterprise_admins(domain))

        return all_admins

    def get_admins_for_domain(self, admin_type, domain):
        admins = []
        for entry in self.data[domain][admin_type]:
            domain = entry["memberdomain"].split(".", 1)[0].upper()
            username = entry["membername"]
            admins.append(f"{domain}\\{username}")

        return admins

    def get_domain_controllers(self, domain):
        return self.data[domain]["domain_controllers"]

    def set_domain_controllers(self, domain, dcs):
        self.data[domain]["domain_controllers"] = dcs

    # These are needed for localization cause english isn't the only language in the world
    def get_da_group_name(self, domain):
        return self.data[domain]["domain_admins"][0]["groupname"]

    def get_ea_group_name(self, domain):
        return self.data[domain]["enterprise_admins"][0]["groupname"]

    def get_domain_admins(self, domain):
        return self.get_admins_for_domain("domain_admins", domain)

    def set_domain_admins(self, domain, domain_admins):
        self.data[domain]["domain_admins"] = domain_admins

    def get_enterprise_admins(self, domain):
        return self.get_admins_for_domain("enterprise_admins", domain)

    def set_enterprise_admins(self, domain, enterprise_admins):
        self.data[domain]["enterprise_admins"] = enterprise_admins

    def get_domain_sid(self, domain):
        return self.data[domain]["domain_sid"]

    def set_domain_sid(self, domain, sid):
        self.data[domain]["domain_sid"] = sid

    def get_priority_targets(self, domain):
        return self.data[domain]["priority_targets"]

    def set_priority_targets(self, domain, targets):
        for t in targets:
            self.data[domain]["priority_targets"].add(t)

    def been_performed(self, domain):
        return self.data[domain]["recon_performed"].is_set()

    def set_performed(self, domain):
        self.data[domain]["recon_performed"].set()

    def event(self, domain):
        return self.data[domain]["recon_performed"]
