from typing import List

from cloudflare import BadRequestError, Cloudflare, NotFoundError


class CloudflareClient:
    def __init__(self, email: str, api_key: str):
        self.cloudflare = Cloudflare(api_email=email, api_key=api_key)

    def get_zone_by_domain(self, domain: str) -> object:
        zone = self.cloudflare.zones.list(name=domain)
        if zone.result:
            return zone.result[0]
        raise Exception(f"Zone with domain {domain} not found")

    def get_dns_records(self, zone_id: str) -> List[object]:
        dns_records = []
        for dns_record in self.cloudflare.dns.records.list(zone_id=zone_id):
            dns_records.append(dns_record)
        return dns_records

    def update_dns_record(
        self,
        zone_id: str,
        dns_record_id: str,
        type: str,
        name: str,
        content: str,
        proxied: bool,
    ):
        try:
            self.cloudflare.dns.records.update(
                dns_record_id=dns_record_id,
                zone_id=zone_id,
                type=type,
                name=name,
                content=content,
                proxied=proxied,
            )
        except BadRequestError as e:
            raise Exception(f"Failed to update DNS record: {e}")
        except NotFoundError as e:
            raise Exception(f"DNS record not found: {e}")
