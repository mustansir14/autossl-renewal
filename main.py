import subprocess
import time
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from internal.cloudflare import CloudflareClient
from internal.env import Env
from internal.uapi import exclude_subdomains_from_autossl

LOG_FILE = "/var/log/cf_autossl_renew.log"
HOURS_LEFT_TO_EXPIRY=48


cloudflare = CloudflareClient(
    email=Env.CLOUDFLARE_EMAIL, api_key=Env.CLOUDFLARE_API_KEY
)


def log_message(message):
    """Write log message to file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{timestamp} - {message}\n")


def get_domains():
    """Retrieve the list of domains from the cPanel server."""
    with open("/etc/localdomains", "r") as file:
        return [line.strip() for line in file if line.strip()]


def get_certificate_expiry(domain):
    """Check the SSL certificate expiry date."""
    cert_path = f"/var/cpanel/ssl/apache_tls/{domain}/combined"
    try:
        with open(cert_path, "rb") as cert_file:
            cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        return cert.not_valid_after_utc
    except Exception as e:
        log_message(f"Error checking certificate expiry for {domain}: {e}")
        return None


def update_cloudflare_record(domain, ip_address):
    """Update Cloudflare A record for the domain."""
    try:
        zone = cloudflare.get_zone_by_domain(domain)

        records = cloudflare.get_dns_records(zone.id)

        for record in records:
            if record.type == "A" and record.name == domain:
                record_id = record.id
                if ip_address == Env.PRIMARY_SERVER_IP:
                    proxied = False
                else:
                    proxied = True
                cloudflare.update_dns_record(
                    zone_id=zone.id,
                    dns_record_id=record_id,
                    type="A",
                    name=domain,
                    content=ip_address,
                    proxied=proxied,
                )
                log_message(f"Updated A record for {domain} to {ip_address}")
                break
    except Exception as e:
        log_message(f"Error updating Cloudflare record for {domain}: {e}")
        raise e


def get_cpanel_user(domain):
    """Retrieve the cPanel username for a domain using cPanel's API."""

    result = subprocess.run(
        f"/scripts/whoowns {domain}",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    if result.returncode != 0:
        log_message(
            f"Error retrieving cPanel user for {domain}: {result.stderr.decode('utf-8').strip()}"
        )
        raise Exception(
            f"Error retrieving cPanel user for {domain}: {result.stderr.decode('utf-8').strip()}"
        )

    return result.stdout.decode("utf-8").strip()


def run_autossl_check(user):
    """Run the AutoSSL check for a cPanel user using cPanel API."""

    # exclude subdomains from check
    try:
        exclude_subdomains_from_autossl(user)
    except Exception as e:
        log_message("Error excluding sub domains: " + str(e))

    result = subprocess.run(
        f"/usr/local/cpanel/bin/autossl_check --user={user}",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    if result.returncode != 0:
        log_message(
            f"Error running AutoSSL check for {user}: {result.stderr.decode('utf-8').strip()}"
        )
        raise Exception(
            f"Error running AutoSSL check for {user}: {result.stderr.decode('utf-8').strip()}"
        )

    log_message(result.stdout.decode("utf-8").strip())


def main():
    """Main script logic."""
    domains = get_domains()

    domains_to_renew = []
    for domain in domains:
        try:
            expiry_date = get_certificate_expiry(domain)
            if not expiry_date:
                continue

            time_to_expiry = expiry_date - datetime.now(timezone.utc)
            if time_to_expiry > timedelta(hours=HOURS_LEFT_TO_EXPIRY):
                log_message(f"Skipping {domain}: Certificate not expiring soon.")
                continue

            # Update Cloudflare to use the Primary Server IP
            update_cloudflare_record(domain, Env.PRIMARY_SERVER_IP)

            domains_to_renew.append(domain)
        except Exception:
            pass

    if domains_to_renew:
        # Wait for propagation
        log_message(f"Waiting for {Env.WAIT_TIME} seconds for DNS propagation...")
        time.sleep(Env.WAIT_TIME)

    for domain in domains_to_renew:
        try:

            try:
                # Run AutoSSL check
                user = get_cpanel_user(domain)
                run_autossl_check(user)
            except Exception as e:
                print(e)

            # Revert Cloudflare A record to Load Balancer IP
            update_cloudflare_record(domain, Env.LOAD_BALANCER_IP)

            log_message("AutoSSL renewal process completed.")
        except Exception:
            pass


if __name__ == "__main__":
    main()
