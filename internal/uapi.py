import json
import subprocess


class AutoSSLException(Exception):
    """Base exception for AutoSSL operations."""

    pass


class CommandExecutionError(AutoSSLException):
    """Raised when a subprocess command fails."""

    pass


class JSONParsingError(AutoSSLException):
    """Raised when JSON parsing fails."""

    pass


class UnexpectedResponseError(AutoSSLException):
    """Raised when the response structure is unexpected."""

    pass


def exclude_subdomains_from_autossl(user):
    """
    Fetch all subdomains for a given cPanel user, filter out the root domain and its www. version,
    and exclude the remaining subdomains from AutoSSL.

    Args:
        user (str): The cPanel username.

    Raises:
        CommandExecutionError: If a subprocess command fails.
        JSONParsingError: If the JSON response cannot be parsed.
        UnexpectedResponseError: If the response structure is invalid or missing expected data.
    """
    try:
        # Fetch SSL installed hosts
        command = f"uapi --user={user} SSL installed_hosts --output=json"
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)

        # Extract the main domain (servername) and the FQDNs
        ssl_data = data["result"]["data"]
        if not ssl_data:
            raise UnexpectedResponseError("No SSL data found for the user.")

        main_domain = ssl_data[0]["servername"]
        fqdns = ssl_data[0]["fqdns"]

        # Filter out root domain and www version of the root domain
        excluded_domains = [
            fqdn for fqdn in fqdns if fqdn not in {main_domain, f"www.{main_domain}"}
        ]

        if not excluded_domains:
            print("No subdomains to exclude from AutoSSL.")
            return

        # Exclude these subdomains using set_autossl_excluded_domains
        exclude_command = (
            f"uapi --user={user} SSL set_autossl_excluded_domains "
            f"--arg domains={','.join(excluded_domains)} --output=json"
        )
        exclude_result = subprocess.run(
            exclude_command, shell=True, capture_output=True, text=True, check=True
        )
        exclude_data = json.loads(exclude_result.stdout)

        if exclude_data["result"]["status"] != 1:
            raise UnexpectedResponseError(
                f"Failed to update AutoSSL exclusions: {exclude_data['result'].get('errors', 'Unknown error')}"
            )

        print(
            f"Successfully excluded the following subdomains from AutoSSL: {excluded_domains}"
        )

    except subprocess.CalledProcessError as e:
        raise CommandExecutionError(f"Command execution failed: {e.stderr.strip()}")
    except json.JSONDecodeError:
        raise JSONParsingError("Failed to parse JSON response.")
    except KeyError:
        raise UnexpectedResponseError("Unexpected response structure.")


if __name__ == "__main__":

    # Example usage
    try:
        user = "chitpayment"
        exclude_subdomains_from_autossl(user)
    except AutoSSLException as e:
        print(f"Error: {e}")
