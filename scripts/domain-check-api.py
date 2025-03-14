import whois
import time
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def get_domain(url: str) -> str:
    """
    Extracts the domain name from a URL.

    Args:
        url: The URL to extract the domain from.

    Returns:
        The extracted domain name, or the original URL if extraction fails.
    """
    try:
        # More robust domain extraction using regular expressions
        match = re.search(r'(?:https?:\/\/)?(?:www\.)?([\w.-]+)(?:\/.*)?$', url)
        if match:
            domain = match.group(1)  # Get the captured group (domain part)

            # Further refine to get only the main domain (e.g., example.com from sub.example.com)
            parts = domain.split('.')
            if len(parts) > 2:
                domain = '.'.join(parts[-2:])  # Take last two parts
            return domain
        else:
            return url # Return original if no match found
    except Exception as e:
        logging.error(f"Error extracting domain from {url}: {e}")
        return url  # Return original URL on error

def remove_duplicates(mylist: list[str]) -> list[str]:
    """Removes duplicate entries from a list, preserving order.

    Args:
        mylist: The input list.

    Returns:
        A new list with duplicates removed.
    """
    return list(dict.fromkeys(mylist))


def get_domains(filepath: str = "../pihole-google.txt"):
    """
    Yields unique domain names from a file, excluding comments and lines with colons.

    Args:
        filepath: The path to the file containing the domains.

    Yields:
        Unique domain names.
    """
    try:
        with open(filepath, "r") as main:
            for line in main:
                line = line.strip()  # Remove leading/trailing whitespace
                if line and not line.startswith("#") and ":" not in line:
                    domain = get_domain(line)
                    if domain:  # Ensure domain is not empty
                        yield domain
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
    except IOError as e:
        logging.error(f"IO error reading file {filepath}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred reading file {filepath}: {e}")


def is_registered(domain: str):
    """
    Checks if a domain is registered and retrieves its WHOIS information.

    Args:
        domain: The domain name to check.

    Returns:
        A list containing the domain name, organization, and nameservers if registered,
        False otherwise.  Returns None if the whois query fails due to rate limiting
        or other transient errors.
    """
    time.sleep(1)  # Respect WHOIS servers
    try:
        w = whois.whois(domain)
        if w.domain_name: # Check if domain_name exists and is not None or empty
            # Normalize domain_name to a list (it can be a string or a list)
            domain_names = w.domain_name if isinstance(w.domain_name, list) else [w.domain_name]

            # Normalize name_servers to lowercase to avoid case inconsistencies
            name_servers = [server.lower() for server in w.name_servers] if isinstance(w.name_servers, list) else []

            return [domain_names, w.org, name_servers]
        else:
            return False # Domain is not registered (or whois info is incomplete)

    except whois.parser.PywhoisError as e:
        logging.warning(f"PywhoisError for {domain}: {e}")
        return False
    except whois.exceptions.WhoisCommandFailed:
        logging.warning(f"Whois command failed for {domain}.  Likely not registered.")
        return False
    except whois.exceptions.UnknownTld:
        logging.warning(f"Unknown TLD for {domain}.")
        return False
    except whois.exceptions.FailedParsingWhoisOutput:
        logging.warning(f"Failed to parse WHOIS output for {domain}")
        return False
    except whois.exceptions.UnknownDateFormat:
        logging.warning(f"Unknown date format in WHOIS output for {domain}")
        return False
    except ConnectionRefusedError:  # Handle connection refused errors
        logging.warning(f"Connection refused for {domain}.  May be rate limited.  Pausing for a longer duration")
        time.sleep(30) # Wait longer and retry later
        return None # Use None to signal a temporary error
    except TimeoutError: # Handle Timeout errors
        logging.warning(f"Connection timeout for {domain}. May be rate limited. Pausing...")
        time.sleep(10) # Wait and retry later
        return None  # Use None to signal a temporary error
    except Exception as e:
        logging.exception(f"Unexpected error during WHOIS lookup for {domain}: {e}")
        return False



def main():
    """
    Main function to iterate over domains and check their registration status.
    """
    domains = remove_duplicates(list(get_domains()))  # Convert generator to list and remove duplicates
    retry_domains = []

    for domain in domains:
        result = is_registered(domain)
        if result is None:  # Temporary error (e.g., rate limit)
            retry_domains.append(domain)
        else:
            print(f"{domain}: {result}")

    if retry_domains:
      print("\nRetrying domains that encountered temporary errors...")
      for domain in retry_domains:
          result = is_registered(domain)
          print(f"{domain}: {result}")


if __name__ == "__main__":
    main()
