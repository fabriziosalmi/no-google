import dns.resolver
import dns.exception
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


def check_domain(domain, resolver=None):
    """
    Checks if a domain has NS records.  Returns True if the domain does *not* have NS records.

    Args:
        domain (str): The domain to check.
        resolver (dns.resolver.Resolver, optional): Custom resolver. Defaults to None.

    Returns:
        bool: True if the domain does *not* have NS records, False otherwise.
    """
    if not resolver:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5  # Set a reasonable timeout to avoid hanging
        resolver.lifetime = 5

    try:
        # Query for 'NS' records
        resolver.resolve(domain, "NS")
        return False  # NS records found
    except dns.resolver.NXDOMAIN:
        return True  # No NS records (domain does not exist)
    except dns.resolver.NoNameservers:
        # This often indicates a problem with the domain's DNS setup. We treat these as if NS records ARE present (don't remove)
        logging.warning(f"No name servers found for {domain}.  Treating as if NS records exist.")
        return False
    except dns.resolver.NoAnswer:
        # No NS records, but other records may exist. We treat these as if NS records ARE present (don't remove)
        logging.warning(f"No NS answer for {domain}. Treating as if NS records exist.")
        return False
    except dns.resolver.Timeout:
        logging.warning(f"Timeout resolving {domain}. Treating as if NS records exist.")
        return False
    except dns.exception.DNSException as e:
        logging.error(f"DNS Exception for {domain}: {e}. Treating as if NS records exist.")
        return False
    except Exception as e:
        logging.exception(f"Unexpected error resolving {domain}: {e}.  Treating as if NS records exist.")
        return False


def main():
    found_domains = 0
    domains_with_ns_records = []
    input_file = "../pihole-google.txt"
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        with open(input_file, "r") as f:
            for line in f:
                line = line.strip()  # strip whitespace and newline
                if line and not line.startswith("#"):
                    if check_domain(line, resolver):
                        logging.info(f"Domain without NS records: {line}")
                        found_domains += 1
                    else:
                        domains_with_ns_records.append(line + "\n")  # Re-add newline
                else:
                    domains_with_ns_records.append(line + "\n")  # Re-add newline for comments

    except FileNotFoundError:
        logging.error(f"Error: Input file '{input_file}' not found.")
        return
    except IOError as e:
        logging.error(f"IO Error reading file '{input_file}': {e}")
        return


    # Write remaining domains back to the file
    try:
        with open(input_file, "w") as f:
            f.writelines(domains_with_ns_records)
    except IOError as e:
        logging.error(f"IO Error writing to file '{input_file}': {e}")
        return

    logging.info(f"Processed domains. Found {found_domains} domains without NS records.")

if __name__ == "__main__":
    main()
