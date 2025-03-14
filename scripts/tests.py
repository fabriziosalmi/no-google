import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def check_duplicates(filepath: str):
    """
    Checks for duplicate lines in a file.

    Args:
        filepath: The path to the file.

    Raises:
        AssertionError: If duplicate lines are found.
    """
    counts = {}
    try:
        with open(filepath, "r") as f:
            for line in f:
                domain = line.strip()  # strip whitespace and newline
                if domain:
                    if domain in counts:
                        counts[domain] += 1
                    else:
                        counts[domain] = 1
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        raise  # Re-raise to stop execution
    except IOError as e:
        logging.error(f"IO error reading file {filepath}: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise

    for domain, count in counts.items():
        if count > 1:
            raise AssertionError(
                f"Duplicate domain found: '{domain}' occurred {count} times in {filepath}. Please remove duplicate domains."
            )
    logging.info("No duplicate domains found.")


def check_regex_domains(filepath: str, forbidden_domains: list[str]):
    """
    Checks for forbidden regex-like domains in a file.

    Args:
        filepath: The path to the file.
        forbidden_domains: A list of forbidden substrings.

    Raises:
        AssertionError: If forbidden domains are found.

    """
    try:
        with open(filepath, "r") as f:
            for line_number, line in enumerate(f, 1):  # Start line numbers from 1
                domain = line.strip()
                if domain:
                    for forbidden in forbidden_domains:
                        if forbidden in domain:
                            raise AssertionError(
                                f"Forbidden domain '{forbidden}' found on line {line_number}: '{domain}' in {filepath}. Please remove regex domains."
                            )
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        raise # Re-raise to stop execution
    except IOError as e:
        logging.error(f"IO error: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise

    logging.info(f"No forbidden domains found in {filepath}.")



def main():
    parser = argparse.ArgumentParser(description="Check for duplicates and regex-like domains in a file.")
    parser.add_argument(
        "--type", nargs="?", choices=["duplicates", "regex"], help="Test Type"
    )
    parser.add_argument(
        "--file", nargs="?", default="../pihole-google.txt", help="Path to the file to check."
    )  # Added file argument
    args = parser.parse_args()

    filepath = args.file

    if args.type == "duplicates":
        check_duplicates(filepath)

    elif args.type == "regex":
        forbidden_domains = [".l.google.com", ".googlevideo.com"]
        check_regex_domains(filepath, forbidden_domains)
    else:
        logging.warning("No test type specified.  Please specify --type duplicates or --type regex")

def test_success():
    """
    Placeholder for a successful test (no errors).
    """
    assert True

if __name__ == "__main__":
    main()
