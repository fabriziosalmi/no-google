import json
import sys
import logging
from collections import OrderedDict, defaultdict
from datetime import date
from pathlib import Path
from typing import Dict, List, Callable

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class DomainBlocklistConverter:

    INPUT_FILE = "pihole-google.txt"
    PIHOLE_FILE = "google-domains"
    UNBOUND_FILE = "pihole-google-unbound.conf"
    ADGUARD_FILE = "pihole-google-adguard.txt"
    ADGUARD_IMPORTANT_FILE = "pihole-google-adguard-important.txt"
    CATEGORIES_PATH = "categories"

    BLOCKLIST_ABOUT = "This blocklist helps to restrict access to Google and its domains. Contribute at https://github.com/nickspaargaren/no-google"

    def __init__(self):
        self.data: Dict[str, List[str]] = OrderedDict()
        self.timestamp: str = date.today().strftime("%Y-%m-%d")

    def read(self):
        """
        Reads the input file into `self.data`, handling file errors.
        """
        try:
            with open(self.INPUT_FILE, "r") as f:
                category = None
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        category = line.lstrip("# ").strip()  # More robust category extraction
                        self.data.setdefault(category, [])
                    elif line:  # Only process non-empty lines
                        if category is None:
                            raise ValueError("Unable to store item without category")
                        self.data[category].append(line)
        except FileNotFoundError:
            logging.error(f"Input file not found: {self.INPUT_FILE}")
            sys.exit(1)  # Exit on critical error
        except ValueError as e:
            logging.error(str(e))
            sys.exit(1)
        except IOError as e:
            logging.error(f"IO Error reading file: {e}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            sys.exit(1)


    def dump(self):
        """
        Outputs data in JSON format on STDOUT.
        """
        try:
            print(json.dumps(self.data, indent=4))
        except Exception as e:
            logging.error(f"Error dumping JSON: {e}")

    def _write_blocklist(self, filename: str, line_formatter: Callable[[str], str]):
        """
        Generic function to write blocklist files.

        Args:
            filename: The name of the file to write.
            line_formatter: A function that takes a domain and returns the formatted line.
        """
        try:
            with open(filename, "w") as f:
                f.write(f"# {self.BLOCKLIST_ABOUT}\n")
                f.write(f"# Last updated: {self.timestamp}\n")
                for category, entries in self.data.items():
                    f.write(f"# {category}\n")  # Or "# Category: {category}\n" for unbound
                    for entry in entries:
                        if entry: # Skip empty entries
                            f.write(line_formatter(entry))
        except IOError as e:
            logging.error(f"IO Error writing file '{filename}': {e}")
            sys.exit(1) # Exit on critical error
        except Exception as e:
            logging.error(f"Unexpected error writing file '{filename}': {e}")
            sys.exit(1)  # Exit on critical error


    def pihole(self):
        """
        Produces blocklist for the Pi-hole.
        """
        self._write_blocklist(self.PIHOLE_FILE, lambda entry: f"0.0.0.0 {entry}\n")

    def unbound(self):
        """
        Produces blocklist for the Unbound DNS server.
        """
        self._write_blocklist(self.UNBOUND_FILE, lambda entry: f'local-zone: "{entry}" always_refuse\n')

    def adguard(self):
        """
        Produces blocklist for AdGuard.
        """
        self._write_blocklist(self.ADGUARD_FILE, lambda entry: f"||{entry}^\n")

    def adguard_important(self):
        """
        Produces blocklist for AdGuard including important syntax.
        """
        self._write_blocklist(self.ADGUARD_IMPORTANT_FILE, lambda entry: f"||{entry}^$important\n")


    def categories(self):
        """
        Produces individual per-category blocklist files.
        """
        try:
            # Create the categories directory if it doesn't exist
            Path(self.CATEGORIES_PATH).mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logging.error(f"Error creating directory '{self.CATEGORIES_PATH}': {e}")
            return  # Don't exit, as we might still be able to create some files

        for category, entries in self.data.items():
            # Compute file names.
            filename = category.replace(" ", "").lower()
            filepath = Path(self.CATEGORIES_PATH).joinpath(filename)
            text_file = filepath.with_suffix(".txt")
            parsed_file = str(filepath) + "parsed"

            # Write two flavours of per-category file, using lambdas for formatting.
            self._write_blocklist(text_file, lambda entry: f"0.0.0.0 {entry}\n")
            self._write_blocklist(parsed_file, lambda entry: f"{entry}\n")


    def duplicates(self):
        """
        Finds and reports duplicates in the main source file.
        """
        hashes = defaultdict(int)
        duplicates_found = False
        for entries in self.data.values(): # Iterate over all entries efficiently
          for entry in entries:
            hashes[entry] += 1

        for entry, count in hashes.items():
            if count > 1:
                print(f"Domain {entry} found {count} times, please remove duplicate domains.")
                duplicates_found = True

        if not duplicates_found:
            print("No duplicate domains found.")


def run(action: str, action_candidates: list[str]):
    """
    Invokes different actions on converter engine.
    """

    # Create converter instance and read input file.
    converter = DomainBlocklistConverter()
    converter.read()

    # Invoke special action "json".
    if action == "json":
        converter.dump()
        return  # Exit after dumping JSON

    # Either invoke specific action, or expand to all actions.
    if action == "all":
        subcommands = action_candidates
    else:
        subcommands = [action]

    # Invoke all actions subsequently.
    for action in subcommands:
        logging.info(f"Invoking subcommand '{action}'")
        try:
            method = getattr(converter, action)
            method()
        except AttributeError:
            logging.error(f"Invalid subcommand: {action}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error during '{action}': {e}")
            sys.exit(1)  # Exit on error during action execution


if __name__ == "__main__":

    # Read subcommand from command line, with error handling.
    action_candidates = [
        "pihole",
        "unbound",
        "adguard",
        "adguard_important",
        "categories",
    ]
    special_candidates = ["all", "duplicates", "json"]
    subcommand = None
    try:
        subcommand = sys.argv[1]
    except IndexError:
        pass  # No subcommand provided
    if subcommand not in action_candidates + special_candidates:
        logging.error(
            f"Subcommand not given or invalid, please use one of {action_candidates + special_candidates}"
        )
        sys.exit(1)

    # Invoke subcommand.
    run(subcommand, action_candidates)
