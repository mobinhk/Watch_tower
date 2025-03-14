#!/usr/bin/env python3

import subprocess
import argparse
import pymongo
import requests
import tempfile
import time
import os
import yaml
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# MongoDB configuration
MONGO_URI = "mongodb://localhost:27017"  # Update with your MongoDB URI

# Discord Webhook configuration
# Replace with your webhook URL
DISCORD_WEBHOOK_URL = "Replace with Own discord webhook url"

# Shodan API Key
# Replace with your Shodan API key
SHODAN_API_KEY = "Replace with Own shodan api key"

# Replace with your C99 API key
C99_api_key = "Replace with Own C99 api key"

# Define ANSI escape codes for colors
BLUE = '\033[94m'
YELLOW = '\033[93m'
RED = '\033[91m'
GREEN = '\033[92m'
WHITE = '\033[97m'
PINK = '\033[35m'
CYAN = '\033[96m'
BLACK = '\033[30m'
GRAY = '\033[90m'
RESET = '\033[0m'  # To reset the color back to default

# Add combinations for Bold and Underlined variants
BOLD_BLUE = '\033[1;94m'  # Bold Light Blue
BOLD_YELLOW = '\033[1;93m'  # Bold Light Yellow
BOLD_RED = '\033[1;91m'    # Bold Light Red
UNDERLINED_GREEN = '\033[4;92m'  # Underlined Light Green
RESET = '\033[0m'          # To reset the color back to default

lock = threading.Lock()


def process_targets_from_file(target_file, methods, threads):
    """Process domains from a target YAML file using multi-threading."""
    try:
        with open(target_file, 'r') as file:
            targets = yaml.safe_load(file)

        all_domains = []
        for target in targets.get('targets', []):
            name = target.get('name')
            domains = target.get('domains', [])
            for domain in domains:
                all_domains.append((domain, name))

        # Use ThreadPoolExecutor to process domains concurrently
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_domain = {
                executor.submit(main, domain, methods): domain
                for domain, name in all_domains
            }

            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    future.result()  # Wait for the thread to complete and handle exceptions
                    print(f"[*] Completed processing for domain: {domain}")
                except Exception as e:
                    print(f"Error processing domain {domain}: {e}")

    except FileNotFoundError:
        print(f"Error: Target file '{target_file}' not found.")
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file '{target_file}': {e}")


def send_to_discord(message):
    """Send a message to Discord using the webhook with rate limiting and 1-second delay between URLs."""
    payload = {"content": message}
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        if response.status_code == 429:  # Handle rate limiting
            # Default to 3 second if not provided
            retry_after = response.json().get("retry_after", 4)
            print(
                f"Rate limited by Discord. Retrying after {retry_after} seconds.")
            # Wait for the specified time before retrying
            time.sleep(retry_after)
            return send_to_discord(message)  # Retry sending the message
        elif response.status_code != 204:
            print(
                f"Failed to send message to Discord: {response.status_code} {response.text}")
    except Exception as e:
        print(f"Error sending message to Discord: {e}")

    # Check if the message contains a URL
    if URL_PATTERN.search(message):
        print("Message contains a URL, waiting 1 second before sending another.")
        time.sleep(10)  # Wait 10 second between messages containing URLs


def get_subdomains_from_crtsh(domain, max_retries=10, retry_delay=10):
    """Fetch subdomains using crt.sh with retry mechanism."""
    command = f"""curl -s "https://crt.sh/?q={domain}&output=json" | jq -r ".[].name_value" | sed 's/^\*\.//g' |sort -u"""
    retries = 0

    while retries < max_retries:
        try:
            # Fetch the subdomains
            result = subprocess.check_output(
                command, shell=True, text=True, executable='/bin/bash')

            # Check if the result is empty or does not contain valid URLs
            if result.strip():
                # Convert result to a set of subdomains
                subdomains = set(result.splitlines())
                if subdomains:
                    return subdomains  # Return the set of subdomains if valid
                else:
                    print(
                        f"No subdomains found in the response for domain: {domain}. Retrying...")
            else:
                print(
                    f"Empty response from crt.sh for domain: {domain}. Retrying...")

        except subprocess.CalledProcessError as e:
            print(f"Error fetching subdomains from crt.sh: {e}. Retrying...")
        except Exception as e:
            print(f"Unexpected error: {e}. Retrying...")

        # Increment the retry count and wait before retrying
        retries += 1
        time.sleep(retry_delay)

    print(
        f"Failed to fetch subdomains from crt.sh after {max_retries} retries.")
    return set()  # Return an empty set if retries are exhausted


def get_subdomains_from_abuseipdb(domain):
    """Fetch additional domain data from AbuseIPDB."""
    command = (
        f"""curl -s "https://www.abuseipdb.com/whois/{domain}" """
        f"""-H "user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36" """
        f"""-b "abuseipdb_session={replace_own_session}" """
        f"""| grep --color=auto --exclude-dir={{.bzr,CVS,.git,.hg,.svn,.idea,.tox}} --color=auto --exclude-dir={{.bzr,CVS,.git,.hg,.svn,.idea,.tox}} -E '<li>\\w.*</li>' """
        f"""| sed -E 's/<\\/?li>//g' | sed "s|$|.{domain}|" """
    )
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return result.strip().split("\n")
    except subprocess.CalledProcessError as e:
        print(f"Error fetching data from AbuseIPDB for {domain}: {e}")
        return []


def get_subdomains_from_subfinder(domain):
    """Fetch subdomains using subfinder."""
    command = f"subfinder -d {domain} --all -silent"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return set(result.splitlines())
    except subprocess.CalledProcessError as e:
        print(f"Error fetching subdomains from subfinder: {e}")
        return set()


def get_subdomains_from_shodan(domain):
    """Fetch subdomains using shosubgo (Shodan)."""
    command = f"shosubgo -d {domain} -s {SHODAN_API_KEY}"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return set(result.splitlines())
    except subprocess.CalledProcessError as e:
        print(f"Error fetching subdomains from Shodan: {e}")
        return set()


def get_subdomains_from_chaos(domain):
    """Fetch subdomains using chaos."""
    command = f"chaos -d {domain} -silent"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return set(result.splitlines())
    except subprocess.CalledProcessError as e:
        print(f"Error fetching subdomains from chaos: {e}")
        return set()


def get_subdomains_from_c99(domain, C99_api_key):
    """Fetch subdomains using C99 API."""
    url = f"https://api.c99.nl/subdomainfinder?key={C99_api_key}&domain={domain}&realtime=true"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return set(subdomain["subdomain"] for subdomain in data.get("subdomains", []))
    except requests.RequestException as e:
        print(f"Error fetching subdomains from C99: {e}")
        return set()


def run_dnsx(subdomains):
    """Run dnsx on the given subdomains using a temporary file."""
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
        # Write all subdomains to the temporary file
        for subdomain in subdomains:
            tmp_file.write(f"{subdomain}\n")
        tmp_file.flush()  # Ensure all data is written to the file

        # Use the temporary file with dnsx
        command = f"cat {tmp_file.name} | dnsx -silent"
        try:
            result = subprocess.check_output(command, shell=True, text=True)
            if result.strip():  # Ensure the result is not empty
                return result.strip().splitlines()  # Return a list of results
            else:
                print("No results from dnsx.")
                return []
        except subprocess.CalledProcessError as e:
            print(f"Error running dnsx: {e}")
            return []


def run_httpx(dnsx_results):
    """Run httpx on the DNSx results in batches."""
    httpx_results = []
    batch_size = 1000  # Process subdomains in batches of 1000
    try:
        for i in range(0, len(dnsx_results), batch_size):
            batch = dnsx_results[i:i + batch_size]
            # Write the batch to a temporary file
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
                tmp_file.writelines(f"{subdomain}\n" for subdomain in batch)
                tmp_file.flush()  # Ensure all data is written to the file

                # Run httpx on the batch
                command = (
                    f"cat {tmp_file.name} | httpx --status-code --title --tech-detect -silent "
                )
                result = subprocess.check_output(
                    command, shell=True, text=True)
                httpx_results.extend(result.strip().split("\n"))
    except subprocess.CalledProcessError as e:
        print(f"Error running httpx: {e}")
    except Exception as e:
        print(f"Unexpected error during httpx execution: {e}")

    return httpx_results


def save_httpx_results_by_shell(collections, httpx_results, domain):
    """Save HTTPx results to MongoDB collections categorized by status codes using shell commands."""
    try:
        # Save HTTPx results to a temporary file
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
            for result in httpx_results:
                tmp_file.write(f"{result}\n")
            tmp_file_path = tmp_file.name

        # Define shell commands for each status code
        commands = {
            "2xx": ["200"],
            "3xx": ["301", "302"],
            "4xx": ["400", "401", "403", "404"],
            "5xx": ["500", "501", "502", "503"],
        }

        # Process each category
        for category, status_codes in commands.items():
            results = []
            for status_code in status_codes:
                try:
                    # Run grep and awk to filter results
                    command = f"cat {tmp_file_path} | grep {status_code} | awk '{{print $1}}'"
                    output = subprocess.check_output(
                        command, shell=True, text=True).strip()
                    if output:
                        results.extend(output.split("\n"))
                except subprocess.CalledProcessError:
                    # Ignore if no matches found for this status code
                    continue

            # Save results to MongoDB collection
            if results:
                documents = [{"httpx_result": res} for res in results]
                collections[category].insert_many(documents)
                print(
                    f"{BOLD_BLUE}[*] Saved {len(documents)} HTTPx results to subdomain_httpx_{category} collection for {domain}{RESET}")
            else:
                print(
                    f"{BOLD_YELLOW}[*] No results to save for status category {category}. for {domain}{RESET}")
    finally:
        # Remove the temporary file
        if os.path.exists(tmp_file_path):
            os.remove(tmp_file_path)


def save_dnsx_results(collection, dnsx_results, domain):
    """Save DNSx results to the MongoDB collection."""
    if dnsx_results:
        documents = [{"dnsx_result": result} for result in dnsx_results]
        collection.insert_many(documents)
        print(
            f"{BOLD_RED}[*] Saved {len(documents)} DNSx results to the collection for {domain}{RESET}")
    else:
        print("No DNSx results to save.")


def get_existing_subdomains(collection):
    """Fetch all subdomains from the MongoDB collection in sorted order."""
    return sorted(
        {doc["subdomain"]
            for doc in collection.find({}, {"_id": 0, "subdomain": 1})}
    )


def add_new_subdomains_to_database(collection, new_subdomains):
    """Add new subdomains to the MongoDB collection in sorted order."""
    if new_subdomains:
        sorted_subdomains = sorted(new_subdomains)  # Sort before insertion
        documents = [{"subdomain": subdomain}
                     for subdomain in sorted_subdomains]
        collection.insert_many(documents)


def run_methods(domain, methods):
    """Run the specified methods to fetch subdomains, remove duplicates, and sort them."""

    subdomains = set()
    for method in methods:
        if method == "crt.sh":
            print(
                f"{BLUE}[*] Running crt.sh method for domain: {domain}{RESET}")
            crtsh_subdomains = get_subdomains_from_crtsh(domain)
            subdomains.update(crtsh_subdomains)
        elif method == "subfinder":
            print(
                f"{YELLOW}[*] Running subfinder method for domain: {domain}{RESET}")
            subfinder_subdomains = get_subdomains_from_subfinder(domain)
            subdomains.update(subfinder_subdomains)
        elif method == "shodan":
            print(f"{RED}[*] Running Shodan method for domain: {domain}{RESET}")
            shodan_subdomains = get_subdomains_from_shodan(domain)
            subdomains.update(shodan_subdomains)
        elif method == "abuseipdb":
            print(
                f"{WHITE}[*] Running abuseipdb method for domain: {domain}{RESET}")
            abuseipdb_subdomains = get_subdomains_from_abuseipdb(domain)
            subdomains.update(abuseipdb_subdomains)
        elif method == "chaos":
            print(
                f"{BLACK}[*] Running chaos method for domain: {domain}{RESET}")
            chaos_subdomains = get_subdomains_from_chaos(domain)
            subdomains.update(chaos_subdomains)
        elif method == "c99":
            print(
                f"{YELLOW}[*] Running C99 method for domain: {domain}{RESET}")
            c99_subdomains = get_subdomains_from_c99(domain, C99_api_key)
            subdomains.update(c99_subdomains)

    # Remove duplicates and sort subdomains
    sorted_subdomains = sorted(subdomains)
    print(
        f"{PINK}[*] Total unique subdomains collected: {len(sorted_subdomains)} for {domain}{RESET}")
    return sorted_subdomains


def send_to_discord(domain, subdomain_url):
    """Send a new subdomain message to Discord using the webhook."""
    message = f"Found a new subdomain on **{domain}**:\n```\n{subdomain_url}\n```"
    payload = {"content": message}
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        if response.status_code != 204:
            print(
                f"Failed to send message to Discord: {response.status_code} {response.text}")
    except Exception as e:
        print(f"Error sending message to Discord: {e}")


def main(domain, methods):
    # Replace '.' with '_' in the domain name to create a valid database name
    sanitized_domain = domain.replace(".", "_").replace("-", "_")

    # Connect to MongoDB
    client = pymongo.MongoClient(MONGO_URI)
    # Create or connect to the domain-specific database
    db = client[f"{sanitized_domain}_db"]
    subdomain_collection = db["subdomains"]
    dnsx_collection = db["subdomains_dnsx"]

    # Collections for HTTPx categorized results
    httpx_collections = {
        "2xx": db["subdomain_httpx_2xx"],
        "3xx": db["subdomain_httpx_3xx"],
        "4xx": db["subdomain_httpx_4xx"],
        "5xx": db["subdomain_httpx_5xx"]
    }

    # Fetch subdomains from methods
    current_subdomains = run_methods(domain, methods)

    # Fetch existing subdomains from the database
    existing_subdomains = get_existing_subdomains(subdomain_collection)

    # Determine new subdomains
    new_subdomains = set(current_subdomains) - set(existing_subdomains)

    # Check if it's the first run (no existing subdomains)
    is_first_run = not existing_subdomains

    # First-Time Execution
    if is_first_run:
        print(
            f"{UNDERLINED_GREEN}[*] First-time execution detected. Processing all subdomains for {domain}{RESET}")
        # Add all subdomains to the database
        add_new_subdomains_to_database(
            subdomain_collection, current_subdomains)

        # Run dnsx and save results
        dnsx_results = run_dnsx(current_subdomains)
        save_dnsx_results(dnsx_collection, dnsx_results, domain)

        # Run httpx and save results in collections
        httpx_results = run_httpx(dnsx_results)
        save_httpx_results_by_shell(httpx_collections, httpx_results, domain)

    else:
        # Subsequent Execution
        if new_subdomains:
            print(
                f"{YELLOW}[*] New subdomains found: {len(new_subdomains)} for {domain}{RESET}")
            # Add new subdomains to the database
            add_new_subdomains_to_database(
                subdomain_collection, new_subdomains)

            # Run dnsx and save results
            dnsx_results = run_dnsx(new_subdomains)
            save_dnsx_results(dnsx_collection, dnsx_results, domain)

            # Run httpx and save results in collections
            httpx_results = run_httpx(dnsx_results)
            save_httpx_results_by_shell(
                httpx_collections, httpx_results, domain)

            # Send only new httpx results to Discord
            if httpx_results:
                for result in httpx_results:
                    if result.strip():  # Ensure the result is not empty
                        send_to_discord(domain, result.split()[
                                        0])  # Send the URL only
                    else:
                        print(
                            f"{WHITE}[*] Skipping empty result for domain: {domain}{RESET}")
            else:
                print(f"[*] No HTTPx results to send for {domain}.")

        else:
            print(
                f"{CYAN}[*] No new subdomains found. Skipping further processing.{RESET}")

    # Close MongoDB connection
    client.close()


def drop_database(domain):
    """Drop the MongoDB database for the specified domain."""
    sanitized_domain = domain.replace(".", "_").replace("-", "_")
    client = pymongo.MongoClient(MONGO_URI)
    db_name = f"{sanitized_domain}_db"
    client.drop_database(db_name)
    print(f"Dropped database: {db_name}")
    client.close()


def count_subdomains(domain):
    """Count the number of subdomains for a domain in the database."""
    sanitized_domain = domain.replace(".", "_").replace("-", "_")
    client = pymongo.MongoClient(MONGO_URI)
    db = client[f"{sanitized_domain}_db"]
    collection = db["subdomains"]
    count = collection.count_documents({})
    client.close()
    return count


def show_subdomains(domain):
    """Show subdomains for a domain in the database."""
    sanitized_domain = domain.replace(".", "_").replace("-", "_")
    client = pymongo.MongoClient(MONGO_URI)
    db = client[f"{sanitized_domain}_db"]
    collection = db["subdomains"]

    subdomains = list(collection.find(
        {}, {"_id": 0, "subdomain": 1}))  # Fetch subdomains
    client.close()  # Close the client only after fetching

    for sub in subdomains:
        print(sub["subdomain"])


def show_httpx_results_by_status(domain, status):
    """Show HTTPx results for a specific status code category."""
    sanitized_domain = domain.replace(".", "_").replace("-", "_")
    client = pymongo.MongoClient(MONGO_URI)
    db = client[f"{sanitized_domain}_db"]
    collection = db[f"subdomain_httpx_{status}"]

    httpx_results = collection.find({}, {"_id": 0, "httpx_result": 1})
    for result in httpx_results:
        print(result["httpx_result"])

    client.close()


def show_subdomains_dnsx(domain):
    """Show DNSX subdomains for a domain in the database."""
    sanitized_domain = domain.replace(".", "_").replace("-", "_")
    client = pymongo.MongoClient(MONGO_URI)
    db = client[f"{sanitized_domain}_db"]
    collection = db["subdomains_dnsx"]  # Collection for DNSX subdomains

    subdomains_dnsx = list(collection.find(
        {}, {"_id": 0, "dnsx_result": 1}))  # Fetch dnsx_result field
    client.close()  # Close the client only after fetching

    # Process and return the data
    return [sub["dnsx_result"] for sub in subdomains_dnsx]


def count_httpx_results_by_status(domain, status):
    """Count the number of HTTPx results for a specific status code category."""
    sanitized_domain = domain.replace(".", "_").replace("-", "_")
    client = pymongo.MongoClient(MONGO_URI)
    db = client[f"{sanitized_domain}_db"]
    collection = db[f"subdomain_httpx_{status}"]

    count = collection.count_documents({})
    client.close()
    return count


def count_dnsx_results(domain):
    """Count the number of DNSx results for a domain in the database."""
    sanitized_domain = domain.replace(".", "_").replace("-", "_")
    client = pymongo.MongoClient(MONGO_URI)
    db = client[f"{sanitized_domain}_db"]
    dnsx_collection = db["subdomains_dnsx"]

    count = dnsx_collection.count_documents({})
    client.close()
    return count


# Define the ANSI escape codes for white and reset
WHITE = "\033[37m"
RESET = "\033[0m"

# Define the custom ArgumentParser that adds color


class ColoredArgumentParser(argparse.ArgumentParser):
    def print_help(self, file=None):
        # Capture the help output in the normal way
        output = sys.stdout if file is None else file
        # Print the entire help message in white color
        help_text = self.format_help()
        # Apply the white color to the entire help message
        output.write(f"{WHITE}{help_text}{RESET}\n")


# Main logic
if __name__ == "__main__":
    # Create the parser using the custom class
    parser = ColoredArgumentParser(
        description="Fetch subdomains and perform DNSx and HTTPx scans.")

    # Define the command-line arguments
    parser.add_argument(
        "-u", "--domain", help="The domain to fetch subdomains for.")
    parser.add_argument(
        "--method",
        help="Comma-separated methods to use: [crt.sh, subfinder, shodan, abuseipdb , chaos , C99 ,  all]",
    )
    parser.add_argument(
        "--target-file", help="Path to the YAML file containing targets.")
    parser.add_argument("--count-target", metavar="DOMAIN",
                        help="Count the number of subdomains in the database for the target domain.")
    parser.add_argument("--count-dnsx", metavar="DOMAIN",
                        help="Count the number of DNSx results in the database for the target domain.")
    parser.add_argument("--count-http-2xx", metavar="DOMAIN",
                        help="Count the number of 2xx HTTPx results in the database for the target domain.")
    parser.add_argument("--count-http-3xx", metavar="DOMAIN",
                        help="Count the number of 3xx HTTPx results in the database for the target domain.")
    parser.add_argument("--count-http-4xx", metavar="DOMAIN",
                        help="Count the number of 4xx HTTPx results in the database for the target domain.")
    parser.add_argument("--count-http-5xx", metavar="DOMAIN",
                        help="Count the number of 5xx HTTPx results in the database for the target domain.")
    parser.add_argument("--show-subdomains", action="store_true",
                        help="Show all subdomains for the given domain")
    parser.add_argument("--show-subdomains-dns", action="store_true",
                        help="Show all DNSX subdomains for the given domain")
    parser.add_argument(
        "--show-http-2xx", help="Show 2xx HTTPx results for the target domain.", action="store_true")
    parser.add_argument(
        "--show-http-3xx", help="Show 3xx HTTPx results for the target domain.", action="store_true")
    parser.add_argument(
        "--show-http-4xx", help="Show 4xx HTTPx results for the target domain.", action="store_true")
    parser.add_argument(
        "--show-http-5xx", help="Show 5xx HTTPx results for the target domain.", action="store_true")
    parser.add_argument("--db-drop", metavar="DOMAIN",
                        help="Drop the database associated with the specified domain.")
    parser.add_argument("--threads", type=int, metavar="THREADS", default=5,
                        help="Number of threads for processing domains (default: 5).")

    # Parse the arguments
    args = parser.parse_args()

    # Handle the rest of your application logic
    if args.db_drop:
        drop_database(args.db_drop)
    elif args.count_target:
        count = count_subdomains(args.count_target)
        print(f"Total subdomains for {args.count_target}: {count}")
    elif args.count_dnsx:
        count = count_dnsx_results(args.count_dnsx)
        print(f"Total DNSx results for {args.count_dnsx}: {count}")
    elif args.count_http_2xx:
        count = count_httpx_results_by_status(args.count_http_2xx, "2xx")
        print(f"Total HTTPx 2xx results for {args.count_http_2xx}: {count}")
    elif args.count_http_3xx:
        count = count_httpx_results_by_status(args.count_http_3xx, "3xx")
        print(f"Total HTTPx 3xx results for {args.count_http_3xx}: {count}")
    elif args.count_http_4xx:
        count = count_httpx_results_by_status(args.count_http_4xx, "4xx")
        print(f"Total HTTPx 4xx results for {args.count_http_4xx}: {count}")
    elif args.count_http_5xx:
        count = count_httpx_results_by_status(args.count_http_5xx, "5xx")
        print(f"Total HTTPx 5xx results for {args.count_http_5xx}: {count}")
    elif args.show_http_2xx:
        if args.domain:
            show_httpx_results_by_status(args.domain, "2xx")
        else:
            parser.error(
                "You must provide a domain with --show-http-2xx using -u or --domain.")
    elif args.show_http_3xx:
        if args.domain:
            show_httpx_results_by_status(args.domain, "3xx")
        else:
            parser.error(
                "You must provide a domain with --show-http-3xx using -u or --domain.")
    elif args.show_http_4xx:
        if args.domain:
            show_httpx_results_by_status(args.domain, "4xx")
        else:
            parser.error(
                "You must provide a domain with --show-http-4xx using -u or --domain.")
    elif args.show_http_5xx:
        if args.domain:
            show_httpx_results_by_status(args.domain, "5xx")
        else:
            parser.error(
                "You must provide a domain with --show-http-5xx using -u or --domain.")
    elif args.show_subdomains:
        subdomains = show_subdomains(args.domain)
        if subdomains:
            print(f"Subdomains for {args.domain}:")
            for subdomain in subdomains:
                print(subdomain)
        else:
            print(f"No subdomains found for {args.domain}.")
    elif args.show_subdomains_dns:
        subdomains = show_subdomains_dnsx(args.domain)
        if subdomains:
            print(f"DNSX subdomains for {args.domain}:")
            for subdomain in subdomains:
                print(subdomain)
        else:
            print(f"No DNSX subdomains found for {args.domain}.")

    elif args.target_file:  # Process the YAML file first
        if args.method:
            if args.method == "all":
                methods = ["crt.sh", "subfinder",
                           "shodan", "abuseipdb", "chaos", "c99"]
            else:
                methods = args.method.split(",")
            process_targets_from_file(args.target_file, methods, args.threads)
        else:
            parser.error(
                "You must provide a method with --target-file using --method.")
    elif args.domain and args.method:  # Process a single domain
        if args.method == "all":
            methods = ["crt.sh", "subfinder",
                       "shodan", "abuseipdb", "chaos", "c99"]
        else:
            methods = args.method.split(",")
        main(domain=args.domain, methods=methods)
    else:
        parser.error(
            "You must provide either --db-drop, --count-target, --count-dnsx, --count-http-{status}, --show-http-{status}, --target-file, or both --domain and --method.")
