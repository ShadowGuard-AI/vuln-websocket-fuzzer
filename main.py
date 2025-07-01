import argparse
import logging
import sys
import json
import time
import random
import os

import websocket  # Requires: pip install websocket-client
import requests    # Requires: pip install requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Fuzzing payloads - expand as needed
FUZZ_PAYLOADS = [
    "",  # Empty payload
    "A" * 1000,  # Large payload
    "<script>alert('XSS')</script>",  # XSS payload
    "'; DROP TABLE users; --",  # SQL injection payload
    "%00", # Null byte
    "\\", # Backslash
    "\n", # Newline
    "\r", # Carriage return
    "{\"cmd\": \"system('rm -rf /')\"}",  # Command injection attempt (JSON)
    "{\"cmd\": \"eval(base64_decode('c3lzdGVtKCdybSAtcmYgLycp')\"}", # Command Injection Base64 encoded
]

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='WebSocket Fuzzer - Tests WebSocket endpoints for vulnerabilities.')

    parser.add_argument('url', type=str, help='The WebSocket URL to fuzz (e.g., ws://example.com/ws).  Use wss:// for secure WebSockets.')
    parser.add_argument('-n', '--num-requests', type=int, default=10, help='Number of fuzz requests to send. Defaults to 10.')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay (in seconds) between requests. Defaults to 0.1.')
    parser.add_argument('-l', '--log-file', type=str, help='File to save the logs to. If not specified, logs are printed to the console.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (debug logging).')
    parser.add_argument('-p', '--payload-file', type=str, help='Path to a file containing a list of payloads (one per line).  Overrides default payloads.')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout (in seconds) for WebSocket connection. Defaults to 10.')
    parser.add_argument('--origin', type=str, help='Sets the Origin header. Useful to check CORS bypass.')


    return parser.parse_args()


def load_payloads_from_file(filename):
    """
    Loads payloads from a file, one payload per line.

    Args:
        filename (str): The path to the payload file.

    Returns:
        list: A list of strings representing the payloads.  Returns an empty list if the file is invalid.
    """
    try:
        with open(filename, 'r') as f:
            payloads = [line.strip() for line in f]
        return payloads
    except FileNotFoundError:
        logging.error(f"Payload file not found: {filename}")
        return []
    except Exception as e:
        logging.error(f"Error reading payload file: {e}")
        return []


def fuzz_websocket(url, num_requests, delay, payloads, timeout, origin=None):
    """
    Fuzzes a WebSocket endpoint by sending various payloads.

    Args:
        url (str): The WebSocket URL to fuzz.
        num_requests (int): The number of requests to send.
        delay (float): The delay (in seconds) between requests.
        payloads (list): A list of payloads to send.
        timeout (int): Timeout in seconds for the websocket connection.
        origin (str):  The origin header to set.

    Returns:
        None
    """
    logging.info(f"Fuzzing WebSocket endpoint: {url}")
    logging.info(f"Number of requests: {num_requests}, Delay: {delay}s, Number of Payloads: {len(payloads)}")

    try:
        ws = websocket.create_connection(url, timeout=timeout, origin=origin) # Origin is passed for CORS testing

        for i in range(num_requests):
            payload = random.choice(payloads)
            logging.debug(f"Sending payload {i+1}/{num_requests}: {payload}")

            try:
                ws.send(payload)
                # Consider logging the response if needed
                if len(payload) < 100:  #Only try to receive if sent payload small to avoid hanging the server
                    try:
                         result = ws.recv(timeout=2) #small timeout for receiving
                         logging.info(f"Received: {result}")
                    except websocket.WebSocketTimeoutException:
                        logging.info("No response received after sending the payload.")
                    except Exception as e:
                        logging.error(f"Error receiving data: {e}")
                else:
                    logging.info(f"Payload larger than 100 chars, skipping receive.  Payload length: {len(payload)}")

            except websocket.WebSocketException as e:
                logging.error(f"WebSocket error: {e}")
                break  # Stop fuzzing if a critical error occurs

            except Exception as e:
                logging.error(f"An unexpected error occurred: {e}")
                break

            time.sleep(delay)

        ws.close()
        logging.info("Fuzzing completed.")

    except websocket.WebSocketException as e:
        logging.error(f"Failed to connect or communicate with WebSocket: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def main():
    """
    Main function to parse arguments and start the fuzzer.
    """
    args = setup_argparse()

    # Configure logging based on arguments
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.debug("Starting vuln-Websocket-Fuzzer")
    logging.debug(f"Arguments: {args}")


    # Input Validation
    if not args.url.startswith(('ws://', 'wss://')):
        logging.error("Invalid WebSocket URL. Must start with ws:// or wss://")
        sys.exit(1)

    if args.num_requests <= 0:
        logging.error("Number of requests must be a positive integer.")
        sys.exit(1)

    if args.delay < 0:
        logging.error("Delay must be a non-negative number.")
        sys.exit(1)

    # Load payloads
    if args.payload_file:
        payloads = load_payloads_from_file(args.payload_file)
        if not payloads:
            logging.warning("No payloads loaded from file. Using default payloads.")
            payloads = FUZZ_PAYLOADS #Fallback to default payloads.
    else:
        payloads = FUZZ_PAYLOADS


    # Start fuzzing
    fuzz_websocket(args.url, args.num_requests, args.delay, payloads, args.timeout, args.origin)


if __name__ == "__main__":
    main()