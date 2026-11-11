# vuln-Websocket-Fuzzer
A command-line tool to fuzz WebSocket endpoints for common vulnerabilities such as command injection or denial-of-service by sending malformed or oversized messages. Payloads are chosen at random from the built in set or from an operator supplied payload file, sent to the operator named endpoint, and responses are read back through the connection socket timeout and logged. Focused on assessing vulnerabilities in web applications by performing scans and providing detailed reports.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-websocket-fuzzer.git`

Requires websocket-client, see requirements.txt. If it is not installed, the tool reports that cleanly and exits non-zero (help still works).

## Usage
`python3 main.py ws://127.0.0.1:8000/ws -n 10`
`python3 main.py wss://example.com/ws -p payloads.txt --timeout 10 -l fuzz.log`

A payload file that cannot be read or loads no payloads exits non-zero; the default payloads are never silently substituted for a named file. An unwritable log file also exits non-zero. The timeout must be positive and applies to both the connection and later receives.

## Parameters
- `-h`: Show help message and exit
- `-n`: Number of fuzz requests to send. Defaults to 10.
- `-d`: Delay in seconds between requests. Defaults to 0.1.
- `-l`: File to save the logs to. If not specified, logs are printed to the console.
- `-v`: Enable verbose output (debug logging)
- `-p`: Path to a file containing payloads, one per line. Overrides the default payloads.
- `--timeout`: Timeout in seconds for the WebSocket connection. Defaults to 10.
- `--origin`: Sets the Origin header. Useful to check CORS bypass.

Exit codes: 0 only when the connection succeeded, payloads were sent, and the receive path read responses without every receive attempt erroring. A failed connection, or a run where no response could ever be read, exits non-zero and does not print a completion line. Invalid URL scheme, request count, delay, or timeout, a missing websocket-client install, an unreadable or empty payload file, or an unwritable log file also exit non-zero.

## License
MIT License, see LICENSE.
