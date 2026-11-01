# vuln-Websocket-Fuzzer
A command-line tool to fuzz WebSocket endpoints for common vulnerabilities such as command injection or denial-of-service by sending malformed or oversized messages. Payloads are chosen at random from the built in set or from an operator supplied payload file, sent to the operator named endpoint, and responses are read back through the connection socket timeout and logged. Focused on assessing vulnerabilities in web applications by performing scans and providing detailed reports.

## Install
`git clone https://github.com/ShadowGuardAI/vuln-websocket-fuzzer`

## Usage
`./vuln-websocket-fuzzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-n`: Number of fuzz requests to send. Defaults to 10.
- `-d`: Delay in seconds between requests. Defaults to 0.1.
- `-l`: File to save the logs to. If not specified, logs are printed to the console.
- `-v`: Enable verbose output (debug logging)
- `-p`: Path to a file containing payloads, one per line. Overrides the default payloads.
- `--timeout`: Timeout in seconds for the WebSocket connection. Defaults to 10.
- `--origin`: Sets the Origin header. Useful to check CORS bypass.

Exit codes: 0 only when the connection succeeded, payloads were sent, and the receive path read responses without every receive attempt erroring. A failed connection, or a run where no response could ever be read, exits non-zero and does not print a completion line. Invalid URL scheme, request count, or delay also exit non-zero.

## License
Copyright (c) ShadowGuardAI
