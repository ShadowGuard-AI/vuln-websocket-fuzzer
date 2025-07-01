# vuln-Websocket-Fuzzer
A command-line tool to fuzz WebSocket endpoints for common vulnerabilities such as command injection or denial-of-service by sending malformed or oversized messages. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowGuardAI/vuln-websocket-fuzzer`

## Usage
`./vuln-websocket-fuzzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-n`: Number of fuzz requests to send. Defaults to 10.
- `-d`: No description provided
- `-l`: File to save the logs to. If not specified, logs are printed to the console.
- `-v`: No description provided
- `-p`: No description provided
- `--timeout`: No description provided
- `--origin`: Sets the Origin header. Useful to check CORS bypass.

## License
Copyright (c) ShadowGuardAI
