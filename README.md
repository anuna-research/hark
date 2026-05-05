# cbcl-lfe-router-client

This project defines a Rust CLI tool for communicating with the cbcl-lfe-router project.

The tool provides a convenient way to register with the router, advertise capabilities, send and receive WebSocket messages, and get feedback on CBCL message validity.

## Related projects

* cbcl-lfe-router - the capability-based router which this tool connects to
* cbcl-rs - a rust library for the CBCL language

## Features

### Connecting

Connect to the router, including any required authorisation/handshake procedures. This creates a persistent WebSocket connection.

Open question - does the router have/expect any kind of heartbeat mechanism?

### Capability advertisement

To know where to route messages, the router must know what capabilities a given agent has. The CLI determines capabilities from a config file (see below) and publishes them to the router.

### Allow agent to send messages

Agents can invoke the CLI with a CBCL message to be sent to the router. The CLI uses cbcl-rs to parse and check the message, either feeding issues back to the agent, or forwarding the message to the router if it's valid.

### Allow agent to receive messages

The CLI provides a command which blocks until a message is received, at which point it prints to STDOUT and exits. This allows easy interfacing with different agent harnesses.

### Agent skill definition

The repository comes along with a markdown skill definition file covering the usage of the CLI tool. It defers to the CLI's in-built help where possible to make the system more robust to CLI interface changes over time. (Look into best practices for authoring skills).

## Configuration

Configuration uses the rust `config` library and `dirs` to get standard locations across platforms.

Config values include:

* Router address
* Agent capabilities

## Open questions

Does the router have a concept of persistent agent 'identity'/'state'? As in - does it make sense to have agents consuming/producing single one-off messages, or is a more long term 'conversation' of messages the expected model? I suppose part of the question here is - is there a concept of a 'chain' of messages in reply to each other, and if so, are there guarantees that replies are routed back to the agent that produced the message being replied to?

Related to that - let's say we have messages representing 'please complete task X' and 'task X complete'. Is there any sense in which the 'same' agent that receives the first message should also be the one to send the 'complete' message? Or would it be acceptable to do say: WSS connection established, agent receives 'please complete task X', WSS connection closed. Agent completes task. Agent opens new WSS connection to send 'task X complete' message. Does that create any confusion/issues, having those messages happen in different sessions?

Would the ideal here be to have a single persistent WSS connection (e.g. a local server) then have commands for waiting on a message from that server, sendng a message to that server, all of which are relayed via the persistent WSS connection? Or is it fine to create/drop WSS connections as needed?

If a persistent connection/local server is preferred, how should CLI invocations (for say blocking until a message is received, sending a message) communicate with the local server? UNIX sockets? What's a reliable cross-platform option here?
