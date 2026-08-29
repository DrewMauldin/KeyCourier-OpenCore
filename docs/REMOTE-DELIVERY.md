# Remote delivery protocol

KeyCourier's remote delivery path is a protocol boundary between the owner
application, an approved consumer and a host-local receiver. The receiver is
configured by the owner before a request is accepted; request metadata cannot
choose a host, command, identity, destination or reload action.

The flow is:

1. A consumer submits metadata-only request information.
2. The owner reviews and approves or denies that request.
3. The application encrypts the approved payload for the configured receiver.
4. The receiver validates signatures, expiry, replay state and its allowlist,
   then installs the value atomically for the selected consumer.
5. The receiver returns only a request identifier, selected identifiers, status
   and a content-free result code.

The receiver must keep private keys and plaintext on the configured host. It
must not accept shell commands or secret material on command-line arguments,
and it must never return credential contents to the consumer or language model.

Transport, storage and deployment details are product-specific. The public
source and protocol specifications are the authority for the validation and
cryptographic rules; deployment configuration remains an owner-reviewed gate.
