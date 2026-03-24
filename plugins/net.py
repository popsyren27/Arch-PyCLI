import logging
import socket
import threading
import uuid
from core.security import SEC_KERNEL
from core.network import NETWORK_NODE


def execute(context, *args):
    """
    Network Controller Plugin.
    Usage: 
      net auth                - Generates a 15-minute access token.
      net send [ip] [port] [token] [command] - Sends a secure command to a node.
    """
    if not args:
        raise ValueError("ERR_USAGE: net [auth | send]")

    subcommand = args[0].lower()

    if subcommand == "auth":
        # Generate a short-lived token (default 15 minutes)
        token = SEC_KERNEL.generate_short_lived_token(NETWORK_NODE.node_id)
        logging.info("Generated short-lived token for node %s", NETWORK_NODE.node_id)
        return f"ACCESS_TOKEN: {token}\nVALID_FOR: 900 seconds"

    if subcommand == "send":
        # Support optional async flag: net send -a [ip] [port] [token] [command]
        async_mode = False
        idx = 1
        if len(args) > 1 and args[1] in ("-a", "--async"):
            async_mode = True
            idx = 2

        if len(args) <= idx + 3:
            raise ValueError("ERR_USAGE: net send [-a] [ip] [port] [token] [command]")

        target_ip = args[idx]
        try:
            target_port = int(args[idx + 1])
        except Exception:
            raise ValueError("ERR_INVALID_PORT")
        if not (1 <= target_port <= 65535):
            raise ValueError("ERR_PORT_OUT_OF_RANGE")

        remote_token = args[idx + 2]
        remote_cmd = " ".join(args[idx + 3:])

        # Basic input limits
        if len(remote_token) > 1024:
            raise ValueError("ERR_INVALID_TOKEN")
        if len(remote_cmd) > 10000:
            raise ValueError("ERR_COMMAND_TOO_LARGE")

        # Basic host validation: ensure host string is not absurdly large
        if not isinstance(target_ip, str) or len(target_ip) > 255:
            raise ValueError("ERR_INVALID_HOST")

        logging.info("Preparing to send remote command to %s:%s (async=%s)", target_ip, target_port, async_mode)

        def _do_send():
            try:
                resp = NETWORK_NODE.send_remote_cmd(target_ip, target_port, remote_token, remote_cmd)
                logging.info("Remote send result to %s:%s -> %s", target_ip, target_port, resp)
            except Exception:
                logging.exception("Failed to send remote command to %s:%s", target_ip, target_port)

        if async_mode:
            job_id = str(uuid.uuid4())
            t = threading.Thread(target=_do_send, daemon=True)
            t.start()
            return f"JOB_SCHEDULED: {job_id}"

        # synchronous send (may block up to network timeouts)
        try:
            response = NETWORK_NODE.send_remote_cmd(target_ip, target_port, remote_token, remote_cmd)
            # avoid returning huge payloads
            if isinstance(response, str) and len(response) > 20000:
                return "REMOTE_RESPONSE_TOO_LARGE"
            return f"REMOTE_RESPONSE: {response}"
        except Exception as e:
            logging.exception("Remote command failed")
            return f"REMOTE_ERROR: {e}"

    raise ValueError(f"ERR_UNKNOWN_NET_SUBCOMMAND: {subcommand}")