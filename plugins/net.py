import logging
from core.security import SEC_KERNEL
from core.network import NETWORK_NODE

def execute(context, *args):
    """
    Network Controller Plugin.
    Usage: 
      net auth                - Generates a 15-minute access token.
      net send [ip] [port] [token] [command] - Sends a secure command to a node.
    """
    assert len(args) > 0, "ERR_USAGE: net [auth | send]"
    
    subcommand = args[0].lower()

    if subcommand == "auth":
        # Generate a 15-minute short-lived token
        new_token = SEC_KERNEL.generate_short_lived_token(NETWORK_NODE.node_id)
        logging.info(f"Generated short-lived token: {new_token}")
        return f"ACCESS_TOKEN: {new_token}\nVALID_FOR: 900 seconds"

    if subcommand == "send":
        assert len(args) >= 5, "ERR_USAGE: net send [ip] [port] [token] [command]"
        target_ip = args[1]
        target_port = int(args[2])
        remote_token = args[3]
        remote_cmd = " ".join(args[4:])
        
        print(f"[*] Establishing encrypted tunnel to {target_ip}...")
        response = NETWORK_NODE.send_remote_cmd(target_ip, target_port, remote_token, remote_cmd)
        return f"REMOTE_RESPONSE: {response}"

    return "ERR_UNKNOWN_NET_SUBCOMMAND"