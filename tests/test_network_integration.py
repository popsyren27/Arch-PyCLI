import time
import unittest

from core.network import DistributedNode
from core.security import SEC_KERNEL
from core.loader import KERNEL_LOADER


class NetworkIntegrationTests(unittest.TestCase):
    def test_local_send_and_auth(self):
        # Ensure plugins are loaded
        KERNEL_LOADER.bootstrap()

        node = DistributedNode(host='127.0.0.1', port=0)
        node.start_node()

        # wait for server socket to be ready
        deadline = time.time() + 1.0
        while time.time() < deadline:
            if getattr(node, '_server_sock', None) is not None:
                break
            time.sleep(0.01)
        self.assertIsNotNone(getattr(node, '_server_sock', None), "Server socket not initialized")

        actual_port = node._server_sock.getsockname()[1]

        # generate a short-lived token and attempt an echo command
        token = SEC_KERNEL.generate_short_lived_token(node.node_id)
        resp = node.send_remote_cmd('127.0.0.1', actual_port, token, 'echo integration_test')

        # Response should include the echoed text
        self.assertIn('integration_test', str(resp))

        # Clean up
        node.stop()


if __name__ == '__main__':
    unittest.main()
