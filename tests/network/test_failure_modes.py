from nucypher.utilities.sandbox.middleware import MockRestMiddleware
import socket


def test_bob_does_not_let_a_connection_error_stop_him(enacted_federated_policy, federated_ursulas, federated_bob, federated_alice):
    assert len(federated_bob.known_nodes) == 0
    ursula1 = list(federated_ursulas)[0]
    ursula2 = list(federated_ursulas)[1]

    federated_bob.remember_node(ursula1)

    class NodeIsDownMiddleware(MockRestMiddleware):
        def get_treasure_map_from_node(self, *args, **kwargs):
            raise socket.gaierror("llamas")

    federated_bob.network_middleware = NodeIsDownMiddleware()
    map = federated_bob.get_treasure_map(federated_alice.stamp, enacted_federated_policy.label)
