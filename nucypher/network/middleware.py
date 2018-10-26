import os
import socket
import ssl
import time

import requests
from bytestring_splitter import BytestringSplitter, VariableLengthBytestring
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from twisted.logger import Logger
from umbral.fragments import CapsuleFrag
from umbral.signing import Signature

from nucypher.config.keyring import _write_tls_certificate


class RestMiddleware:
    log = Logger()

    def consider_arrangement(self, arrangement):
        node = arrangement.ursula
        response = requests.post("https://{}/consider_arrangement".format(node.rest_interface),
                                 bytes(arrangement),
                                 verify=node.certificate_filepath)

        if not response.status_code == 200:
            raise RuntimeError("Bad response: {}".format(response.content))
        return response

    def learn_about_seednode(self, seednode_metadata, known_certs_dir, timeout=3, accept_federated_only=False):
        from nucypher.characters.lawful import Ursula
        # Pre-fetch certificate
        self.log.info("Fetching seednode {} TLS certificate".format(seednode_metadata.checksum_address))

        # TODO: Utilize timeout.
        certificate, filepath = self._get_certificate(checksum_address=seednode_metadata.checksum_address,
                                                      hostname=seednode_metadata.rest_host,
                                                      port=seednode_metadata.rest_port,
                                                      certs_dir=known_certs_dir,
                                                      timeout=timeout)

        if certificate is False:
            return False

        potential_seed_node = Ursula.from_rest_url(self,
                                                   seednode_metadata.rest_host,
                                                   seednode_metadata.rest_port,
                                                   certificate_filepath=filepath,
                                                   federated_only=True)  # TODO: 466

        if not seednode_metadata.checksum_address == potential_seed_node.checksum_public_address:
            raise potential_seed_node.SuspiciousActivity(
                "This seed node has a different wallet address: {} (was hoping for {}).  Are you sure this is a seed node?".format(
                    potential_seed_node.checksum_public_address,
                    seednode_metadata.checksum_address))
        try:
            potential_seed_node.verify_node(self,
                                            accept_federated_only=accept_federated_only,
                                            certificate_filepath=filepath)
        except potential_seed_node.InvalidNode:
            raise  # TODO: What if our seed node fails verification?

        return potential_seed_node

    def _get_certificate(self, checksum_address, certs_dir, hostname, port,
                         timeout=3, retry_attempts: int = 3, retry_rate: int = 2, ):
        socket.setdefaulttimeout(timeout)  # Set Socket Timeout
        current_attempt = 0
        try:
            seednode_certificate = ssl.get_server_certificate(addr=(hostname, port))
        except socket.timeout:
            if current_attempt == retry_attempts:
                message = "No Response from seednode {} after {} attempts"
                self.log.info(message.format(checksum_address, retry_attempts))
                return False, False
            self.log.info(
                "No Response from seednode {}. Retrying in {} seconds...".format(checksum_address, retry_rate))
            time.sleep(retry_rate)

        certificate = x509.load_pem_x509_certificate(seednode_certificate.encode(),
                                                     backend=default_backend())
        # Write certificate
        filename = '{}.{}'.format(checksum_address, Encoding.PEM.name.lower())
        certificate_filepath = os.path.join(certs_dir, filename)
        _write_tls_certificate(certificate=certificate, full_filepath=certificate_filepath, force=True)
        self.log.info("Saved seednode {} TLS certificate".format(checksum_address))
        return certificate, certificate_filepath

    def enact_policy(self, ursula, id, payload):
        response = requests.post('https://{}/kFrag/{}'.format(ursula.rest_interface, id.hex()), payload,
                                 verify=ursula.certificate_filepath)
        if not response.status_code == 200:
            raise RuntimeError("Bad response: {}".format(response.content))
        return True, ursula.stamp.as_umbral_pubkey()

    def reencrypt(self, work_order):
        ursula_rest_response = self.send_work_order_payload_to_ursula(work_order)
        cfrags_and_signatures = BytestringSplitter((CapsuleFrag, VariableLengthBytestring), Signature).repeat(
            ursula_rest_response.content)
        cfrags = work_order.complete(
            cfrags_and_signatures)  # TODO: We'll do verification of Ursula's signature here.  #141
        return cfrags

    def get_competitive_rate(self):
        return NotImplemented

    def get_treasure_map_from_node(self, node, map_id):
        endpoint = "https://{}/treasure_map/{}".format(node.rest_interface, map_id)
        response = requests.get(endpoint, verify=node.certificate_filepath)
        return response

    def put_treasure_map_on_node(self, node, map_id, map_payload):
        endpoint = "https://{}/treasure_map/{}".format(node.rest_interface, map_id)
        response = requests.post(endpoint, data=map_payload, verify=node.certificate_filepath)
        return response

    def send_work_order_payload_to_ursula(self, work_order):
        payload = work_order.static_payload()
        id_as_hex = work_order.arrangement_id.hex()
        endpoint = 'https://{}/kFrag/{}/reencrypt'.format(work_order.ursula.rest_interface, id_as_hex)
        return requests.post(endpoint, payload, verify=work_order.ursula.certificate_filepath)

    def node_information(self, host, port, certificate_filepath):
        endpoint = "https://{}:{}/public_information".format(host, port)
        return requests.get(endpoint, verify=certificate_filepath)

    def get_nodes_via_rest(self,
                           url,
                           certificate_filepath,
                           announce_nodes=None,
                           nodes_i_need=None):
        if nodes_i_need:
            # TODO: This needs to actually do something.
            # Include node_ids in the request; if the teacher node doesn't know about the
            # nodes matching these ids, then it will ask other nodes.
            pass

        if announce_nodes:
            payload = bytes().join(bytes(n) for n in announce_nodes)
            response = requests.post("https://{}/node_metadata".format(url),
                                     verify=certificate_filepath,
                                     data=payload)
        else:
            response = requests.get("https://{}/node_metadata".format(url),
                                    verify=certificate_filepath)
        return response
