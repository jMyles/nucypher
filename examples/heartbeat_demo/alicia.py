from nucypher.characters.lawful import Bob, Ursula
from nucypher.config.characters import AliceConfiguration
from nucypher.config.storages import LocalFileBasedNodeStorage
from nucypher.crypto.powers import EncryptingPower, SigningPower
from nucypher.network.middleware import RestMiddleware
from nucypher.utilities.logging import simpleObserver

import datetime
import os
import shutil
import maya
import json
import sys
from twisted.logger import globalLogPublisher


POLICY_FILENAME = "policy-metadata.json"

######################
# Boring setup stuff #
######################
#
# # Twisted Logger
globalLogPublisher.addObserver(simpleObserver)
#
# # Temporary file storage
TEMP_ALICE_DIR = "{}/alicia-files".format(os.path.dirname(os.path.abspath(__file__)))
TEMP_URSULA_CERTIFICATE_DIR = "{}/ursula-certs".format(TEMP_ALICE_DIR)

# We expect the url of the seednode as the first argument.
SEEDNODE_URL = sys.argv[1]


#######################################
# Alicia, the Authority of the Policy #
#######################################


# We get a persistent Alice.
passphrase = "TEST_ALICIA_INSECURE_DEVELOPMENT_PASSWORD"
try:  # If we had an existing Alicia in disk, let's get it from there
    alice_config_file = os.path.join(TEMP_ALICE_DIR, "config_root", "alice.config")
    new_alice_config = AliceConfiguration.from_configuration_file(
            filepath=alice_config_file,
            network_middleware=RestMiddleware(),
            start_learning_now=False,
            save_metadata=False,
        )
    alicia = new_alice_config(passphrase=passphrase)
except:  # If anything fails, let's create Alicia from scratch
    # Remove previous demo files and create new ones
    shutil.rmtree(TEMP_ALICE_DIR, ignore_errors=True)
    os.mkdir(TEMP_ALICE_DIR)
    os.mkdir(TEMP_URSULA_CERTIFICATE_DIR)

    ursula = Ursula.from_seed_and_stake_info(host=SEEDNODE_URL,
                                             certificates_directory=TEMP_URSULA_CERTIFICATE_DIR,
                                             federated_only=True,
                                             minimum_stake=0)

    # Let's create an Alice from a Configuration.
    # This requires creating a local storage for her first.
    node_storage = LocalFileBasedNodeStorage(
        federated_only=True,
        character_class=Ursula,  # Alice needs to store some info about Ursula
        known_metadata_dir=os.path.join(TEMP_ALICE_DIR, "known_metadata"),
    )

    alice_config = AliceConfiguration(
        config_root=os.path.join(TEMP_ALICE_DIR, "config_root"),
        node_storage=node_storage,
        auto_initialize=True,
        auto_generate_keys=True,
        passphrase=passphrase,
        is_me=True,
        known_nodes={ursula},
        start_learning_now=False,
        federated_only=True,
        learn_on_same_thread=True,
    )
    alicia = alice_config(passphrase=passphrase,
                          known_certificates_dir=TEMP_URSULA_CERTIFICATE_DIR,
                          )

    # We will save Alicia's config to a file for later use
    alice_config_file = alice_config.to_configuration_file()

# Let's get to learn about the NuCypher network
alicia.start_learning_loop(now=True)

# At this point, Alicia is fully operational and can create policies.
# The Policy Label is a bytestring that categorizes the data that Alicia wants to share.
# Note: we add some random chars to create different policies, only for demonstration purposes
label = "heart-data-❤️-"+os.urandom(4).hex()
label = label.encode()

# Alicia can create the public key associated to the policy label,
# even before creating any associated policy.
policy_pubkey = alicia.get_policy_pubkey_from_label(label)

print("The policy public key for "
      "label '{}' is {}".format(label.decode("utf-8"), policy_pubkey.to_bytes().hex()))

# Data Sources can produce encrypted data for access policies
# that **don't exist yet**.
# In this example, we create a local file with encrypted data, containing
# heart rate measurements from a heart monitor
import heart_monitor
heart_monitor.generate_heart_rate_samples(policy_pubkey,
                                          label=label,
                                          save_as_file=True)


# Alicia now wants to share data associated with this label.
# To do so, she needs the public key of the recipient.
# In this example, we generate it on the fly (for demonstration purposes)
from doctor_keys import get_doctor_pubkeys
doctor_pubkeys = get_doctor_pubkeys()

powers_and_material = {
    EncryptingPower: doctor_pubkeys['enc'],
    SigningPower: doctor_pubkeys['sig']
}

# We create a view of the Bob who's going to be granted access.
doctor_strange = Bob.from_public_keys(powers_and_material=powers_and_material,
                                      federated_only=True)

# Here are our remaining Policy details, such as:
# - Policy duration
policy_end_datetime = maya.now() + datetime.timedelta(days=5)
# - m-out-of-n: This means Alicia splits the re-encryption key in 5 pieces and
#               she requires Bob to seek collaboration of at least 3 Ursulas
m, n = 3, 5


# With this information, Alicia creates a policy granting access to Bob.
# The policy is sent to the NuCypher network.
print("Creating access policy for the Doctor...")
policy = alicia.grant(bob=doctor_strange,
                      label=label,
                      m=m,
                      n=n,
                      expiration=policy_end_datetime)
print("Done!")

# For the demo, we need a way to share with Bob some additional info
# about the policy, so we store it in a JSON file
policy_info = {
    "policy_pubkey": policy.public_key.to_bytes().hex(),
    "alice_sig_pubkey": bytes(alicia.stamp).hex(),
    "label": label.decode("utf-8"),
}

filename = POLICY_FILENAME
with open(filename, 'w') as f:
    json.dump(policy_info, f)

