from nkms.crypto import default_algorithm
from nkms.crypto import symmetric_from_algorithm
from nkms.crypto import pre_from_algorithm
from nkms import crypto


def test_symmetric():
    Cipher = symmetric_from_algorithm(default_algorithm)
    key = crypto.random(Cipher.KEY_SIZE)
    cipher = Cipher(key)
    data = b'Hello world' * 10

    edata = cipher.encrypt(data)
    assert edata != data
    assert cipher.decrypt(edata) == data


def test_pre_rekey_with_private_and_public():
    pre = pre_from_algorithm(default_algorithm)

    sk_alice = b'a' * 32
    sk_bob = b'b' * 32

    pk_alice = pre.priv2pub(sk_alice)
    pk_bob = pre.priv2pub(sk_bob)

    cleartext = b'Hello world'

    cyphertext_for_alice = pre.encrypt(pk_alice, cleartext)
    assert pre.decrypt(sk_alice, cyphertext_for_alice) == cleartext  # Alice can read her message.
    assert pre.decrypt(sk_bob, cyphertext_for_alice) != cleartext  # But Bob can't!

    # Now we make a re-encryption key from Alice to Bob
    rk_alice_bob = pre.rekey(sk_alice, pk_bob)
    # Use the key on Alice's cyphertext...
    cyphertext_for_bob = pre.reencrypt(rk_alice_bob, cyphertext_for_alice)
    # ...and sure enough, Bob can read it!
    assert pre.decrypt(sk_bob, cyphertext_for_bob) == cleartext


def test_pre_rekey_with_private_and_ephemeral():
    """
    Demonstration of Chapter II, Section A, paragraph 2, lines 10-15 of whitepaper
    """
    cleartext = "A Mr. Death or something - he's come about the reaping."
    pre = pre_from_algorithm(default_algorithm)
    key_length = 32

    sk_alice = b'a' * key_length
    pk_alice = pre.priv2pub(sk_alice)

    sk_bob = b'b' * 32
    pk_bob = pre.priv2pub(sk_bob)

    sk_ephemeral = crypto.random(key_length)
    pk_ephemeral = pre.priv2pub(sk_ephemeral)

    rk_alice_to_ephemeral = pre.rekey(sk_alice, sk_ephemeral)

    sk_ephemeral_encrypted = pre.encrypt(pk_bob, sk_ephemeral)

    rk_alice_to_bob = pre.rekey(rk_alice_to_ephemeral, sk_ephemeral_encrypted)

    # re-encryption node activity

    cyphertext_for_alice = pre.encrypt(pk_alice, cleartext)
    cyphertext_ephemeral = pre.reencrypt(rk_alice_to_ephemeral, cyphertext_for_alice)
    cyphertext_for_bob = pre.reencrypt(cyphertext_ephemeral, sk_ephemeral_encrypted)

    # decryption by bob
    bob_possession_sk_ephemeral_encrypted = pre.decrypt(pk_ephemeral, sk_bob, )
