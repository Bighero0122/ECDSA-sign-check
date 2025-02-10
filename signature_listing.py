from ecdsa import VerifyingKey, BadSignatureError, SECP256k1
from itertools import combinations

def verify_signatures(public_keys, signatures, message):
    """
    Verify if at least 2/3 of the public keys have signed the message.

    Args:
        public_keys (list): List of public keys in hexadecimal format.
        signatures (list): List of ECDSA signatures in hexadecimal format.
        message (str): The message that was signed.

    Returns:
        bool: True if at least 2/3 of the public keys have signed the message, False otherwise.
    """
    required_signatures = (len(public_keys) * 2) // 3 + 1  # Calculate 2/3 threshold
    valid_signatures_count = 0

    for public_key_hex, signature_hex in zip(public_keys, signatures):
        try:
            # Convert public key from hex to VerifyingKey object
            vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
            # Convert signature from hex to bytes
            signature = bytes.fromhex(signature_hex)
            # Verify the signature
            if vk.verify(signature, message.encode()):
                valid_signatures_count += 1
                # Early exit if the required number of signatures is reached
                if valid_signatures_count >= required_signatures:
                    return True
        except BadSignatureError:
            continue

    return False

# Example usage
public_keys = [
    'your_public_key_1',
    'your_public_key_2',
    'your_public_key_3',
    # Add more public keys as needed
]

signatures = [
    'signature_1',
    'signature_2',
    'signature_3',
    # Add corresponding signatures
]

message = "Your message here"

result = verify_signatures(public_keys, signatures, message)
print("At least 2/3 of the keys have signed the message:", result)
