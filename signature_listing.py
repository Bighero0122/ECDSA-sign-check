from ecdsa import VerifyingKey, BadSignatureError, SECP256k1, SigningKey
from itertools import combinations

def verify_signatures(public_keys, signatures, message):
    """
    Verify if any >= 2/3 subset of the public keys have signed the message.

    Args:
        public_keys (list): List of public keys in hexadecimal format.
        signatures (list): List of ECDSA signatures in hexadecimal format.
        message (str): The message that was signed.

    Returns:
        bool: True if any >= 2/3 subset of public keys have valid signatures, False otherwise.
    """
    if len(public_keys) != len(signatures):
        return False

    threshold = (len(public_keys) * 2) // 3 + 1
    valid_pairs = []

    # First, identify all valid signature-pubkey pairs
    for i, (pub_key_hex, sig_hex) in enumerate(zip(public_keys, signatures)):
        try:
            vk = VerifyingKey.from_string(bytes.fromhex(pub_key_hex), curve=SECP256k1)
            signature = bytes.fromhex(sig_hex)
            if vk.verify(signature, message.encode()):
                valid_pairs.append(i)
        except (BadSignatureError, ValueError):
            continue

    # Check if we have enough valid signatures to potentially meet threshold
    if len(valid_pairs) < threshold:
        return False

    # For each possible subset size from threshold to total valid pairs
    for size in range(threshold, len(valid_pairs) + 1):
        # Check if any combination of this size is valid
        if len(list(combinations(valid_pairs, size))) > 0:
            return True

    return False

def generate_test_data(num_keys, message):
    """
    Generate test key pairs and signatures.
    
    Args:
        num_keys (int): Number of key pairs to generate
        message (str): Message to sign
        
    Returns:
        tuple: (public_keys, signatures, private_keys)
    """
    private_keys = []
    public_keys = []
    signatures = []
    
    for _ in range(num_keys):
        # Generate new key pair
        sk = SigningKey.generate(curve=SECP256k1)
        private_keys.append(sk.to_string().hex())
        
        # Get public key
        vk = sk.get_verifying_key()
        public_keys.append(vk.to_string().hex())
        
        # Sign message
        signature = sk.sign(message.encode())
        signatures.append(signature.hex())
    
    return public_keys, signatures, private_keys

# Test implementation
def run_test():
    message = "Hello, this is a test message!"
    num_keys = 5  # Using 5 keys to better demonstrate the threshold
    
    # Generate test data
    public_keys, signatures, private_keys = generate_test_data(num_keys, message)
    
    # Print generated key pairs
    print("\nGenerated Key Pairs and Signatures:")
    for i in range(num_keys):
        print(f"\nKey Pair {i+1}:")
        print(f"Private Key: {private_keys[i]}")
        print(f"Public Key:  {public_keys[i]}")
        print(f"Signature:   {signatures[i]}")
    
    print(f"\nTotal keys: {num_keys}")
    print(f"Required signatures (2/3): {(num_keys * 2) // 3 + 1}")
    
    # Test 1: All signatures valid
    print("\nTest 1: All signatures valid")
    result = verify_signatures(public_keys, signatures, message)
    print(f"Result (should be True): {result}")
    
    # Test 2: Exactly 2/3 valid signatures
    print("\nTest 2: Exactly 2/3 valid signatures")
    threshold = (num_keys * 2) // 3 + 1
    modified_signatures = signatures[:threshold] + ['00' * 70] * (num_keys - threshold)
    result = verify_signatures(public_keys, modified_signatures, message)
    print(f"Result (should be True): {result}")
    
    # Test 3: Less than 2/3 valid signatures
    print("\nTest 3: Less than 2/3 valid signatures")
    modified_signatures = signatures[:threshold-1] + ['00' * 70] * (num_keys - threshold + 1)
    result = verify_signatures(public_keys, modified_signatures, message)
    print(f"Result (should be False): {result}")

if __name__ == "__main__":
    run_test()
