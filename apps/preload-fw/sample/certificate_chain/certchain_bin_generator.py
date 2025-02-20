import hashlib
import sys
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Constants from the C code
CERT_CHAIN_SIZE = 0x1000  # Certificate chain size (4KB)
SHA256_HASH_LENGTH = 32   # SHA256 hash length (32 bytes)
CERT_INFO_MAGIC_NUM = 0x43455254  # Magic number ('CERT' in hex)
ECDSA384_PUBLIC_KEY_SIZE = 48 * 2 + 1  # 97 bytes for uncompressed public key

# Certificate type enum
CERT_TYPE = 0
PUBLICKEY_TYPE = 1
ECC_PRIVATEKEY_TYPE = 2
CERT_REQ_TYPE = 3
LAST_CERT_TYPE = 4


def extract_public_key_xy(pem_file_path, verbose=False):
    """
    Extracts the uncompressed x and y coordinates from an ECDSA public key.
    Adds the uncompressed prefix 0x04.
    """
    if verbose:
        print(f"Loading public key from PEM file: {pem_file_path}")

    with open(pem_file_path, "rb") as pem_file:
        pem_data = pem_file.read()

    # Load the public key from PEM
    public_key = serialization.load_pem_public_key(pem_data)

    # Ensure it's an ECDSA P-384 key
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or \
       not isinstance(public_key.curve, ec.SECP384R1):
        raise ValueError("The key is not an ECDSA P-384 public key.")

    # Get the public numbers (x and y coordinates)
    public_numbers = public_key.public_numbers()
    x = public_numbers.x
    y = public_numbers.y

    # Convert x and y to bytes (48 bytes each for P-384)
    x_bytes = x.to_bytes(48, byteorder='big')
    y_bytes = y.to_bytes(48, byteorder='big')

    # Include the 0x04 prefix byte for uncompressed key
    prefix_byte = b'\x04'

    # Combine the prefix with x and y
    xy_bytes = prefix_byte + x_bytes + y_bytes

    if verbose:
        print("Extracted public key (x, y):")
        print(f"x (48 bytes): {x_bytes.hex()}")
        print(f"y (48 bytes): {y_bytes.hex()}")
        print(f"Uncompressed public key (x + y) length: {len(xy_bytes)}")
        print(f"Uncompressed public key (x + y): {xy_bytes.hex()}")

    return xy_bytes


def calculate_sha256(data, verbose=False):
    """
    Calculates the SHA-256 hash of the input data.
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    hash_result = sha256_hash.digest()

    if verbose:
        print(f"SHA-256 hash of certificate chain {hash_result.hex()}")

    return hash_result


def pack_certificate_chain(certchain_file, pubkey_file, output_file,
                           cert_type=CERT_TYPE, verbose=False):
    """
    Packs the certificate chain and public key into a binary format with the
    structure described.
    """
    # Read certificate chain file (DER format)
    if verbose:
        print(f"Reading certificate chain from file: {certchain_file}")

    with open(certchain_file, "rb") as cert_file:
        cert_data = cert_file.read()

    # Get the public key x and y components in uncompressed format
    pubkey_bytes = extract_public_key_xy(pubkey_file, verbose)

    # Calculate the hash of the certificate chain
    cert_hash = calculate_sha256(cert_data, verbose)

    # Prepare the structure fields
    magic = CERT_INFO_MAGIC_NUM
    length = len(cert_data)
    data = cert_data
    hash_field = cert_hash
    pubkey = pubkey_bytes
    cert_type_byte = cert_type.to_bytes(1, byteorder='little')

    # Create the binary data structure
    binary_data = (
        magic.to_bytes(4, byteorder='little') +
        length.to_bytes(4, byteorder='little') +
        # Fill the cert data to CERT_CHAIN_SIZE (padded with zeros)
        data.ljust(CERT_CHAIN_SIZE, b'\x00') +
        hash_field +
        pubkey +
        cert_type_byte
    )

    # Write the packed structure to output file
    if verbose:
        print(f"Writing packed data to file: {output_file}")

    with open(output_file, "wb") as out_file:
        out_file.write(binary_data)

    print(f"Packed data written to '{output_file}'.")


if __name__ == "__main__":
    verbose = False

    if len(sys.argv) < 4:
        print("Usage: python3 certchain_bin_generator.py <certchain.der> <dev_id_pubkey.pem> <output.bin> [--verbose]")
        sys.exit(1)

    # Check if verbose flag is passed
    if '--verbose' in sys.argv:
        verbose = True

    certchain_file = sys.argv[1]
    pubkey_file = sys.argv[2]
    output_file = sys.argv[3]

    if verbose:
        print("Verbose mode enabled.")

    # Validate input files
    if not os.path.exists(certchain_file):
        print(f"Error: Certificate chain file '{certchain_file}' not found.")
        sys.exit(1)
    if not os.path.exists(pubkey_file):
        print(f"Error: Public key file '{pubkey_file}' not found.")
        sys.exit(1)

    # Pack the certificate chain and public key into the binary structure
    pack_certificate_chain(certchain_file, pubkey_file, output_file,
                           cert_type=CERT_TYPE, verbose=verbose)
