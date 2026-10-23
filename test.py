from cryptography.fernet import InvalidToken

from encryption import decrypt_file, encrypt_file


def run_tests():
    original_filename = "secret_report.pdf"
    original_file_data = b"%PDF-1.4 Mock sensitive document content \x00\xff\xfe"
    correct_password = "CorrectHorseBatteryStaple123!"
    wrong_password = "WrongPassword456!"

    print("Running encryption...")
    encrypted_data = encrypt_file(
        original_file_data, original_filename, correct_password
    )

    # 1. Successful Encryption & Decryption
    print("\n[Test 1] Testing successful roundtrip decryption...")
    decrypted_filename, decrypted_data = decrypt_file(encrypted_data, correct_password)
    assert decrypted_filename == original_filename, "Filename does not match original"
    assert decrypted_data == original_file_data, "File data does not match original"
    print("PASS: Decrypted filename and content matched original.")

    # 2. Decrypt with Wrong Password
    print("\n[Test 2] Testing incorrect password rejection...")
    try:
        decrypt_file(encrypted_data, wrong_password)
        raise AssertionError("Expected InvalidToken was not raised!")
    except InvalidToken:
        print("PASS: Successfully caught InvalidToken for incorrect password.")

    # 3. Malformed Encrypted Data Cases
    print("\n[Test 3] Testing malformed/truncated data scenarios...")

    # Case A: Missing or invalid magic prefix
    bad_header_data = b"BEEF" + encrypted_data[4:]
    try:
        decrypt_file(bad_header_data, correct_password)
        raise AssertionError("Failed to catch invalid header")
    except ValueError:
        print("  PASS: Caught invalid header prefix.")

    # Case B: Truncated salt/payload
    truncated_data = encrypted_data[:12]
    try:
        decrypt_file(truncated_data, correct_password)
        raise AssertionError("Failed to catch truncated header/salt")
    except ValueError:
        print("  PASS: Caught truncated file structure.")

    # Case C: Valid header & salt, but empty ciphertext
    no_ciphertext = encrypted_data[:20]
    try:
        decrypt_file(no_ciphertext, correct_password)
        raise AssertionError("Failed to catch missing ciphertext")
    except ValueError:
        print("  PASS: Caught missing ciphertext.")

    # Case D: Corrupted ciphertext bytes
    corrupted_ciphertext = bytearray(encrypted_data)
    corrupted_ciphertext[-1] ^= 0xFF
    try:
        decrypt_file(bytes(corrupted_ciphertext), correct_password)
        raise AssertionError("Failed to catch corrupted ciphertext")
    except InvalidToken:
        print("  PASS: Caught corrupted ciphertext tampering.")

    print("\nAll assertions passed successfully!")


if __name__ == "__main__":
    run_tests()
