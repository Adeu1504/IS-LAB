# 1. Implement the hash function in Python. Your function should start with an initial hash
# value of 5381 and for each character in the input string, multiply the current hash value
# by 33, add the ASCII value of the character, and use bitwise operations to ensure
# thorough mixing of the bits. Finally, ensure the hash value is kept within a 32-bit range
# by applying an appropriate mask

def custom_hash_djb2(input_string: str) -> int:
    """
    Computes a 32-bit hash of a string using the djb2 algorithm.

    This function starts with an initial hash value of 5381. For each
    character in the input string, it updates the hash using the formula:
    hash = ((hash << 5) + hash) + ascii_value_of_char
    This is equivalent to: hash = (hash * 33) + ascii_value_of_char.

    A bitwise AND with 0xFFFFFFFF is applied in each step to ensure the
    hash value remains within a 32-bit unsigned integer range.

    Args:
        input_string: The string to be hashed.

    Returns:
        A 32-bit integer representing the hash of the input string.
    """
    # 1. Start with an initial hash value of 5381
    hash_val = 5381

    # 5. Define the 32-bit mask
    mask = 0xFFFFFFFF

    # 2. For each character in the input string...
    for char in input_string:
        # 3. Multiply by 33, add ASCII value, and use bitwise operations
        # The expression ((hash_val << 5) + hash_val) is a fast,
        # bitwise way to compute (hash_val * 32 + hash_val), which is hash_val * 33.
        # ord(char) gets the ASCII value of the character.
        hash_val = ((hash_val << 5) + hash_val) + ord(char)

        # 4. Ensure the hash value is kept within a 32-bit range
        # The bitwise AND operator applies the mask, effectively keeping
        # only the lower 32 bits of the number.
        hash_val &= mask

    return hash_val


# --- Example Usage ---
if __name__ == "__main__":
    test_strings = [
        "Hello World",
        "Python is fun!",
        "This is a test of the custom hash function.",
        "djb2 algorithm",
        "",  # Test with an empty string
        "a"  # Test with a single character
    ]

    print("--- Testing the custom_hash_djb2 function ---")
    for s in test_strings:
        hashed_value = custom_hash_djb2(s)
        # We print the result in both decimal and hexadecimal format
        print(f"Input: '{s}'")
        print(f"  - Hash (decimal): {hashed_value}")
        print(f"  - Hash (hex):     0x{hashed_value:08x}\n")