# app.py
import os
import io
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
CORS(app) # Enable CORS for all routes, allowing frontend from different origin

# --- Helper Functions for Encryption/Decryption ---

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a cryptographic key from a password using PBKDF2HMAC.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # For Fernet, key must be 32 bytes
        salt=salt,
        iterations=100000, # Recommended number of iterations
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# --- Helper Functions for Steganography (LSB) ---

def bytes_to_binary_string(data: bytes) -> str:
    """Converts bytes to a binary string (e.g., b'A' -> '01000001')."""
    return ''.join(f'{byte:08b}' for byte in data)

def binary_string_to_bytes(binary_str: str) -> bytes:
    """Converts a binary string back to bytes."""
    byte_array = bytearray()
    for i in range(0, len(binary_str), 8):
        byte_array.append(int(binary_str[i:i+8], 2))
    return bytes(byte_array)

def hide_message(image: Image.Image, message_bytes: bytes) -> Image.Image:
    """
    Hides a message (as bytes) within the least significant bits of an image.
    The message length is embedded first, followed by the message itself.
    """
    # Convert message bytes to binary string
    message_binary = bytes_to_binary_string(message_bytes)

    # Prepend message length (as 32-bit binary string)
    # Max message length is 2^32 - 1. This is a very large number, so it should be sufficient.
    message_len_binary = f'{len(message_binary):032b}' # 32 bits for length
    full_binary_data = message_len_binary + message_binary

    if len(full_binary_data) > image.width * image.height * 3: # 3 channels (RGB)
        raise ValueError("Message is too large to hide in the image.")

    img_data = list(image.getdata())
    new_img_data = []
    data_index = 0

    for pixel in img_data:
        new_pixel = list(pixel)
        for i in range(3): # Iterate through R, G, B channels
            if data_index < len(full_binary_data):
                # Replace LSB with a bit from the message
                new_pixel[i] = (new_pixel[i] & 0xFE) | int(full_binary_data[data_index])
                data_index += 1
            else:
                break # No more data to hide
        new_img_data.append(tuple(new_pixel))
        if data_index >= len(full_binary_data):
            break # All data hidden, can append remaining pixels as is

    # Append remaining original pixels if any
    new_img_data.extend(img_data[len(new_img_data):])

    new_image = Image.new(image.mode, image.size)
    new_image.putdata(new_img_data)
    return new_image

def reveal_message(image: Image.Image) -> bytes:
    """
    Extracts a hidden message (as bytes) from the least significant bits of an image.
    Assumes the first 32 bits store the message length.
    """
    img_data = list(image.getdata())
    extracted_bits = ""
    bits_needed_for_length = 32

    # Extract bits for message length
    for pixel in img_data:
        for i in range(3): # R, G, B channels
            extracted_bits += str(pixel[i] & 1) # Get LSB
            if len(extracted_bits) == bits_needed_for_length:
                break
        if len(extracted_bits) == bits_needed_for_length:
            break

    if len(extracted_bits) < bits_needed_for_length:
        raise ValueError("Not enough data to extract message length. Image may not contain a hidden message.")

    message_len_bits = extracted_bits[:bits_needed_for_length]
    message_binary_len = int(message_len_bits, 2)

    # Extract actual message bits
    message_bits_start_index = bits_needed_for_length
    total_bits_to_extract = bits_needed_for_length + message_binary_len

    extracted_message_bits = ""
    data_index = bits_needed_for_length # Start after length bits

    for pixel in img_data:
        for i in range(3):
            if data_index < total_bits_to_extract:
                extracted_message_bits += str(pixel[i] & 1)
                data_index += 1
            else:
                break
        if data_index >= total_bits_to_extract:
            break

    if len(extracted_message_bits) < message_binary_len:
        raise ValueError("Incomplete message extracted. Image might be corrupted or key is wrong.")

    # Convert binary string back to bytes
    return binary_string_to_bytes(extracted_message_bits)

# --- API Endpoints ---

@app.route('/encode', methods=['POST'])
def encode():
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400
    if 'message' not in request.form:
        return jsonify({'error': 'No message provided'}), 400
    if 'key' not in request.form:
        return jsonify({'error': 'No encryption key provided'}), 400

    image_file = request.files['image']
    message = request.form['message']
    user_key = request.form['key']

    try:
        # Use a consistent salt for key derivation for this demo.
        # In a real-world app, for better security, the salt should be unique per encryption
        # and stored/transmitted with the ciphertext (e.g., prepended to the encrypted message).
        # For steganography, embedding the salt before the encrypted message in LSBs
        # would be the robust approach.
        salt = b'a_fixed_salt_for_steganography_demo' # IMPORTANT: Use a truly random, unique salt in production!

        # Derive Fernet key from user's password
        fernet_key = derive_key(user_key, salt)
        f = Fernet(fernet_key)

        # Encrypt the message
        encrypted_message = f.encrypt(message.encode('utf-8'))

        # Open the image
        img = Image.open(io.BytesIO(image_file.read())).convert("RGB")

        # Hide the encrypted message in the image
        stego_image = hide_message(img, encrypted_message)

        # Save the steganographic image to a BytesIO object
        img_byte_arr = io.BytesIO()
        stego_image.save(img_byte_arr, format='PNG') # PNG is lossless, good for steganography
        img_byte_arr.seek(0)

        # Encode the image to base64 for sending back to frontend
        encoded_image_b64 = base64.b64encode(img_byte_arr.read()).decode('utf-8')

        return jsonify({'encoded_image': encoded_image_b64}), 200

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.error(f"Error during encoding: {e}")
        return jsonify({'error': 'An unexpected error occurred during encoding.'}), 500

@app.route('/decode', methods=['POST'])
def decode():
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400
    if 'key' not in request.form:
        return jsonify({'error': 'No encryption key provided'}), 400

    image_file = request.files['image']
    user_key = request.form['key']

    try:
        # Use the same salt as used for encoding to derive the key
        salt = b'a_fixed_salt_for_steganography_demo' # Must match the encoding salt

        # Derive Fernet key from user's password
        fernet_key = derive_key(user_key, salt)
        f = Fernet(fernet_key)

        # Open the steganographic image
        img = Image.open(io.BytesIO(image_file.read())).convert("RGB")

        # Reveal the encrypted message from the image
        encrypted_message_extracted = reveal_message(img)

        # Decrypt the message
        decoded_message = f.decrypt(encrypted_message_extracted).decode('utf-8')

        return jsonify({'decoded_message': decoded_message}), 200

    except ValueError as e:
        # This can catch errors like "Not enough data to extract message length"
        # or "Incomplete message extracted" from reveal_message,
        # or "Message is not padded" from Fernet decryption if key is wrong.
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.error(f"Error during decoding: {e}")
        # Catch Fernet.InvalidToken for incorrect keys
        if "InvalidToken" in str(e):
            return jsonify({'error': 'Invalid encryption key or corrupted message.'}), 400
        return jsonify({'error': 'An unexpected error occurred during decoding.'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))
