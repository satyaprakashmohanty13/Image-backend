import cv2
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import struct
import logging

# Configure logging for better debugging in backend
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---

def bytes_to_binary_string(data):
    """Converts a byte string to its binary representation string."""
    return ''.join(format(byte, '08b') for byte in data)

def binary_string_to_bytes(binary_string):
    """Converts a binary representation string back to a byte string."""
    byte_array = bytearray()
    # Ensure the binary string is a multiple of 8 bits by padding with zeros if necessary
    padding_needed = (8 - len(binary_string) % 8) % 8
    binary_string += '0' * padding_needed

    for i in range(0, len(binary_string), 8):
        byte = int(binary_string[i:i+8], 2)
        byte_array.append(byte)
    return bytes(byte_array)

def generate_key(passphrase: str, salt: bytes):
    """Generates a Fernet key from a passphrase using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key

# --- Encoder Function ---

def embed_data_in_frame(frame, data_bits, current_bit_index):
    """
    Embeds data bits into the LSBs of a single video frame.
    Returns the modified frame, the new bit index, and a boolean indicating if embedding is complete.
    """
    height, width, _ = frame.shape
    frame_flat = frame.flatten()

    bits_embedded_in_frame = 0
    total_bits_to_embed = len(data_bits)

    for i in range(len(frame_flat)):
        if current_bit_index < total_bits_to_embed:
            pixel_val = frame_flat[i]
            bit_to_embed = int(data_bits[current_bit_index])
            frame_flat[i] = (pixel_val & 0xFE) | bit_to_embed
            current_bit_index += 1
            bits_embedded_in_frame += 1
        else:
            break

    modified_frame = frame_flat.reshape((height, width, 3))
    embedding_complete = (current_bit_index == total_bits_to_embed)
    return modified_frame, current_bit_index, embedding_complete

def video_steganography_encode(video_path, message, output_path, passphrase):
    """
    Encodes a message into a video file using LSB steganography and encryption.
    Returns True on success, False on failure.
    """
    logging.info(f"Starting encoding process for '{video_path}'...")

    try:
        # 1. Generate a salt and key for encryption
        salt = os.urandom(16)
        key = generate_key(passphrase, salt)
        f = Fernet(key)

        # 2. Encrypt the message
        encrypted_message = f.encrypt(message.encode('utf-8'))
        logging.info(f"Message encrypted. Encrypted length: {len(encrypted_message)} bytes.")

        # 3. Prepare data for embedding: salt + encrypted_message_length + encrypted_message
        encrypted_message_length = len(encrypted_message)
        length_bytes = struct.pack('!I', encrypted_message_length)

        data_to_embed_bytes = salt + length_bytes + encrypted_message
        data_to_embed_bits = bytes_to_binary_string(data_to_embed_bytes)
        logging.info(f"Total bits to embed (including salt and length): {len(data_to_embed_bits)}")

        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            logging.error(f"Error: Could not open video file '{video_path}'")
            return False

        fourcc = cv2.VideoWriter_fourcc(*'mp4v') # Codec for output video
        fps = cap.get(cv2.CAP_PROP_FPS)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

        max_bits_capacity = width * height * 3 * int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        logging.info(f"Video capacity: {max_bits_capacity} bits ({max_bits_capacity / 8 / 1024:.2f} KB)")

        if len(data_to_embed_bits) > max_bits_capacity:
            logging.error("Error: Message too large for video capacity.")
            cap.release()
            return False

        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
        if not out.isOpened():
            logging.error(f"Error: Could not create output video file '{output_path}'")
            cap.release()
            return False

        current_bit_index = 0
        frame_count = 0
        embedding_complete = False

        while cap.isOpened() and not embedding_complete:
            ret, frame = cap.read()
            if not ret:
                break

            frame_count += 1
            if current_bit_index < len(data_to_embed_bits):
                modified_frame, current_bit_index, embedding_complete = \
                    embed_data_in_frame(frame.copy(), data_to_embed_bits, current_bit_index)
                out.write(modified_frame)
            else:
                out.write(frame)

            if frame_count % 100 == 0:
                logging.info(f"Processed {frame_count} frames. Embedded {current_bit_index}/{len(data_to_embed_bits)} bits.")

        cap.release()
        out.release()
        cv2.destroyAllWindows()

        if embedding_complete:
            logging.info(f"Encoding successful! Stego video saved to '{output_path}'")
            return True
        else:
            logging.error("Error: Embedding did not complete. Video capacity might be too small or an issue occurred.")
            return False

    except Exception as e:
        logging.exception(f"An unexpected error occurred during encoding: {e}")
        return False

# --- Decoder Function ---

def video_steganography_decode(stego_video_path, passphrase):
    """
    Decodes a message from a steganographic video file.
    Returns the decrypted message string on success, None on failure.
    """
    logging.info(f"Starting decoding process for '{stego_video_path}'...")

    try:
        cap = cv2.VideoCapture(stego_video_path)
        if not cap.isOpened():
            logging.error(f"Error: Could not open video file '{stego_video_path}'")
            return None

        extracted_salt_bits = ""
        extracted_length_bits = ""
        extracted_message_bits = ""
        encrypted_message_length = 0
        salt_extracted = False
        length_extracted = False
        message_extracted = False

        frame_count = 0
        f = None # Fernet object

        while cap.isOpened() and not message_extracted:
            ret, frame = cap.read()
            if not ret:
                break

            frame_count += 1
            frame_flat = frame.flatten()

            # Phase 1: Extract Salt (16 bytes = 128 bits)
            if not salt_extracted:
                bits_to_get = 128 - len(extracted_salt_bits)
                if bits_to_get > 0:
                    for i in range(len(frame_flat)):
                        if len(extracted_salt_bits) < 128:
                            extracted_salt_bits += str(frame_flat[i] & 0x01)
                        else:
                            break
                    if len(extracted_salt_bits) == 128:
                        salt_extracted = True
                        logging.info("Salt extracted.")
                        salt = binary_string_to_bytes(extracted_salt_bits)
                        key = generate_key(passphrase, salt)
                        f = Fernet(key)

            # Phase 2: Extract Encrypted Message Length (4 bytes = 32 bits)
            if salt_extracted and not length_extracted:
                bits_to_get = 32 - len(extracted_length_bits)
                if bits_to_get > 0:
                    # Calculate the starting index in the current frame for length bits
                    # It's the remainder of salt bits already processed in this frame
                    start_index_in_frame = len(extracted_salt_bits) % frame.size
                    for i in range(start_index_in_frame, len(frame_flat)):
                        if len(extracted_length_bits) < 32:
                            extracted_length_bits += str(frame_flat[i] & 0x01)
                        else:
                            break
                    if len(extracted_length_bits) == 32:
                        length_extracted = True
                        length_bytes = binary_string_to_bytes(extracted_length_bits)
                        encrypted_message_length = struct.unpack('!I', length_bytes)[0]
                        logging.info(f"Encrypted message length extracted: {encrypted_message_length} bytes ({encrypted_message_length * 8} bits).")

            # Phase 3: Extract Encrypted Message
            if length_extracted and not message_extracted:
                bits_to_get = (encrypted_message_length * 8) - len(extracted_message_bits)
                if bits_to_get > 0:
                    total_preamble_bits = len(extracted_salt_bits) + len(extracted_length_bits)
                    current_frame_bit_capacity = frame.size # width * height * 3
                    
                    # Calculate the starting index for message extraction in the current frame
                    start_index_for_message_in_frame = total_preamble_bits % current_frame_bit_capacity
                    
                    for i in range(start_index_for_message_in_frame, len(frame_flat)):
                        if len(extracted_message_bits) < (encrypted_message_length * 8):
                            extracted_message_bits += str(frame_flat[i] & 0x01)
                        else:
                            break
                    
                    if len(extracted_message_bits) == (encrypted_message_length * 8):
                        message_extracted = True
                        logging.info("Encrypted message bits extracted.")

            if frame_count % 100 == 0:
                logging.info(f"Processed {frame_count} frames. Extracted {len(extracted_message_bits)}/{encrypted_message_length * 8} message bits.")

        cap.release()
        cv2.destroyAllWindows()

        if not message_extracted:
            logging.error("Error: Could not extract the complete message. Video might be corrupted or message was not fully embedded.")
            return None

        try:
            encrypted_message_bytes = binary_string_to_bytes(extracted_message_bits)
            if f is None:
                logging.error("Fernet object not initialized. Salt might not have been extracted.")
                return None
            decrypted_message = f.decrypt(encrypted_message_bytes).decode('utf-8')
            logging.info("Decoding successful!")
            return decrypted_message
        except Exception as e:
            logging.error(f"Error during decryption: {e}")
            logging.error("This could be due to an incorrect passphrase or corrupted data.")
            return None

    except Exception as e:
        logging.exception(f"An unexpected error occurred during decoding: {e}")
        return None

