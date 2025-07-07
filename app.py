import os
import uuid
from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from steganography_core import video_steganography_encode, video_steganography_decode
import logging

# Configure logging for Flask app
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Directory to temporarily store uploaded and processed files
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def home():
    return "Video Steganography Backend is running!"

@app.route('/encode', methods=['POST'])
def encode_video():
    logging.info("Received /encode request.")
    if 'video' not in request.files:
        return jsonify({"error": "No video file provided"}), 400
    if 'message' not in request.form:
        return jsonify({"error": "No message provided"}), 400
    if 'passphrase' not in request.form:
        return jsonify({"error": "No passphrase provided"}), 400

    video_file = request.files['video']
    message = request.form['message']
    passphrase = request.form['passphrase']

    if video_file.filename == '':
        return jsonify({"error": "No selected video file"}), 400

    # Generate unique filenames for temporary storage
    input_video_path = os.path.join(app.config['UPLOAD_FOLDER'], str(uuid.uuid4()) + "_" + video_file.filename)
    output_video_filename = str(uuid.uuid4()) + "_stego_" + video_file.filename
    output_video_path = os.path.join(app.config['UPLOAD_FOLDER'], output_video_filename)

    try:
        video_file.save(input_video_path)
        logging.info(f"Input video saved to: {input_video_path}")

        success = video_steganography_encode(input_video_path, message, output_video_path, passphrase)

        if success:
            logging.info(f"Sending stego video: {output_video_path}")
            return send_file(output_video_path, as_attachment=True, download_name=output_video_filename, mimetype='video/mp4')
        else:
            logging.error("Encoding failed.")
            return jsonify({"error": "Video encoding failed. Check server logs for details."}), 500
    except Exception as e:
        logging.exception("Error during encoding process:")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    finally:
        # Clean up temporary files
        if os.path.exists(input_video_path):
            os.remove(input_video_path)
            logging.info(f"Removed temporary input video: {input_video_path}")
        if os.path.exists(output_video_path):
            # The file might still be in use by send_file, but it will eventually be deleted by OS.
            # For production, consider a scheduled cleanup or a more robust file handling.
            pass # We rely on send_file to handle cleanup or let the OS eventually clean up.

@app.route('/decode', methods=['POST'])
def decode_video():
    logging.info("Received /decode request.")
    if 'video' not in request.files:
        return jsonify({"error": "No video file provided"}), 400
    if 'passphrase' not in request.form:
        return jsonify({"error": "No passphrase provided"}), 400

    video_file = request.files['video']
    passphrase = request.form['passphrase']

    if video_file.filename == '':
        return jsonify({"error": "No selected video file"}), 400

    input_video_path = os.path.join(app.config['UPLOAD_FOLDER'], str(uuid.uuid4()) + "_" + video_file.filename)

    try:
        video_file.save(input_video_path)
        logging.info(f"Input stego video saved to: {input_video_path}")

        decrypted_message = video_steganography_decode(input_video_path, passphrase)

        if decrypted_message is not None:
            logging.info("Decoding successful.")
            return jsonify({"message": decrypted_message}), 200
        else:
            logging.error("Decoding failed.")
            return jsonify({"error": "Video decoding failed. Check server logs for details, possibly incorrect passphrase or corrupted data."}), 500
    except Exception as e:
        logging.exception("Error during decoding process:")
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500
    finally:
        # Clean up temporary files
        if os.path.exists(input_video_path):
            os.remove(input_video_path)
            logging.info(f"Removed temporary input stego video: {input_video_path}")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))

