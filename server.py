import json
import uuid
import random
import time
from flask import Flask, jsonify, request, send_from_directory
from kem import MeridianKEM
from config import FLAG, N, Q, ETA, HW, MAX_QUERIES_PER_SESSION, HOST, PORT

app = Flask(__name__, static_folder="static", static_url_path="")

# Initialize KEM
kem = MeridianKEM()

# Encapsulate the flag as a sequence of bits
flag_bits = []
flag_ciphertexts = []
for ch in FLAG:
    byte_val = ord(ch)
    for bit_pos in range(8):
        bit = (byte_val >> bit_pos) & 1
        flag_bits.append(bit)
        u, v = kem.encapsulate(bit)
        flag_ciphertexts.append({"u": u, "v": v})

print(f"[MERIDIAN] Flag encapsulated: {len(FLAG)} bytes = {len(flag_bits)} bits = {len(flag_ciphertexts)} ciphertexts")

# Session management
sessions = {}  # session_id -> {"queries": int, "created": float}

# Cache the public key
public_key_data = kem.get_public_key()


def get_session_id():
    """Get or create a session ID."""
    sid = request.headers.get("X-Session-ID")
    if not sid:
        sid = request.args.get("session_id")
    if not sid:
        sid = str(uuid.uuid4())
    if sid not in sessions:
        sessions[sid] = {"queries": 0, "created": time.time()}
    return sid


def check_query_limit(sid):
    """Check if the session has exceeded the query limit."""
    session = sessions.get(sid, {"queries": 0, "created": time.time()})
    if session["queries"] >= MAX_QUERIES_PER_SESSION:
        return False
    session["queries"] += 1
    sessions[sid] = session
    return True


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/info")
def info():
    """Return challenge information."""
    return jsonify({
        "challenge": "MERIDIAN",
        "difficulty": "Insane",
        "description": "Custom LWE-based Key Encapsulation Mechanism with timing side-channel",
        "parameters": {
            "n": N,
            "q": Q,
            "eta": ETA,
            "hamming_weight": HW,
            "secret_type": "Binary vector with exactly HW ones",
            "public_key": "(A, b) where b = A*s + e mod q",
            "encapsulation": "u = A^T*r + e1, v = b^T*r + e2 + m*floor(q/2)",
            "decapsulation": "w = v - s^T*u mod q, decode |w| < q/4"
        },
        "flag_length_bytes": len(FLAG),
        "flag_bits": len(flag_bits),
        "num_ciphertexts": len(flag_ciphertexts),
        "max_queries_per_session": MAX_QUERIES_PER_SESSION,
        "timing_note": "The server reports internal processing time in microseconds for performance monitoring",
        "session_note": "Use X-Session-ID header to maintain your session across requests"
    })


@app.route("/api/public_key")
def public_key():
    """Return the public key (A, b)."""
    return jsonify({
        "A": public_key_data["A"],
        "b": public_key_data["b"],
        "n": public_key_data["n"],
        "q": public_key_data["q"]
    })


@app.route("/api/flag")
def get_flag():
    """Return the encapsulated flag ciphertexts."""
    return jsonify({
        "ciphertexts": flag_ciphertexts,
        "num_bits": len(flag_ciphertexts),
        "flag_length": len(FLAG)
    })


@app.route("/api/decapsulate", methods=["POST"])
def decapsulate():
    """
    Submit a ciphertext for decapsulation.
    Returns the decapsulated bit and server-side processing time.

    Body: {"u": [int, ...], "v": int}

    The processing_time_us field measures internal server processing
    time in microseconds, useful for performance monitoring and debugging.
    """
    sid = get_session_id()

    if not check_query_limit(sid):
        return jsonify({
            "error": "Query limit exceeded for this session",
            "queries_used": sessions[sid]["queries"],
            "max_queries": MAX_QUERIES_PER_SESSION,
            "hint": "Start a new session by using a different X-Session-ID"
        }), 429

    data = request.get_json()
    if not data:
        return jsonify({"error": "Provide JSON body with 'u' and 'v'"}), 400

    u = data.get("u")
    v = data.get("v")

    if u is None or v is None:
        return jsonify({"error": "Missing 'u' or 'v' in request body"}), 400

    if not isinstance(u, list) or len(u) != N:
        return jsonify({"error": f"'u' must be a list of {N} integers"}), 400

    if not isinstance(v, int):
        return jsonify({"error": "'v' must be an integer"}), 400

    # Validate ranges
    for i, ui in enumerate(u):
        if not isinstance(ui, int) or ui < 0 or ui >= Q:
            return jsonify({"error": f"u[{i}] must be an integer in [0, {Q-1}]"}), 400

    if v < 0 or v >= Q:
        return jsonify({"error": f"'v' must be an integer in [0, {Q-1}]"}), 400

    # Decapsulate and measure timing
    message_bit, proc_time_us = kem.decapsulate(u, v)

    # Add measurement noise (simulates real-world server jitter)
    # This noise is separate from the algorithmic timing and represents
    # OS scheduling, CPU frequency variation, etc.
    noise_us = random.gauss(0, 5)    # Gaussian noise sigma=5us
    jitter_us = random.uniform(-8, 8)  # Uniform jitter +/-8us

    total_time_us = proc_time_us + noise_us + jitter_us

    return jsonify({
        "bit": message_bit,
        "processing_time_us": round(total_time_us, 2),
        "session_id": sid,
        "queries_remaining": MAX_QUERIES_PER_SESSION - sessions[sid]["queries"]
    })


@app.route("/api/session", methods=["POST"])
def new_session():
    """Create a new session."""
    sid = str(uuid.uuid4())
    sessions[sid] = {"queries": 0, "created": time.time()}
    return jsonify({
        "session_id": sid,
        "max_queries": MAX_QUERIES_PER_SESSION
    })


@app.route("/api/session/status")
def session_status():
    """Check session status."""
    sid = get_session_id()
    session = sessions.get(sid, {"queries": 0, "created": time.time()})
    return jsonify({
        "session_id": sid,
        "queries_used": session["queries"],
        "queries_remaining": MAX_QUERIES_PER_SESSION - session["queries"],
        "max_queries": MAX_QUERIES_PER_SESSION
    })


if __name__ == "__main__":
    app.run(host=HOST, port=PORT, debug=False)
