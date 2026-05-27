import os

# Flag - set via environment variable
FLAG = os.environ.get("FLAG", "QA{r3d4ct3d}")

# KEM parameters
N = 40        # lattice dimension
Q = 12289     # prime modulus
ETA = 1       # error bound
HW = 20       # Hamming weight of secret

# Query limits per session
MAX_QUERIES_PER_SESSION = int(os.environ.get("MAX_QUERIES", "10000"))

# Server configuration
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "10001"))
