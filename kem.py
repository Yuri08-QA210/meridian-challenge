import os
import random
import time


# ============================================================
# MERIDIAN - Custom LWE-based Key Encapsulation Mechanism
# ============================================================
# Parameters:
#   n  = 40       (lattice dimension)
#   q  = 12289    (prime modulus)
#   eta = 1       (error bound: coefficients in {-1, 0, 1})
#   hw  = 20      (Hamming weight of secret)
# ============================================================

N = 40
Q = 12289
ETA = 1
HW = 20  # Hamming weight of binary secret vector


def mod_q(x):
    """Reduce x modulo q into [0, q)."""
    return x % Q


def center_mod_q(x):
    """Reduce x modulo q into (-q/2, q/2]."""
    x = x % Q
    if x > Q // 2:
        x -= Q
    return x


def random_matrix(n, q):
    """Generate a random n x n matrix modulo q."""
    return [[random.randrange(q) for _ in range(n)] for _ in range(n)]


def random_small_vector(n, eta=1):
    """Generate a random vector with coefficients in {-eta, ..., 0, ..., eta}."""
    return [random.randint(-eta, eta) for _ in range(n)]


def random_binary_vector(n, hw):
    """Generate a random binary vector with exactly hw ones."""
    v = [0] * n
    positions = random.sample(range(n), hw)
    for p in positions:
        v[p] = 1
    return v


def mat_vec_mul(A, v, q):
    """Multiply n x n matrix A by n-vector v, modulo q."""
    n = len(v)
    result = [0] * n
    for i in range(n):
        s = 0
        for j in range(n):
            s += A[i][j] * v[j]
        result[i] = s % q
    return result


def vec_dot_mod(a, b, q):
    """Dot product of two vectors modulo q."""
    return sum(ai * bi for ai, bi in zip(a, b)) % q


class MeridianKEM:
    """Custom LWE-based Key Encapsulation Mechanism."""

    def __init__(self):
        self.n = N
        self.q = Q
        self.eta = ETA
        self.hw = HW

        # Key generation
        self.s = None        # Private key (binary vector)
        self.A = None        # Public matrix
        self.b = None        # Public vector
        self.pk = None       # Public key (A, b)
        self._keygen()

    def _keygen(self):
        """Generate a new keypair."""
        self.s = random_binary_vector(self.n, self.hw)
        self.A = random_matrix(self.n, self.q)
        e = random_small_vector(self.n, self.eta)

        # b = A * s + e mod q
        self.b = mat_vec_mul(self.A, self.s, self.q)
        self.b = [(self.b[i] + e[i]) % self.q for i in range(self.n)]

        self.pk = (self.A, self.b)

        print(f"[MERIDIAN] Key generated. Secret Hamming weight: {sum(self.s)}")

    def get_public_key(self):
        """Return the public key."""
        return {
            "A": self.A,
            "b": self.b,
            "n": self.n,
            "q": self.q
        }

    def encapsulate(self, message_bit):
        """
        Encapsulate a message bit using the public key.

        Returns ciphertext (u, v) where:
          u = A^T * r + e1 mod q
          v = b^T * r + e2 + message_bit * (q//2) mod q
        """
        A, b = self.pk
        r = random_binary_vector(self.n, self.hw)
        e1 = random_small_vector(self.n, self.eta)
        e2 = random.randint(-self.eta, self.eta)

        # u = A^T * r + e1 mod q
        u = [0] * self.n
        for i in range(self.n):
            s = 0
            for j in range(self.n):
                s += A[j][i] * r[j]  # A^T[i][j] = A[j][i]
            u[i] = (s + e1[i]) % self.q

        # v = b^T * r + e2 + m * (q//2) mod q
        v = (vec_dot_mod(b, r, self.q) + e2 + message_bit * (self.q // 2)) % self.q

        return u, v

    def _norm_check(self, u):
        """
        Ciphertext norm validation for lattice decoding safety.

        Computes an approximate squared norm of the ciphertext projected
        onto the secret key subspace. This prevents malformed ciphertexts
        from causing decoding errors in the center-reduction step.

        NOTE: The iterative precision safeguard in this function creates
        a timing dependency on the secret key and input vector. This is
        a known implementation issue that will be addressed in a future
        constant-time rewrite.
        """
        norm_sq = 0
        for i in range(self.n):
            if self.s[i] == 1:
                c = u[i]

                # Precision safeguard: iterative accumulation prevents
                # floating-point errors in the norm estimation.
                # The number of accumulation rounds is proportional to
                # the coefficient magnitude, ensuring sufficient precision
                # for large values.
                rounds = c // 50 + 1
                accum = 0
                for _ in range(rounds):
                    accum = (accum + c) % (2**31 - 1)

                norm_sq += accum

        return norm_sq < (self.q ** 2) * self.n // 4

    def decapsulate(self, u, v):
        """
        Decapsulate a ciphertext (u, v) to recover the message bit.

        Computes: w = v - s^T * u mod q
        Decodes: if |w| < q/4, then m=0; else m=1

        Returns (message_bit, processing_time_microseconds).

        WARNING: This implementation is NOT constant-time!
        See _norm_check() for the timing side-channel details.
        """
        t_start = time.perf_counter_ns()

        # Step 1: Compute inner product s^T * u
        dot = 0
        for i in range(self.n):
            if self.s[i] == 1:
                dot += u[i]
        dot = dot % self.q

        # Step 2: Ciphertext validity check (has timing side-channel!)
        self._norm_check(u)

        # Step 3: Compute w = v - dot mod q
        w = (v - dot) % self.q

        # Step 4: Center and decode
        w_centered = center_mod_q(w)

        t_end = time.perf_counter_ns()
        processing_time_us = (t_end - t_start) / 1000  # microseconds

        # Decode: |w_centered| < q/4 => m=0, else m=1
        if abs(w_centered) < self.q // 4:
            message_bit = 0
        else:
            message_bit = 1

        return message_bit, processing_time_us

    def decapsulate_with_key(self, u, v, secret_key):
        """
        Decapsulate using a provided secret key (for verification after recovery).
        This is a constant-time implementation for comparison purposes.
        """
        dot = 0
        for i in range(self.n):
            dot += secret_key[i] * u[i]
        dot = dot % self.q
        w = (v - dot) % self.q
        w_centered = center_mod_q(w)
        if abs(w_centered) < self.q // 4:
            return 0
        else:
            return 1
