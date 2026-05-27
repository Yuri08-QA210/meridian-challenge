import os
import random
import time

N = 40
Q = 12289
ETA = 1
HW = 20


def mod_q(x):
    return x % Q


def center_mod_q(x):
    x = x % Q
    if x > Q // 2:
        x -= Q
    return x


def random_matrix(n, q):
    return [[random.randrange(q) for _ in range(n)] for _ in range(n)]


def random_small_vector(n, eta=1):
    return [random.randint(-eta, eta) for _ in range(n)]


def random_binary_vector(n, hw):
    v = [0] * n
    positions = random.sample(range(n), hw)
    for p in positions:
        v[p] = 1
    return v


def mat_vec_mul(A, v, q):
    n = len(v)
    result = [0] * n
    for i in range(n):
        s = 0
        for j in range(n):
            s += A[i][j] * v[j]
        result[i] = s % q
    return result


def vec_dot_mod(a, b, q):
    return sum(ai * bi for ai, bi in zip(a, b)) % q


class MeridianKEM:
    def __init__(self):
        self.n = N
        self.q = Q
        self.eta = ETA
        self.hw = HW
        self.s = None
        self.A = None
        self.b = None
        self.pk = None
        self._keygen()

    def _keygen(self):
        self.s = random_binary_vector(self.n, self.hw)
        self.A = random_matrix(self.n, self.q)
        e = random_small_vector(self.n, self.eta)
        self.b = mat_vec_mul(self.A, self.s, self.q)
        self.b = [(self.b[i] + e[i]) % self.q for i in range(self.n)]
        self.pk = (self.A, self.b)

    def get_public_key(self):
        return {
            "A": self.A,
            "b": self.b,
            "n": self.n,
            "q": self.q
        }

    def encapsulate(self, message_bit):
        A, b = self.pk
        r = random_binary_vector(self.n, self.hw)
        e1 = random_small_vector(self.n, self.eta)
        e2 = random.randint(-self.eta, self.eta)

        u = [0] * self.n
        for i in range(self.n):
            s = 0
            for j in range(self.n):
                s += A[j][i] * r[j]
            u[i] = (s + e1[i]) % self.q

        v = (vec_dot_mod(b, r, self.q) + e2 + message_bit * (self.q // 2)) % self.q
        return u, v

    def _validate_ciphertext(self, u):
        acc = 0
        for i in range(self.n):
            if self.s[i] == 1:
                c = u[i]
                steps = c // 50 + 1
                partial = 0
                for _ in range(steps):
                    partial = (partial + c) % (2**31 - 1)
                acc += partial
        return acc < (self.q ** 2) * self.n // 4

    def decapsulate(self, u, v):
        t_start = time.perf_counter_ns()

        dot = 0
        for i in range(self.n):
            if self.s[i] == 1:
                dot += u[i]
        dot = dot % self.q

        self._validate_ciphertext(u)

        w = (v - dot) % self.q
        w_centered = center_mod_q(w)

        t_end = time.perf_counter_ns()
        processing_time_us = (t_end - t_start) / 1000

        if abs(w_centered) < self.q // 4:
            message_bit = 0
        else:
            message_bit = 1

        return message_bit, processing_time_us

    def decapsulate_with_key(self, u, v, secret_key):
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