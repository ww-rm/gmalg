import secrets


class Random:
    def randbits(self, k: int) -> int:
        """Generates an int with k random bits."""

        raise NotImplementedError("Please implement randbits method.")


class SecretsRandom(Random):
    """Random object implemented by `secrets` module."""

    def randbits(self, k: int) -> int:
        return secrets.randbits(k)


class ConstRandom(Random):
    """Return a const number."""

    def __init__(self, n: int) -> None:
        self._n = n

    def randbits(self, k: int) -> int:
        return self._n
