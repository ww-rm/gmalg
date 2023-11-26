import secrets
from typing import Callable

from .core import ECDLP, EllipticCurveCipher
from .sm3 import SM3

__all__ = ["SM2"]


_p = bytes.fromhex("FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF")
_a = bytes.fromhex("FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC")
_b = bytes.fromhex("28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93")
_n = bytes.fromhex("FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123")
_xG = bytes.fromhex("32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7")
_yG = bytes.fromhex("BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0")


class SM2(EllipticCurveCipher):
    """SM2"""

    def __init__(self, d: bytes = None, xP: bytes = None, yP: bytes = None, id_: bytes = None, *,
                 rnd_fn: Callable[[int], int] = None) -> None:
        """SM2.

        Args:
            d (bytes): secret key.
            xP (bytes): x of public key.
            yP (bytes): y of public key.
            id_ (bytes): user id used in sign.

            rnd_fn ((int) -> int): random function used to generate k-bit random number, default to `secrets.randbits`
        """
        super().__init__(
            ECDLP(int.from_bytes(_p, "big"), int.from_bytes(_a, "big"), int.from_bytes(_b, "big"),
                  int.from_bytes(_n, "big"), int.from_bytes(_xG, "big"), int.from_bytes(_yG, "big")),
            SM3, rnd_fn or self._default_rnd_fn, d=d, xP=xP, yP=yP, id_=id_
        )

    def _default_rnd_fn(self, k: int) -> int:
        return secrets.randbits(k)
