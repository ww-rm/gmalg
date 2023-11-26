import secrets
from typing import Callable

from .core import ECDLP, EllipticCurve, EllipticCurveCipher
from .sm3 import SM3

__all__ = ["SM2"]

_ec = EllipticCurve(
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF,
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFC,
    0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93,
)

_ecdlp = ECDLP(
    _ec,
    0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7,
    0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0,
    0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123,
)


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
        super().__init__(_ecdlp, SM3, rnd_fn or self._default_rnd_fn, d=d, xP=xP, yP=yP, id_=id_)

    def _default_rnd_fn(self, k: int) -> int:
        return secrets.randbits(k)
