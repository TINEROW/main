from __future__ import annotations

import pytest

from verifier_inputs import (
    BN254_SCALAR_FIELD_MODULUS,
    RejectCode,
    VerifierInputError,
    encode_field_to_bytes32_hex,
    encode_public_inputs,
)


def test_encode_field_accepts_decimal_and_hex_without_reduction() -> None:
    expected = "00" * 31 + "2a"
    assert encode_field_to_bytes32_hex("42") == expected
    assert encode_field_to_bytes32_hex("0x2a") == expected
    assert encode_field_to_bytes32_hex(42) == expected


def test_encode_public_inputs_preserves_order_and_field_names() -> None:
    assert encode_public_inputs(["1", "2"], ["first", "second"]) == (
        "00" * 31 + "01" + "00" * 31 + "02"
    )


@pytest.mark.parametrize("value", ["-1", str(BN254_SCALAR_FIELD_MODULUS), "0x" + "ff" * 32])
def test_encode_field_rejects_non_canonical_values(value: str) -> None:
    with pytest.raises(VerifierInputError) as error:
        encode_field_to_bytes32_hex(value, "witness")

    assert error.value.code is RejectCode.NON_CANONICAL_FIELD
    assert error.value.field == "witness"
    assert "ff" not in str(error.value)


def test_encode_field_rejects_malformed_values_without_echoing_input() -> None:
    with pytest.raises(VerifierInputError) as error:
        encode_field_to_bytes32_hex("not-a-field-secret", "witness")

    assert error.value.code is RejectCode.MALFORMED_HEX
    assert str(error.value) == "malformed_hex:witness"
