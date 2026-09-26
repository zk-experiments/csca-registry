//! brainpoolP512r1 (RFC 5639 §3.7) for ECDSA verification.
//!
//! RustCrypto ships `bp256`/`bp384` but no `bp512`. This module assembles the
//! curve exactly the way those crates do — `primefield` Montgomery field and
//! scalar types, `primeorder` short-Weierstrass arithmetic, `ecdsa` on top —
//! using the `crypto-bigint` backend (`monty_field_arithmetic!`) instead of
//! fiat-crypto output. Only the domain constants are local; they are checked
//! against the generated curve table in the tests, and every German, Finnish,
//! Swiss, Swedish, … CSCA signature in the fixtures exercises the verify path.
//!
//! Verification only: nothing here handles secret scalars.

#![allow(missing_debug_implementations)]

use elliptic_curve::hazmat::FieldArithmetic;
use elliptic_curve::{
    array::typenum::U64,
    bigint::{Odd, U512},
    CurveArithmetic, PrimeCurveArithmetic,
};
use primeorder::{mul_backend, point_arithmetic, PrimeCurveParams};

pub use self::field::FieldElement;
pub use self::scalar::Scalar;

const MODULUS_HEX: &str = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3";
const ORDER_HEX: &str = "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069";
const ORDER: Odd<U512> = Odd::<U512>::from_be_hex(ORDER_HEX);

/// brainpoolP512r1.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct BrainpoolP512r1;

impl elliptic_curve::Curve for BrainpoolP512r1 {
    type FieldBytesSize = U64;
    type Uint = U512;
    const ORDER: Odd<U512> = ORDER;
}

impl elliptic_curve::PrimeCurve for BrainpoolP512r1 {}

impl elliptic_curve::point::PointCompression for BrainpoolP512r1 {
    const COMPRESS_POINTS: bool = false;
}

impl ecdsa::EcdsaCurve for BrainpoolP512r1 {
    const NORMALIZE_S: bool = false;
}

mod field {
    use super::MODULUS_HEX;
    use elliptic_curve::{
        bigint::U512,
        ff::PrimeField,
        ops::BatchInvert,
        subtle::{Choice, ConstantTimeEq, CtOption},
    };

    // Multiplicative generators: the smallest quadratic non-residues (2 mod p,
    // 7 mod n), which is what `ff` needs for its 2-adic root of unity. Point
    // decompression is never used (COMPRESS_POINTS = false, uncompressed keys only).
    primefield::monty_field_params! {
        name: FieldParams,
        modulus: MODULUS_HEX,
        uint: U512,
        byte_order: primefield::ByteOrder::BigEndian,
        multiplicative_generator: 2,
        doc: "Montgomery parameters for brainpoolP512's field modulus"
    }

    primefield::monty_field_element! {
        name: FieldElement,
        params: FieldParams,
        uint: U512,
        doc: "Element of the brainpoolP512 base field"
    }

    primefield::monty_field_arithmetic! {
        name: FieldElement,
        params: FieldParams,
        uint: U512
    }

    impl BatchInvert for FieldElement {}
}

mod scalar {
    use super::{BrainpoolP512r1, ORDER, ORDER_HEX};
    use elliptic_curve::{
        bigint::U512,
        ff::PrimeField,
        scalar::{FromUintUnchecked, IsHigh},
        subtle::{Choice, ConstantTimeEq, ConstantTimeGreater, CtOption},
    };
    use primeorder::wnaf;

    primefield::monty_field_params! {
        name: ScalarParams,
        modulus: ORDER_HEX,
        uint: U512,
        byte_order: primefield::ByteOrder::BigEndian,
        multiplicative_generator: 7,
        doc: "Montgomery parameters for brainpoolP512's scalar modulus"
    }

    primefield::monty_field_element! {
        name: Scalar,
        params: ScalarParams,
        uint: U512,
        doc: "Element of the brainpoolP512 scalar field"
    }

    primefield::monty_field_arithmetic! {
        name: Scalar,
        params: ScalarParams,
        uint: U512
    }

    primefield::monty_field_reduce! {
        name: Scalar,
        params: ScalarParams,
        uint: U512,
    }

    elliptic_curve::scalar_impls!(BrainpoolP512r1, Scalar);
    wnaf::impl_wnaf_size_for_scalar!(Scalar);

    impl AsRef<Scalar> for Scalar {
        fn as_ref(&self) -> &Scalar {
            self
        }
    }

    impl FromUintUnchecked for Scalar {
        type Uint = U512;

        fn from_uint_unchecked(uint: Self::Uint) -> Self {
            Self::from_uint_unchecked(uint)
        }
    }

    impl IsHigh for Scalar {
        fn is_high(&self) -> Choice {
            const MODULUS_SHR1: U512 = ORDER.as_ref().shr_vartime(1);
            self.to_canonical().ct_gt(&MODULUS_SHR1)
        }
    }
}

/// Affine point.
pub type AffinePoint = primeorder::AffinePoint<BrainpoolP512r1>;
/// Projective point.
pub type ProjectivePoint = primeorder::ProjectivePoint<BrainpoolP512r1>;

impl CurveArithmetic for BrainpoolP512r1 {
    type AffinePoint = AffinePoint;
    type ProjectivePoint = ProjectivePoint;
    type Scalar = Scalar;
}

impl FieldArithmetic for BrainpoolP512r1 {
    type FieldElement = FieldElement;
}

impl PrimeCurveArithmetic for BrainpoolP512r1 {
    type CurveGroup = ProjectivePoint;
}

impl PrimeCurveParams for BrainpoolP512r1 {
    type PointArithmetic = point_arithmetic::EquationAIsGeneric;
    type Backend = mul_backend::VariableOnly;

    const EQUATION_A: FieldElement = FieldElement::from_hex_vartime(
        "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
    );
    const EQUATION_B: FieldElement = FieldElement::from_hex_vartime(
        "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
    );
    const GENERATOR: (FieldElement, FieldElement) = (
        FieldElement::from_hex_vartime(
            "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
        ),
        FieldElement::from_hex_vartime(
            "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::ff::PrimeField;
    use elliptic_curve::subtle::ConstantTimeEq;

    #[test]
    fn constants_match_curve_table() {
        let row = super::super::curves::NAMED
            .iter()
            .find(|r| r.0 == "brainpoolP512r1")
            .unwrap();
        assert_eq!(row.2, MODULUS_HEX);
        assert_eq!(row.7, ORDER_HEX);
        let hex = |f: FieldElement| hex::encode(f.to_repr());
        assert_eq!(hex(BrainpoolP512r1::EQUATION_A), row.3);
        assert_eq!(hex(BrainpoolP512r1::EQUATION_B), row.4);
        assert_eq!(hex(BrainpoolP512r1::GENERATOR.0), row.5);
        assert_eq!(hex(BrainpoolP512r1::GENERATOR.1), row.6);
    }

    #[test]
    fn generator_times_order_is_identity() {
        use elliptic_curve::group::Group;
        let g = ProjectivePoint::generator();
        let n_minus_1 = -Scalar::ONE;
        assert_eq!(g * n_minus_1 + g, ProjectivePoint::identity());
        assert!(bool::from((g * Scalar::from(2u64)).ct_eq(&g.double())));
    }
}
