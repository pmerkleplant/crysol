/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

/**
 * @notice Point is a secp256k1 point in affine coordinates
 *
 * @dev The point at infinity is represented via:
 *          x = y = type(uint).max
 */
struct Point {
    uint x;
    uint y;
}

/**
 * @notice ProjectivePoint is a secp256k1 point in projective coordinates
 *
 * @dev A projective point represents an affine point (x, y) as (X, Y, Z)
 *      satisfying the following equations:
 *          x = X / Z²
 *          y = Y / Z³
 */
struct ProjectivePoint {
    uint x;
    uint y;
    uint z;
}

/**
 * @title Secp256k1Arithmetic
 *
 * @notice Provides common arithmetic-related functionality for the secp256k1
 *         elliptic curve
 *
 * @custom:references
 *      - [SEC 2 v2]: https://www.secg.org/sec2-v2.pdf
 *      - [Yellow Paper]: TODO
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 * @author Inspired by Chronicle Protocol's Scribe (https://github.com/chronicleprotocol/scribe)
 */
library Secp256k1Arithmetic {
    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Optimization Constants

    uint private constant B3 = mulmod(B, 3, P);

    //--------------------------------------------------------------------------
    // Secp256k1 Constants
    //
    // Secp256k1 is a Koblitz curve specified as:
    //      y² ≡ x³ + ax + b (mod p)
    //
    // where:
    uint internal constant A = 0;
    uint internal constant B = 7;
    uint internal constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    /// @dev The generator G as Point.
    ///
    /// @dev Note that the generator is also called base point.
    function G() internal pure returns (Point memory) {
        // Gₓ = 79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798
        // Gᵧ = 483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8
        return Point(
            0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
            0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
        );
    }

    /// @dev The order of the group generated via G.
    uint internal constant Q =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Taken from [SEC 2 v2] section 2.4.1 "Recommended Parameters secp256k1".
    //--------------------------------------------------------------------------

    //--------------------------------------------------------------------------
    // Point

    /// @dev Returns the zero point.
    ///
    /// @dev Note that the zero point is invalid and this function only provided
    ///      for convenience.
    function ZeroPoint() internal pure returns (Point memory) {
        return Point(0, 0);
    }

    /// @dev Returns whether point `point` is the zero point.
    function isZeroPoint(Point memory point) internal pure returns (bool) {
        return (point.x | point.y) == 0;
    }

    /// @dev Returns the additive identity.
    ///
    /// @dev Note that the identity is represented via:
    ///         point.x = point.y = type(uint).max
    ///
    /// @dev Note that the identity is also called point at infinity.
    function Identity() internal pure returns (Point memory) {
        return Point(type(uint).max, type(uint).max);
    }

    /// @dev Returns whether point `point` is the identity.
    ///
    /// @dev Note that the identity is represented via:
    ///         point.x = point.y = type(uint).max
    ///
    /// @dev Note that the identity is also called point at infinity.
    function isIdentity(Point memory point) internal pure returns (bool) {
        return (point.x & point.y) == type(uint).max;
    }

    /// @dev Returns whether point `point` is on the curve.
    ///
    /// @dev Note that secp256k1 curve is specified as y² ≡ x³ + ax + b (mod p)
    ///      where:
    ///         a = 0
    ///         b = 7
    ///
    /// @dev Note that the identity is also on the curve.
    function isOnCurve(Point memory point) internal pure returns (bool) {
        if (point.isIdentity()) {
            return true;
        }

        uint left = mulmod(point.y, point.y, P);
        // Note that adding a * x can be waived as ∀ x: a * x = 0.
        uint right =
            addmod(mulmod(point.x, mulmod(point.x, point.x, P), P), B, P);

        return left == right;
    }

    /// @dev Returns the parity of point `point`'s y coordinate.
    ///
    /// @dev The value 0 represents an even y value and 1 represents an odd y
    ///      value.
    ///
    ///      See "Appendix F: Signing Transactions" in [Yellow Paper].
    function yParity(Point memory point) internal pure returns (uint) {
        return point.y & 1;
    }

    /// @dev Returns whether point `point` equals point `other`.
    function equals(Point memory point, Point memory other)
        internal
        pure
        returns (bool)
    {
        // TODO: (point.x ^ other.y) | (point.y ^ other.y) ?
        return (point.x == other.x) && (point.y == other.y);
    }

    //--------------------------------------------------------------------------
    // Projective Point

    /// @dev Returns whether point `point` is the identity.
    ///
    /// @dev Note that the identity is represented via:
    ///         point.x = 0, point.y = 1, point.z = 0
    ///
    /// @dev Note that the identity is also called point at infinity.
    function isIdentity(ProjectivePoint memory point)
        internal
        pure
        returns (bool)
    {
        return point.x == 0 && point.y == 1 && point.z == 0;
        // TODO: return point.y == 1 && (point.x | point.y) == 0;
    }

    //----------------------------------
    // Arithmetic

    // TODO: Add negate() function.

    // TODO: What about intoAdd()? Saves memory allocations...
    /// @dev Returns the sum of projective points `point` and `other` as new
    ///      projective point.
    ///
    /// @dev Assumes:
    ///      - Points are on curve
    function add(ProjectivePoint memory point, ProjectivePoint memory other)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        /*
        // Uses complete addition formula from Renes-Costello-Batina 2015.
        // See https://eprint.iacr.org/2015/1060.pdf Alg 1.

        if (point.isIdentity()) {
            return other;
        }
        if (other.isIdentity()) {
            return point;
        }

        // forgefmt: disable-start

        // Inputs: P = (x1, y1, z1), Q = (x2, y2, z2)
        uint x1 = point.x; uint x2 = other.x;
        uint y1 = point.y; uint y2 = other.y;
        uint z1 = point.z; uint z2 = other.z;

        // Output: P + Q = (x3, y3, z3)
        uint x3;
        uint y3;
        uint z3;

        // Constants used:
        // - B3 = mulmod(B, 3, P)

        // Variables:
        {
        uint t0; uint t1; uint t2; uint t3; uint t4; uint t5;

        // Alg:
        t0 = mulmod(x1, x2, P);
        t1 = mulmod(y1, y2, P);
        t2 = mulmod(z1, z2, P);
        t3 = addmod(x1, y1, P);
        t4 = mulmod(x2, y2, P); // step 5
        t3 = mulmod(t3, t4, P);
        t4 = addmod(t0, t1, P);
        t3 = addmod(t3, P - t4, P);
        t4 = addmod(x1, z1, P);
        t5 = addmod(x2, z2, P); // step 10
        t4 = mulmod(t4, t5, P);
        t5 = addmod(t0, t2, P);
        t4 = addmod(t4, P - t5, P);
        t5 = addmod(y1, z1, P);
        x3 = addmod(y2, z2, P); // step 15
        t5 = mulmod(t5, x3, P);
        x3 = addmod(t1, t2, P);
        t5 = addmod(t5, P - x3, P);
        z3 = mulmod(A, t4, P);
        x3 = mulmod(B3, t2, P); // step 20
        z3 = addmod(x3, z3, P);
        x3 = addmod(t1, P - z3, P);
        z3 = addmod(t1, z3, P);
        y3 = mulmod(x3, z3, P);
        t1 = addmod(t0, t0, P); // step 25
        t1 = addmod(t1, t0, P);
        t2 = mulmod(A, t2, P);
        t4 = mulmod(B3, t4, P);
        t1 = addmod(t1, t2, P);
        t2 = addmod(t0, P - t2, P); // step 30
        t2 = mulmod(A, t2, P);
        t4 = addmod(t4, t2, P);
        t0 = mulmod(t1, t4, P);
        y3 = addmod(y3, t0, P);
        t0 = mulmod(t5, t4, P); // step 35
        x3 = mulmod(t3, x3, P);
        x3 = addmod(x3, P - t0, P);
        t0 = mulmod(t3, t1, P);
        z3 = mulmod(t5, z3, P);
        z3 = addmod(z3, t0, P); // step 40
        }
        // forgefmt: disable-end

        return ProjectivePoint(x3, y3, z3);
        */

        // Uses complete addition formula from Renes-Costello-Batina 2015.
        // See https://eprint.iacr.org/2015/1060.pdf Alg 7.
        //
        // TODO: This implementation can be optimized.
        //       See for example https://github.com/RustCrypto/elliptic-curves/blob/master/k256/src/arithmetic/projective.rs#L96.

        // TODO: Can be removed... Should be?
        //if (point.isIdentity()) {
        //    return other;
        //}
        //if (other.isIdentity()) {
        //    return point;
        //}

        // forgefmt: disable-start

        // Inputs: P = (x1, y1, z1), Q = (x2, y2, z2)
        uint x1 = point.x; uint x2 = other.x;
        uint y1 = point.y; uint y2 = other.y;
        uint z1 = point.z; uint z2 = other.z;

        // Output: (x3, y3, z3) = P + Q
        uint x3;
        uint y3;
        uint z3;

        // Constants used:
        // - B3 = mulmod(B, 3, P)

        // Variables:
        uint t0; uint t1; uint t2; uint t3; uint t4;

        // Alg:
        // Note that x - y = x + (P - y) (mod P)
        t0 = mulmod(x1, x2, P); // Step 1
        t1 = mulmod(y1, y2, P);
        t2 = mulmod(z1, z2, P);
        t3 = addmod(x1, y1, P);
        t4 = addmod(x2, y2, P); // Step 5
        t3 = mulmod(t3, t4, P);
        t4 = addmod(t0, t1, P);
        unchecked { t3 = addmod(t3, P - t4, P); }
        t4 = addmod(y1, z1, P);
        x3 = addmod(y2, z2, P); // Step 10
        t4 = mulmod(t4, x3, P);
        x3 = addmod(t1, t2, P);
        unchecked { t4 = addmod(t4, P - x3, P); }
        x3 = addmod(x1, z1, P);
        y3 = addmod(x2, z2, P); // Step 15
        x3 = mulmod(x3, y3, P);
        y3 = addmod(t0, t2, P);
        unchecked { y3 = addmod(x3, P - y3, P); }
        x3 = addmod(t0, t0, P);
        t0 = addmod(x3, t0, P); // Step 20
        t2 = mulmod(B3, t2, P);
        z3 = addmod(t1, t2, P);
        unchecked { t1 = addmod(t1, P - t2, P); }
        y3 = mulmod(B3, y3, P);
        x3 = mulmod(t4, y3, P); // Step 25
        t2 = mulmod(t3, t1, P);
        unchecked { x3 = addmod(t2, P - x3, P); }
        y3 = mulmod(y3, t0, P);
        t1 = mulmod(t1, z3, P);
        y3 = addmod(t1, y3, P); // Step 30
        t0 = mulmod(t0, t3, P);
        z3 = mulmod(z3, t4, P);
        z3 = addmod(z3, t0, P);
        // forgefmt: disable-end

        return ProjectivePoint(x3, y3, z3);
    }

    /// @dev Returns the product of projective point `point` and scalar `scalar`.
    ///
    /// @dev Assumes:
    ///      - Points are on curve
    function mul(ProjectivePoint memory point, uint scalar)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        // TODO: Should revert if scalar not in [0, Q)?

        // Catch multiplication with identity or scalar of zero.
        if (point.isIdentity() || scalar == 0) {
            // TODO: Need Identity()(ProjectivePoint) function.
            return ProjectivePoint(0, 1, 0);
        }

        ProjectivePoint memory copy = point;
        ProjectivePoint memory product = ProjectivePoint(0, 0, 0);

        while (scalar != 0) {
            if (scalar & 1 == 1) {
                product = product.add(copy);
            }
            scalar >>= 1; // Divide by 2.
            copy = copy.add(copy);
        }

        return product;
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Point

    /// @dev Returns point `point` as projective point.
    function toProjectivePoint(Point memory point)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        // TODO: Comment about projective identity representation.
        return point.isIdentity()
            ? ProjectivePoint(0, 1, 0)
            : ProjectivePoint(point.x, point.y, 1);
    }

    //----------------------------------
    // Projective Point

    /// @dev Mutates projective point `point` to affine point.
    function intoPoint(ProjectivePoint memory point)
        internal
        pure
        returns (Point memory)
    {
        if (point.isIdentity()) {
            return Identity();
        }

        // Compute z⁻¹, i.e. the modular inverse of point.z.
        uint zInv = modularInverseOf(point.z);

        // Compute (z⁻¹)² (mod p)
        uint zInv_2 = mulmod(zInv, zInv, P);

        // Compute point.x * (z⁻¹)² (mod p), i.e. the x coordinate of given
        // projective point in affine representation.
        uint x = mulmod(point.x, zInv_2, P);

        // Compute point.y * (z⁻¹)³ (mod p), i.e. the y coordinate of given
        // projective point in affine representation.
        uint y = mulmod(point.y, mulmod(zInv, zInv_2, P), P);

        // Store x and y in point.
        assembly ("memory-safe") {
            mstore(point, x)
            mstore(add(point, 0x20), y)
        }

        // Return as Point(point.x, point.y).
        // Note that from this moment point.z is dirty memory!
        Point memory p;
        assembly ("memory-safe") {
            p := point
        }
        return p;
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns the modular inverse of `x` for modulo `P`.
    ///
    ///      The modular inverse of `x` is x⁻¹ such that x * x⁻¹ ≡ 1 (mod P).
    ///
    /// @dev Reverts if:
    ///      - x not in [1, P)
    ///
    /// @dev Uses the Extended Euclidean Algorithm.
    ///
    /// @custom:invariant Terminates in finite time.
    function modularInverseOf(uint x) internal pure returns (uint) {
        // TODO: Refactor to use Fermats Little Theorem.
        //       While generally less performant due to the modexp precompile
        //       pricing its less cheaper in EVM context.
        //       For more info, see page 4 in "Speeding up Elliptic Curve Computations for Ethereum Account Abstraction".

        if (x == 0) {
            revert("Modular inverse of zero does not exist");
        }
        if (x >= P) {
            revert("NotAFieldElement(x)");
        }

        uint t;
        uint q;
        uint newT = 1;
        uint r = P;

        assembly ("memory-safe") {
            // Implemented in assembly to circumvent division-by-zero
            // and over-/underflow protection.
            //
            // Functionally equivalent Solidity code:
            //      while (x != 0) {
            //          q = r / x;
            //          (t, newT) = (newT, addmod(t, (P - mulmod(q, newT, P)), P));
            //          (r, x) = (x, r - (q * x));
            //      }
            //
            // For the division r / x, x is guaranteed to not be zero via the
            // loop condition.
            //
            // The subtraction of form P - mulmod(_, _, P) is guaranteed to not
            // underflow due to the subtrahend being a (mod P) result,
            // i.e. the subtrahend being guaranteed to be less than P.
            //
            // The subterm q * x is guaranteed to not overflow because
            // q * x ≤ r due to q = ⎣r / x⎦.
            //
            // The term r - (q * x) is guaranteed to not underflow because
            // q * x ≤ r and therefore r - (q * x) ≥ 0.
            for {} x {} {
                q := div(r, x)

                let tmp := t
                t := newT
                newT := addmod(tmp, sub(P, mulmod(q, newT, P)), P)

                tmp := r
                r := x
                x := sub(tmp, mul(q, x))
            }
        }

        return t;
    }

    /// @dev Returns whether `xInv` is the modular inverse of `x`.
    ///
    /// @dev Note that there is no modular inverse for zero.
    ///
    /// @dev Reverts if:
    ///      - x not in [0, P)
    ///      - xInv not in [0, P)
    function areModularInverse(uint x, uint xInv)
        internal
        pure
        returns (bool)
    {
        if (x >= P) {
            revert("NotAFieldElement(x)");
        }
        if (xInv >= P) {
            revert("NotAFieldElement(xInv)");
        }

        return mulmod(x, xInv, P) == 1;
    }
}
