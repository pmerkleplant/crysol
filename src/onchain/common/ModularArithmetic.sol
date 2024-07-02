/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

/**
 * @title ModularArithmetic
 *
 * @notice Provides modular arithmetic functionality
 *
 * @custom:references
 *      - [Dubois 2023]: https://eprint.iacr.org/2023/939.pdf
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library ModularArithmetic {
    /// @dev Computes the modular inverse of `x` mod `prime`.
    ///
    ///      The modular inverse of `x` is x⁻¹ such that
    ///      x * x⁻¹ ≡ 1 (mod prime).
    ///
    /// @dev Note that `prime` MUST be a prime number!
    ///
    /// @dev Reverts if:
    ///        x not in [1, prime)
    ///
    /// @dev Uses modular exponentiation based on Fermat's little theorem.
    function computeInverse(uint x, uint prime) internal view returns (uint) {
        if (x == 0) {
            revert("ModularInverseOfZeroDoesNotExist()");
        }
        if (x >= prime) {
            revert("ModularInverseOfXGreaterThanPrime()");
        }

        // Note that while modular inversion is usually performed using the
        // extended Euclidean algorithm this function uses modular
        // exponentiation based on Fermat's little theorem from which follows:
        //  ∀ p ∊ Uint: ∀ x ∊ [1, p): p.isPrime() → xᵖ⁻² ≡ x⁻¹ (mod p)
        //
        // Note that modular exponentiation can be efficiently computed via the
        // `modexp` precompile. Due to the precompile's price structure the
        // expected gas usage is lower than using the extended Euclidean
        // algorithm.
        //
        // For further details, see [Dubois 2023].
        return computeExponentiation(x, addmod(0, prime - 2, prime), prime);
    }

    /// @dev Computes base^{exponent} mod `prime`.
    ///
    /// @dev Note that `prime` MUST be a prime number!
    ///
    /// @dev Uses the `modexp` precompile.
    function computeExponentiation(uint base, uint exponent, uint prime)
        internal
        view
        returns (uint)
    {
        // Payload to compute base^{exponent} (mod prime).
        // Note that the size of each argument is 32 bytes.
        bytes memory payload = abi.encode(32, 32, 32, base, exponent, prime);

        // The `modexp` precompile is at address 0x05.
        address target = address(5);

        ( /*bool ok*/ , bytes memory result) = target.staticcall(payload);
        // assert(ok); // Precompile calls do not fail.

        // Note that abi.decode() reverts if result is empty.
        // Result is empty iff the modexp computation failed due to insufficient
        // gas.
        return abi.decode(result, (uint));
    }
}
