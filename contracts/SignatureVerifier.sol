// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract SignatureVerifier {
    function getMessageHash(address user, bytes32 nonce) public pure returns (bytes32) {
        // prosta wiadomość do podpisu (na początek)
        return keccak256(abi.encodePacked(user, nonce));
    }

    function getEthSignedMessageHash(bytes32 messageHash) public pure returns (bytes32) {
        // standard "Ethereum Signed Message"
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    }

    function recoverSigner(bytes32 ethSignedMessageHash, bytes memory signature) public pure returns (address) {
        require(signature.length == 65, "Bad signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        // MetaMask czasem daje v = 0/1, a Ethereum oczekuje 27/28
        if (v < 27) v += 27;

        require(v == 27 || v == 28, "Bad v value");
        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    function verify(address expectedSigner, address user, bytes32 nonce, bytes memory signature) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(user, nonce);
        bytes32 ethHash = getEthSignedMessageHash(messageHash);
        address recovered = recoverSigner(ethHash, signature);
        return recovered == expectedSigner;
    }
}
