// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/*
    KONTRAKT: SignatureVerifier

    Cel kontraktu:
    ----------------
    Kontrakt służy do weryfikacji podpisu kryptograficznego (ECDSA),
    który został wygenerowany poza blockchainem (off-chain).

    Kontrakt NIE:
    - nie przechowuje danych użytkowników
    - nie zapisuje stanu
    - nie zarządza kontami

    Kontrakt JEDYNIE:
    - sprawdza, czy podpis pochodzi od oczekiwanego adresu Ethereum
*/

contract SignatureVerifier {
    /*
        Funkcja: getMessageHash

        Tworzy skrót (hash) wiadomości, która ma zostać podpisana.
        W tym przypadku wiadomość składa się z:
        - adresu użytkownika
        - nonce (jednorazowej wartości)

        Dlaczego hash?
        - podpisywanie hasha jest tańsze i bezpieczniejsze
        - hash ma zawsze stałą długość (32 bajty)
    */

    function getMessageHash(
        address user,
        bytes32 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, nonce));
    }

    /*
        Funkcja: getEthSignedMessageHash

        Ethereum (MetaMask, ethers.js) nie podpisuje "gołego" hasha.
        Zawsze dodawany jest prefiks:
        "\x19Ethereum Signed Message:\n32"

        Dzięki temu podpis:
        - nie może zostać użyty jako podpis transakcji
        - jest jednoznacznie podpisem "wiadomości"
    */

    function getEthSignedMessageHash(
        bytes32 messageHash
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    messageHash
                )
            );
    }

    /*
        Funkcja: recoverSigner

        Z podpisu ECDSA odzyskujemy adres Ethereum, który go wygenerował.

        Podpis ECDSA składa się z trzech elementów:
        - r (32 bajty)
        - s (32 bajty)
        - v (1 bajt)

        Funkcja ecrecover pozwala "odtworzyć" adres publiczny
        na podstawie podpisu i podpisanej wiadomości.
    */

    function recoverSigner(
        bytes32 ethSignedMessageHash,
        bytes memory signature
    ) public pure returns (address) {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid v value");

        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    /*
        Funkcja: verify

        To jest GŁÓWNA funkcja kontraktu.

        Sprawdza, czy podpis:
        - został wygenerowany przez expectedSigner
        - dotyczy konkretnych danych (user + nonce)

        Zwraca:
        - true  -> podpis poprawny
        - false -> podpis nieprawidłowy
    */

    function verify(
        address expectedSigner,
        address user,
        bytes32 nonce,
        bytes memory signature
    ) public pure returns (bool) {
        bytes32 messageHash = getMessageHash(user, nonce);

        bytes32 ethHash = getEthSignedMessageHash(messageHash);

        address recoveredSigner = recoverSigner(ethHash, signature);

        return recoveredSigner == expectedSigner;
    }
}
