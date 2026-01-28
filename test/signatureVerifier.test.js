/*
    Plik testowy: signatureVerifier.test.js

    Cel testów:
    -----------
    Weryfikacja poprawności działania mechanizmu uwierzytelniania
    opartego na podpisach kryptograficznych ECDSA, realizującego
    założenia Self-Sovereign Identity (SSI).

    Zakres testów:
    --------------
    - scenariusz poprawny (posiadanie właściwego klucza prywatnego)
    - scenariusze negatywne (próby podszycia się, manipulacja danymi)
    - analiza odporności na wybrane klasy ataków

    Środowisko testowe:
    -------------------
    - Truffle (framework testowy)
    - Ganache (lokalna sieć blockchain Ethereum)
*/

require("dotenv").config(); // Wczytanie zmiennych środowiskowych z pliku .env

// Załadowanie artefaktu smart kontraktu SignatureVerifier
const SignatureVerifier = artifacts.require("SignatureVerifier");

// Biblioteka ethers.js wykorzystywana do:
// - tworzenia portfeli Ethereum z klucza prywatnego
// - generowania podpisów kryptograficznych ECDSA off-chain
const { ethers } = require("ethers");

/*
    Główna grupa testów funkcjonalnych kontraktu SignatureVerifier
*/
contract("SignatureVerifier", () => {

    /*
        TEST 1: SCENARIUSZ POPRAWNY

        Sprawdzenie, czy użytkownik posiadający poprawny klucz prywatny
        jest w stanie wygenerować podpis ECDSA, który zostanie poprawnie
        zweryfikowany przez smart kontrakt.
    */
    it("verifies ECDSA signature and recovers signer", async () => {

        // Pobranie instancji wdrożonego kontraktu
        const verifier = await SignatureVerifier.deployed();

        // Klucz prywatny użytkownika (konto testowe Ganache)
        const privateKey = process.env.TEST_PRIVATE_KEY;

        // Utworzenie portfela Ethereum reprezentującego tożsamość użytkownika
        const wallet = new ethers.Wallet(privateKey);

        // Publiczny adres Ethereum użytkownika
        const userAddress = wallet.address;

        // Nonce – jednorazowy identyfikator próby weryfikacji
        const nonce = ethers.zeroPadValue("0x01", 32);

        // Generowanie hasha wiadomości po stronie smart kontraktu
        const messageHash = await verifier.getMessageHash(userAddress, nonce);

        // Podpisanie hasha off-chain przy użyciu klucza prywatnego
        const signature = await wallet.signMessage(
            ethers.getBytes(messageHash)
        );

        // Weryfikacja podpisu po stronie smart kontraktu
        const isValid = await verifier.verify(
            userAddress,   // expectedSigner
            userAddress,   // user
            nonce,
            signature
        );

        // Oczekiwany wynik: poprawna weryfikacja podpisu
        assert.equal(isValid, true, "Valid signature should be accepted");
    });

    /*
        TEST 2: PODSZYCIe SIĘ POD UŻYTKOWNIKA (INNY KLUCZ PRYWATNY)

        Sprawdzenie, czy podpis wygenerowany innym kluczem prywatnym
        zostanie poprawnie odrzucony przez system.
    */
    it("rejects signature made by attacker key when claiming victim address", async () => {

        const verifier = await SignatureVerifier.deployed();

        // Ofiara – prawdziwy użytkownik
        const victimWallet = new ethers.Wallet(process.env.TEST_PRIVATE_KEY);
        const victimAddress = victimWallet.address;

        // Atakujący – losowo wygenerowany portfel Ethereum
        const attackerWallet = ethers.Wallet.createRandom();

        const nonce = ethers.zeroPadValue("0x01", 32);

        // Hash generowany dla danych ofiary
        const messageHash = await verifier.getMessageHash(victimAddress, nonce);

        // Podpis wykonany kluczem atakującego
        const signature = await attackerWallet.signMessage(
            ethers.getBytes(messageHash)
        );

        const isValid = await verifier.verify(
            victimAddress,
            victimAddress,
            nonce,
            signature
        );

        // Oczekiwany wynik: odrzucenie próby podszycia się
        assert.equal(isValid, false, "Signature from attacker must be rejected");
    });

    /*
        TEST 3: MANIPULACJA NONCE (OCHRONA PRZED REPLAY ATTACK)

        Sprawdzenie, czy zmiana wartości nonce po podpisaniu wiadomości
        powoduje odrzucenie podpisu.
    */
    it("rejects signature if nonce is changed after signing", async () => {

        const verifier = await SignatureVerifier.deployed();

        const wallet = new ethers.Wallet(process.env.TEST_PRIVATE_KEY);
        const userAddress = wallet.address;

        const nonceSigned = ethers.zeroPadValue("0x01", 32);
        const nonceProvided = ethers.zeroPadValue("0x02", 32);

        const messageHash = await verifier.getMessageHash(userAddress, nonceSigned);
        const signature = await wallet.signMessage(
            ethers.getBytes(messageHash)
        );

        const isValid = await verifier.verify(
            userAddress,
            userAddress,
            nonceProvided,
            signature
        );

        // Oczekiwany wynik: podpis niepoprawny
        assert.equal(isValid, false, "Signature should be invalid for modified nonce");
    });

    /*
        TEST 4: NIEZGODNY expectedSigner

        Sprawdzenie, czy podpis zostanie odrzucony, jeżeli oczekiwany
        autor podpisu nie zgadza się z rzeczywistym podpisującym.
    */
    it("rejects valid signature if expectedSigner is different", async () => {

        const verifier = await SignatureVerifier.deployed();

        const wallet = new ethers.Wallet(process.env.TEST_PRIVATE_KEY);
        const userAddress = wallet.address;

        const otherAddress = ethers.Wallet.createRandom().address;
        const nonce = ethers.zeroPadValue("0x01", 32);

        const messageHash = await verifier.getMessageHash(userAddress, nonce);
        const signature = await wallet.signMessage(
            ethers.getBytes(messageHash)
        );

        const isValid = await verifier.verify(
            otherAddress,
            userAddress,
            nonce,
            signature
        );

        assert.equal(isValid, false, "Signature should be rejected for incorrect signer");
    });

    /*
        TEST 5: PUSTY PODPIS

        Sprawdzenie odporności systemu na brak danych wejściowych.
    */
    it("rejects empty signature", async () => {

        const verifier = await SignatureVerifier.deployed();

        const wallet = new ethers.Wallet(process.env.TEST_PRIVATE_KEY);
        const userAddress = wallet.address;
        const nonce = ethers.zeroPadValue("0x01", 32);

        try {
            await verifier.verify(userAddress, userAddress, nonce, "0x");
            assert.fail("Verification should fail for empty signature");
        } catch (error) {
            assert.include(error.message, "Invalid signature length");
        }
    });

    /*
        TEST 6: USZKODZONY PODPIS (NIEPRAWIDŁOWA STRUKTURA)
    */
    it("rejects malformed signature with incorrect length", async () => {

        const verifier = await SignatureVerifier.deployed();

        const wallet = new ethers.Wallet(process.env.TEST_PRIVATE_KEY);
        const userAddress = wallet.address;
        const nonce = ethers.zeroPadValue("0x01", 32);

        const malformedSignature = "0x1234567890abcdef";

        try {
            await verifier.verify(userAddress, userAddress, nonce, malformedSignature);
            assert.fail("Verification should fail for malformed signature");
        } catch (error) {
            assert.include(error.message, "Invalid signature length");
        }
    });

    /*
        TEST 7: REPLAY ATTACK – ZNANE OGRANICZENIE PROTOTYPU

        Demonstracja możliwości ponownego użycia tego samego podpisu
        przy zastosowaniu statycznej wartości nonce.
    */
    it("demonstrates replay attack possibility with static nonce (known limitation)", async () => {

        const verifier = await SignatureVerifier.deployed();

        const wallet = new ethers.Wallet(process.env.TEST_PRIVATE_KEY);
        const userAddress = wallet.address;
        const nonce = ethers.zeroPadValue("0x01", 32);

        const messageHash = await verifier.getMessageHash(userAddress, nonce);
        const signature = await wallet.signMessage(
            ethers.getBytes(messageHash)
        );

        const firstCheck = await verifier.verify(userAddress, userAddress, nonce, signature);
        const secondCheck = await verifier.verify(userAddress, userAddress, nonce, signature);

        assert.equal(firstCheck, true);
        assert.equal(secondCheck, true);
    });

    /*
        TEST 8: PODPIS DLA INNEGO ADRESU UŻYTKOWNIKA

        Sprawdzenie, czy podpis przypisany do jednego adresu
        nie może zostać użyty dla innego użytkownika.
    */
    it("rejects signature if it was signed for a different user address", async () => {

        const verifier = await SignatureVerifier.deployed();

        const wallet = new ethers.Wallet(process.env.TEST_PRIVATE_KEY);
        const realUser = wallet.address;
        const fakeUser = ethers.Wallet.createRandom().address;
        const nonce = ethers.zeroPadValue("0x01", 32);

        const messageHash = await verifier.getMessageHash(realUser, nonce);
        const signature = await wallet.signMessage(
            ethers.getBytes(messageHash)
        );

        const isValid = await verifier.verify(realUser, fakeUser, nonce, signature);

        assert.equal(isValid, false, "Signature should be invalid for different user");
    });
});
