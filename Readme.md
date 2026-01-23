# SSI Blockchain Prototype (ECDSA Verification)

Projekt demonstracyjny wykonany w ramach pracy inżynierskiej.
Celem jest implementacja mechanizmu Self-Sovereign Identity (SSI)
opartego o kryptograficzną weryfikację podpisów ECDSA w sieci Ethereum.

## Technologie
- Solidity (smart contracts)
- Truffle
- Ganache (lokalna sieć Ethereum)
- Node.js
- ethers.js
- Git / GitHub

## Opis działania
Użytkownik podpisuje kryptograficznie wiadomość (nonce) przy użyciu
klucza prywatnego. Smart kontrakt weryfikuje podpis i odzyskuje adres
nadawcy, potwierdzając kontrolę nad kluczem prywatnym bez potrzeby
przechowywania danych osobowych.

## Uruchomienie projektu
1. Uruchom Ganache (Quickstart Ethereum)
2. Zainstaluj zależności:
   ```bash
   npm install
3. Skonfiguruj zmienną środowiskową:
TEST_PRIVATE_KEY=0x...
4. Uruchom testy:
truffle test

Autor

Damian Haranek