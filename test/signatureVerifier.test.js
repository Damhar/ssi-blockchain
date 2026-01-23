const SignatureVerifier = artifacts.require("SignatureVerifier");
const { ethers } = require("ethers");

contract("SignatureVerifier", (accounts) => {
    it("verifies ECDSA signature and recovers signer", async () => {
        const verifier = await SignatureVerifier.deployed();

        // 🔐 PRIVATE KEY z Ganache (konto index 0)
        const privKey = process.env.TEST_PRIVATE_KEY;
        const wallet = new ethers.Wallet(privKey);

        const user = wallet.address;
        const nonce = ethers.zeroPadValue("0x01", 32);

        const messageHash = await verifier.getMessageHash(user, nonce);
        const signature = await wallet.signMessage(ethers.getBytes(messageHash));

        const isValid = await verifier.verify(user, user, nonce, signature);
        assert.equal(isValid, true, "Signature should be valid");
    });
});
