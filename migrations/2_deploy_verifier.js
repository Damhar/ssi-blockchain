const SignatureVerifier = artifacts.require("SignatureVerifier");

module.exports = function (deployer) {
    deployer.deploy(SignatureVerifier);
};