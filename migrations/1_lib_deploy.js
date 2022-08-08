const MissmatchLib = artifacts.require("MissmatchLib");

module.exports = function (deployer) {
  deployer.deploy(MissmatchLib);
};