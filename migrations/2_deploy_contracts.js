const Missmatch = artifacts.require("Missmatch");
const MissmatchLib = artifacts.require("MissmatchLib");

module.exports = function (deployer) {
  deployer.link(MissmatchLib, Missmatch);
  deployer.deploy(Missmatch);
};