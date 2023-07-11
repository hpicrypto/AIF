const mcl = require('mcl-wasm');
const utils = require("../../utils/mcl");

function PedersenCommitment() {

    return {
        // Takes a curve and returns the public parameter pp containing generator g and h
        setup: async function (curve = mcl.curveType) {
            await mcl.init(curve);
            return {g: utils.getRndGeneratorG1(mcl), h: utils.getRndGeneratorG1(mcl)};
        },

        // Takes a string m and public parameter pp and returns a commitment c and opener o
        commit: function (pp, m) {
            const mZp = utils.hashToZp(mcl, m);
            const o = utils.getRandomZp(mcl);
            const c = mcl.add(mcl.mul(pp.g, mZp), mcl.mul(pp.h, o));
            return {c, o};
        },

        // Takes a string m, commitment c, opener o and public parameter pp and returns true if the commitment is valid
        open: function (pp, m, c, o) {
            const mZp = utils.hashToZp(mcl, m);
            return mcl.add(mcl.mul(pp.g, mZp), mcl.mul(pp.h, o)).isEqual(c);
        }
    };
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        COM: PedersenCommitment()
    };
}