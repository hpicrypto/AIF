const mcl = require('mcl-wasm');
const utils = require("../../utils/mcl");

function NIZKPedersenCommitment() {

    return {

        // NIZK{(m, o): Open(m, c, o) = 1}(g, h, c)
        genProof: function (g, h, m, c, o) {
            const mZp = utils.hashToZp(mcl, m);
            const u1 = utils.getRandomZp(mcl);
            const u2 = utils.getRandomZp(mcl);
            const a = mcl.add(mcl.mul(g, u1), mcl.mul(h, u2));
            const z = utils.hashToZp(mcl, '', g, h, a, c);
            const r1 = mcl.add(u1, mcl.mul(mZp, z));
            const r2 = mcl.add(u2, mcl.mul(o, z));

            const pi = {a, r1: r1, r2: r2};
            const state = {u1: u1, u2: u2};

            return {pi, state};
        },

        vfProof: function (g, h, c, pi) {
            const z = utils.hashToZp(mcl, '', g, h, pi.a, c);
            // g^r1 * h^r2
            const lhs = mcl.add(mcl.mul(g, pi.r1), mcl.mul(h, pi.r2));
            // c^z * a
            const rhs = mcl.add(pi.a, mcl.mul(c, z));

            return lhs.isEqual(rhs);
        }
    }
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        NIZK_COM: NIZKPedersenCommitment()
    };
}