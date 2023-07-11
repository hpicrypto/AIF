const mcl = require('mcl-wasm');
const {BLS12_381} = require('mcl-wasm');
const utils = require('../../utils/mcl');


function PSMultiMessageSignatureScheme() {
    "use strict";

    return {

        // Setup algorithm for the signature scheme that takes as input a curve and returns an instance of mcl
        setup: async function (curve = BLS12_381) {
            await mcl.init(curve);
            return mcl;
        },

        // KeyGen algorithm that takes as input the message vector dimension l and returns a key pair according to the scheme
        kGen: function (l = 2) {
            const g = utils.getRndGeneratorG2(mcl);       // generator G2
            const x = utils.getRandomZp(mcl);             // secret key
            const X = mcl.mul(g, x);                  // public key

            const y = [];                           // secret keys
            const Y = [];                           // public keys

            let yi, Yi;
            for (let i = 0; i < l; i++) {
                yi = utils.getRandomZp(mcl);
                Yi = mcl.mul(g, yi);
                y.push(yi);
                Y.push(Yi);
            }

            return {sk: {x, y}, pk: {g, X, Y}};
        },

        // Sign algorithm that takes as input a secret key sk and a message vector msgLst and returns a signature on the message vector
        sign: function (sk, msgLst) {
            const zpLst = utils.hashStringLstToZpLst(mcl, msgLst);
            const h = utils.getRndGeneratorG1(mcl);

            let sum = new mcl.G1(),     // sum of h^yi*mi
                tmp;
            for (let i = 0; i < zpLst.length; i++) {
                tmp = mcl.mul(zpLst[i], sk.y[i]);         // yi*mi
                tmp = mcl.mul(h, tmp);                    // h^yi*mi
                sum = mcl.add(sum, tmp);
            }
            // sigma
            return {one: h, two: mcl.add(mcl.mul(h, sk.x), sum)};
        },

        // Verify algorithm that takes as input a public key pk, a message vector msgLst, and a signature sigma and returns {0,1}, implying sigma is a valid signature on msgLst under pk
        vf: function (pk, msgLst, sigma) {
            const zpLst = utils.hashStringLstToZpLst(mcl, msgLst);

            let X = new mcl.G2();
            X.deserialize(pk.X.serialize());
            for (let i = 0; i < zpLst.length; i++)
                X = mcl.add(X, mcl.mul(pk.Y[i], zpLst[i]));

            let lhs = mcl.pairing(sigma.one, X);               // pairing left-hand side
            let rhs = mcl.pairing(sigma.two, pk.g);            // pairing right-hand side

            return lhs.isEqual(rhs);
        },

    };
}


if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        MMS: PSMultiMessageSignatureScheme()
    };
}