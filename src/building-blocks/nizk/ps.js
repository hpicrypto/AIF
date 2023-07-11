const mcl = require('mcl-wasm');
const utils = require("../../utils/mcl");
const {COM} = require("../../building-blocks/com/pc");

function NIZKPSSignatures() {

    return {

        // Returns NIZK pi proving knowledge of a signature (sigma) on a message (msgLst) where some messages are hidden (hiddenMsgIdxLst)
        // Optimization: Calculations of message randomizers (uY) are done in G2 before calculating the pairing
        genProof: function (pk, msgLst, sigma, hiddenMsgIdxLst) {

            const revealedMsgLst = msgLst.filter((msg, idx) => !hiddenMsgIdxLst.includes(idx));
            const revealedMsgLstZp = utils.hashStringLstToZpLst(mcl, revealedMsgLst);
            const msgLstZp = utils.hashStringLstToZpLst(mcl, msgLst);

            const uH = [];
            for (let i = 0; i < hiddenMsgIdxLst.length; i++)
                uH.push(utils.getRandomZp(mcl));

            // Randomize signature
            const r = utils.getRandomZp(mcl);
            const t = utils.getRandomZp(mcl);
            const s1r = mcl.mul(sigma.one, r);
            const s2r = mcl.mul(sigma.two, r);
            const s1rt = mcl.mul(s1r, t);
            const s2rS1rt = mcl.add(s2r, s1rt);
            const rdmSig = {one: s1r, two: s2rS1rt};

            // Signature announcement
            const uT = utils.getRandomZp(mcl);

            // Moved to G2 before calculating the pairing
            let uY = new mcl.G2();
            for (let i = 0; i < hiddenMsgIdxLst.length; i++)
                uY = mcl.add(uY, mcl.mul(pk.Y[hiddenMsgIdxLst[i]], uH[i]));
            uY = mcl.add(uY, mcl.mul(pk.g, uT));
            const aSig = mcl.pairing(rdmSig.one, uY);

            // Challenge
            const z = utils.hashToZp(mcl, '', aSig, ...revealedMsgLstZp);

            // Responses
            const rHiddenLst = [];
            for (let i = 0; i < hiddenMsgIdxLst.length; i++)
                rHiddenLst.push({idx: hiddenMsgIdxLst[i], r: mcl.add(uH[i], mcl.mul(msgLstZp[hiddenMsgIdxLst[i]], z))});
            const rT = mcl.add(uT, mcl.mul(t, z));

            const msgIdXLst = msgLst.map((msg, idx) => {
                return {idx: idx, msg: msg}
            });
            const revealedMsgIdXLst = msgIdXLst.filter((msgIdX) => !hiddenMsgIdxLst.includes(msgIdX.idx));

            return {sig: rdmSig, revealedMsgIdXLst: revealedMsgIdXLst, aSig: aSig, rHiddenLst: rHiddenLst, rT: rT};
        },

        // Returns 0 or 1, implying pi is a valid proof of knowledge of a signature (sigma) on a message (msgLst) where some messages are hidden (hiddenMsgIdxLst)
        // Optimization: Calculations of the challenge (z) are moved to G1 and the revealed/hidden messages are moved to G2 before calculating the pairing
        vfProof: function (pk, pi) {
            const revealedMsgLstZp = [];
            for (let i = 0; i < pi.revealedMsgIdXLst.length; i++)
                revealedMsgLstZp.push(utils.hashToZp(mcl, pi.revealedMsgIdXLst[i].msg));

            // Challenge
            const z = utils.hashToZp(mcl, '', pi.aSig, ...revealedMsgLstZp);

            // Move z to G1; move revealed messages to G2
            const lhsP1 = mcl.pairing(mcl.mul(pi.sig.two, z), pk.g);
            let lhsG2 = new mcl.G2();
            lhsG2.deserialize(pk.X.serialize());
            for (let i = 0; i < pi.revealedMsgIdXLst.length; i++)
                lhsG2 = mcl.add(lhsG2, mcl.mul(pk.Y[pi.revealedMsgIdXLst[i].idx], revealedMsgLstZp[i]));
            const lhsP2 = mcl.pairing(mcl.mul(pi.sig.one, z), lhsG2);
            const lhsP3 = mcl.mul(lhsP1, mcl.inv(lhsP2));
            const lhsP4 = mcl.mul(lhsP3, pi.aSig);

            // Move hidden message responses to G2
            let rhsG2 = new mcl.G2();
            for (let i = 0; i < pi.rHiddenLst.length; i++)
                rhsG2 = mcl.add(rhsG2, mcl.mul(pk.Y[pi.rHiddenLst[i].idx], pi.rHiddenLst[i].r));
            rhsG2 = mcl.add(rhsG2, mcl.mul(pk.g, pi.rT));
            // const rhsG2 = mcl.add(mcl.mul(Y1, pi.rRid), mcl.mul(gTilde, pi.rT));
            const rhsP1 = mcl.pairing(pi.sig.one, rhsG2);

            return lhsP4.isEqual(rhsP1);
        },
    }
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        NIZK_PS: NIZKPSSignatures()
    };
}