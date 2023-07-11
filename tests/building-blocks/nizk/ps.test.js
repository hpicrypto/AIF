const {BLS12_381} = require("mcl-wasm");
const chai = require('chai');
const {MMS} = require("../../../src/building-blocks/mms/ps");
const {NIZK_PS} = require("../../../src/building-blocks/nizk/ps");
const expect = chai.expect;

describe('NIZK - PS Signatures', () => {

    let pp;

    before(async function () {
        pp = await MMS.setup(BLS12_381);
    });

    it('Generate/verify proof - 1 hidden, 2 revealed', () => {
        const msgLst = ['Hello', 'World', '!'];
        const kp = MMS.kGen(msgLst.length);
        const sigma = MMS.sign(kp.sk, msgLst);

        const pi = NIZK_PS.genProof(kp.pk, msgLst, sigma, [0]);
        const b = NIZK_PS.vfProof(kp.pk, pi);

        expect(b).equals(true);
    });

    it('Generate/verify proof - all hidden', () => {
        const msgLst = ['Hello', 'World', '!'];
        const kp = MMS.kGen(msgLst.length);
        const sigma = MMS.sign(kp.sk, msgLst);

        const pi = NIZK_PS.genProof(kp.pk, msgLst, sigma, [0, 1, 2]);
        const b = NIZK_PS.vfProof(kp.pk, pi);

        expect(b).equals(true);
    });

    it('Generate/verify proof - all revealed', () => {
        const msgLst = ['Hello', 'World', '!'];
        const kp = MMS.kGen(msgLst.length);
        const sigma = MMS.sign(kp.sk, msgLst);

        const pi = NIZK_PS.genProof(kp.pk, msgLst, sigma, []);
        const b = NIZK_PS.vfProof(kp.pk, pi);

        expect(b).equals(true);
    });

    it('Mismatch public key at creation', async () => {
        const msgLst = ['Hello', 'World', '!'];
        const kp1 = MMS.kGen(msgLst.length);
        const kp2 = MMS.kGen(msgLst.length);
        const sigma = MMS.sign(kp1.sk, msgLst);

        const pi = NIZK_PS.genProof(kp2.pk, msgLst, sigma, [0]);
        const b = NIZK_PS.vfProof(kp1.pk, pi);

        expect(b).equals(false);
    });

    it('Mismatch public key at verification', async () => {
        const msgLst = ['Hello', 'World', '!'];
        const kp1 = MMS.kGen(msgLst.length);
        const kp2 = MMS.kGen(msgLst.length);
        const sigma = MMS.sign(kp1.sk, msgLst);

        const pi = NIZK_PS.genProof(kp1.pk, msgLst, sigma, [0]);
        const b = NIZK_PS.vfProof(kp2.pk, pi);

        expect(b).equals(false);
    });

    it('Mismatch message at creation', async () => {
        const msgLst1 = ['Hello', 'World', '!'];
        const msgLst2 = ['Hello', 'World', '?'];
        const kp = MMS.kGen(msgLst1.length);
        const sigma = MMS.sign(kp.sk, msgLst1);

        const pi = NIZK_PS.genProof(kp.pk, msgLst2, sigma, [0]);
        const b = NIZK_PS.vfProof(kp.pk, pi);

        expect(b).equals(false);
    });


});