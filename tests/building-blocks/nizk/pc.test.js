const {COM} = require('../../../src/building-blocks/com/pc');
const {BLS12_381} = require("mcl-wasm");
const chai = require('chai');
const {NIZK_COM} = require("../../../src/building-blocks/nizk/pc");
const expect = chai.expect;

describe('NIZK - Pedersen Commitment Scheme', () => {

    let pp;

    before(async function () {
        pp = await COM.setup(BLS12_381);
    });

    it('Generate/verify proof', async () => {
        const m = 'Hello World';
        const {c, o} = COM.commit(pp, m);

        const {pi, state} = NIZK_COM.genProof(pp.g, pp.h, m, c, o);
        const b = NIZK_COM.vfProof(pp.g, pp.h, c, pi);

        expect(b).equals(true);
    });

    it('Mismatch commitment', async () => {
        const m = 'Hello World';
        const com1 = COM.commit(pp, m);
        const com2 = COM.commit(pp, m);

        const {pi, state} = NIZK_COM.genProof(pp.g, pp.h, m, com1.c, com1.o);
        const b = NIZK_COM.vfProof(pp.g, pp.h, com2.c, pi);

        expect(b).equals(false);
    });

    it('Mismatch g and h', async () => {
        const pp1 = await COM.setup(BLS12_381);
        const m = 'Hello World';
        const com = COM.commit(pp, m); // com created under pp1

        const {pi, state} = NIZK_COM.genProof(pp1.g, pp1.h, m, com.c, com.o);
        const b1 = NIZK_COM.vfProof(pp.g, pp1.h, com.c, pi); // pp.g != pp1.g
        const b2 = NIZK_COM.vfProof(pp1.g, pp.h, com.c, pi); // pp.h != pp1.h

        expect(b1).equals(false);
        expect(b2).equals(false);
    });

});