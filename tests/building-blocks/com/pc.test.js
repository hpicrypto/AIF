const {COM} = require('../../../src/building-blocks/com/pc');
const {BLS12_381} = require("mcl-wasm");
const chai = require('chai');
const expect = chai.expect;

describe('Pedersen Commitment Scheme', () => {

    let pp;
    before(async function () {
        pp = await COM.setup(BLS12_381);
    });

    it('Commit/open message', async () => {
        // await COM.setup(BLS12_381);
        const m = 'Hello World';

        const {c, o} = COM.commit(pp, m);
        const b = COM.open(pp, m, c, o);

        expect(b).equals(true);
    });

    it('Mismatch message', async () => {
        // await COM.setup(BLS12_381);
        const m1 = 'Hello';
        const m2 = 'World';

        const {c, o} = COM.commit(pp, m1);
        const b = COM.open(pp, m2, c, o);

        expect(b).equals(false);
    });

    it('Mismatch commitment', async () => {
        const m = 'Hello World';

        const c1 = COM.commit(pp, m);
        const c2 = COM.commit(pp, m);

        const b = COM.open(pp, m, c2.c, c1.o);

        expect(b).equals(false);
    });

    it('Mismatch opener', async () => {
        const m = 'Hello World';

        const c1 = COM.commit(pp, m);
        const c2 = COM.commit(pp, m);

        const b = COM.open(pp, m, c1.c, c2.o);

        expect(b).equals(false);
    });

});