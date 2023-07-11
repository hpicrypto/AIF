const {MMS} = require('../../../src/building-blocks/mms/ps');
const chai = require('chai');
const expect = chai.expect;

describe('PS Multi-Message Signature Scheme', () => {

    before(async function () {
        await MMS.setup();
    });

    it('Generate keys', async () => {
        const {sk, pk} = MMS.kGen(n = 1);
        expect(sk.y.length).equals(1);
        expect(pk.Y.length).equals(1);
    });

    it('Sign/verify messages/signature', async () => {
        const msg = ['Hello', 'World', '!'];
        const {sk, pk} = MMS.kGen(msg.length);
        const sigma = MMS.sign(sk, msg);
        const b = MMS.vf(pk, msg, sigma);
        expect(b).equals(true);
    });

    it('Mismatch message', async () => {
        const msg1 = ['Hello', 'World', '!'];
        const msg2 = ['Hello', 'World', '?'];
        const {sk, pk} = MMS.kGen(msg1.length);
        const sigma = MMS.sign(sk, msg1);
        const b = MMS.vf(pk, msg2, sigma);
        expect(b).equals(false);
    });

    it('Mismatch public key', async () => {
        const msg = ['Hello', 'World', '!'];
        const kp1 = MMS.kGen(msg.length);
        const kp2 = MMS.kGen(msg.length);
        const sigma = MMS.sign(kp1.sk, msg);
        const b = MMS.vf(kp2.pk, msg, sigma);
        expect(b).equals(false);
    });

    it('Mismatch message length', async () => {
        const msg = ['Hello', 'World'];
        const {sk, pk} = MMS.kGen(n = msg.length);
        const sigma = MMS.sign(sk, msg);
        const b = MMS.vf(pk, [msg[0]], sigma);
        expect(b).equals(false);
    });

});