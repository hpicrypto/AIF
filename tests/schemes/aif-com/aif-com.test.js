const {AIF_COM} = require("../../../src/schemes/aif-com/aif-com");
const chai = require('chai');
const {fixtures} = require("../test-fixtures");
const {generateNonce, currentEpoch} = require("../func-mocks");
const expect = chai.expect;

function mockRegisterProtocol(kpIdP, rid) {
    const rpJoin = AIF_COM.join(kpIdP.ipk, rid);
    const idpReg = AIF_COM.reg(rid, kpIdP.member, rpJoin.req);

    return {rsk: '', rpk: ''};
}

function mockCredentialProtocol(pp, kpIdP, rid) {
    const {rsk, rpk} = mockRegisterProtocol(kpIdP, rid);
    const sid = generateNonce();
    const ep = currentEpoch(pp.epoch.start, pp.epoch.end);

    AIF_COM.credReq(kpIdP.ipk, rid, rsk, sid, ep);
    AIF_COM.credIss(rid, kpIdP.isk, kpIdP.member, sid, ep);

    return '';
}

describe('AIF_COM', function () {
    this.timeout(10000);
    let pp;

    before(async () => {
        pp = AIF_COM.setup();
    });

    it('Setup IdP', async () => {
        const kpIdP = await AIF_COM.setupIdP();
        expect(kpIdP).to.not.be.null;
    });

    it('Registration protocol', async () => {
        const kpIdP = await AIF_COM.setupIdP();
        const {rsk, rpk} = mockRegisterProtocol(kpIdP, fixtures.rid);
        expect(rsk).to.not.be.null;
        expect(rpk).to.not.be.null;
    });
    it('Credential protocol', async () => {
        const kpIdP = await AIF_COM.setupIdP();
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        expect(cred).to.be.empty;
    });

    it('User authentication init', () => {
        const {privU, pubU} = AIF_COM.aInit(fixtures.rid);

        expect(privU).to.not.be.null;
        expect(pubU).to.not.be.null;
    });

    it('RP authentication request', async () => {
        const kpIdP = await AIF_COM.setupIdP();
        const {privU, pubU} = AIF_COM.aInit(fixtures.rid);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        const n = generateNonce();
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const authRp = AIF_COM.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);

        expect(authRp).to.be.empty;
    });

    it('IdP response', async () => {
        const kpIdP = await AIF_COM.setupIdP();
        const n = generateNonce();
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        const {privU, pubU} = AIF_COM.aInit(fixtures.rid);
        const authRp = AIF_COM.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);
        const t = AIF_COM.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRp, pubU, n, ep);

        expect(t).to.not.be.null;
    });

    it('Finalize and verify token', async () => {
        const kpIdP = await AIF_COM.setupIdP();

        const n = generateNonce();
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        const {privU, pubU} = AIF_COM.aInit(fixtures.rid);
        const authRp = AIF_COM.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);

        const t = AIF_COM.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRp, pubU, n, ep);
        const tid = AIF_COM.aFin(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, pubU, privU, n, ep, t);

        const b = AIF_COM.vf(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, n, ep, tid);

        expect(b).to.be.true;
    });

})