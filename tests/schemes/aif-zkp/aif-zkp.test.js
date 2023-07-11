const {AIF_ZKP} = require("../../../src/schemes/aif-zkp/aif-zkp");
const chai = require('chai');
const {generateNonce, currentEpoch} = require("../func-mocks");
const {fixtures} = require("../test-fixtures");
const expect = chai.expect;

function mockRegisterProtocol(kpIdP, rid) {
    const rpJoin = AIF_ZKP.join(kpIdP.ipk, rid);
    const idpReg = AIF_ZKP.reg(rid, kpIdP.member, rpJoin.req);

    return {rsk: rpJoin.state.kpRP.sk, rpk: rpJoin.state.kpRP.pk};
}

function mockCredentialProtocol(pp, kpIdP, rid) {
    const {rsk, rpk} = mockRegisterProtocol(kpIdP, rid);
    const sid = generateNonce();
    const ep = currentEpoch(pp.epoch.start, pp.epoch.end);

    const rpReq = AIF_ZKP.credReq(kpIdP.ipk, rid, rsk, sid, ep);
    const idpRes = AIF_ZKP.credIss(rid, kpIdP.isk, kpIdP.member, sid, ep, rpReq.req);

    return {sigmaIdP: idpRes.res.sigmaIdP, ep: ep};
}

describe('AIF_ZKP', function () {
    this.timeout(10000);

    let pp;

    before(async function () {
        pp = AIF_ZKP.setup();
    });

    it('Setup IdP', async () => {
        const kpIdP = await AIF_ZKP.setupIdP(pp);
        expect(kpIdP).to.not.be.null;
    });

    it('Registration protocol', async () => {
        const kpIdP = await AIF_ZKP.setupIdP(pp);

        const {rsk, rpk} = mockRegisterProtocol(kpIdP, fixtures.rid);

        expect(rsk).to.not.be.null;
        expect(rpk).to.not.be.null;
    });

    it('Credential protocol', async () => {
        const kpIdP = await AIF_ZKP.setupIdP(pp);
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        expect(cred).not.to.be.empty;

        expect(cred.sigmaIdP).to.not.be.null;
        expect(cred.ep).equals(ep);
    });

    it('User authentication init', () => {
        const {privU, pubU} = AIF_ZKP.aInit(fixtures.rid);

        expect(privU).to.not.be.null;
        expect(pubU).to.not.be.null;
    });

    it('RP authentication request', async () => {
        const kpIdP = await AIF_ZKP.setupIdP(pp);
        const {privU, pubU} = AIF_ZKP.aInit(fixtures.rid);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        const n = generateNonce();
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const authRp = AIF_ZKP.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);

        expect(authRp).to.not.be.null;
    });

    it('IdP response', async () => {
        const kpIdP = await AIF_ZKP.setupIdP(pp);
        const n = generateNonce();
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        const {privU, pubU} = AIF_ZKP.aInit(fixtures.rid);
        const authRp = AIF_ZKP.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);
        const t = AIF_ZKP.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRp, pubU, n, ep);

        expect(t).to.not.be.null;
    });

    it('Finalize and verify token', async () => {
        const kpIdP = await AIF_ZKP.setupIdP(pp);
        const n = generateNonce();
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        const {privU, pubU} = AIF_ZKP.aInit(fixtures.rid);
        const authRp = AIF_ZKP.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);
        const t = AIF_ZKP.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRp, pubU, n, ep);
        const tid = AIF_ZKP.aFin(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, pubU, privU, n, ep, t);

        const b = AIF_ZKP.vf(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, n, ep, tid);

        expect(b).to.be.true;
    });

    it('Finalize and verify token (optimized)', async () => {
        const optimized = true;
        const kpIdP = await AIF_ZKP.setupIdP(pp);
        const n = generateNonce();
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        const {privU, pubU} = AIF_ZKP.aInit(fixtures.rid);
        const authRp = AIF_ZKP.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep, optimized);
        const t = AIF_ZKP.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRp, pubU, n, ep, optimized);
        const tid = AIF_ZKP.aFin(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, pubU, privU, n, ep, t);

        const b = AIF_ZKP.vf(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, n, ep, tid);

        expect(b).to.be.true;
    });

})