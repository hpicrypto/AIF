const {AIF_SIG} = require("../../../src/schemes/aif-sig/aif-sig");
const chai = require('chai');
const {fixtures} = require("../test-fixtures");
const {generateNonce, currentEpoch} = require("../func-mocks");
const expect = chai.expect;

function mockRegisterProtocol(kpIdP, rid) {
    const rpReq = AIF_SIG.join(kpIdP.ipk, rid);
    const idPRes = AIF_SIG.reg(rid, kpIdP.member, rpReq.req);

    return {rsk: rpReq.state.kpRP.sk, rpk: rpReq.state.kpRP.pk};
}

function mockCredentialProtocol(pp, kpIdP, rid) {
    const {rsk, rpk} = mockRegisterProtocol(kpIdP, rid);
    const sid = generateNonce();
    const ep = currentEpoch(pp.epoch.start, pp.epoch.end);

    const rpReq = AIF_SIG.credReq(kpIdP.ipk, rid, rsk, sid, ep);
    const idpRes = AIF_SIG.credIss(rid, kpIdP.isk, kpIdP.member, sid, ep, rpReq.req);

    return {rsk: rsk, ep: ep};
}

describe('AIF_SIG', function () {
    this.timeout(10000);
    let pp;

    before(async function () {
        pp = AIF_SIG.setup();
    });

    it('Setup IdP', async () => {
        const kpIdP = await AIF_SIG.setupIdP(pp);
        expect(kpIdP).to.not.be.null;
    });

    it('Registration protocol', async () => {
        const kpIdP = await AIF_SIG.setupIdP(pp);
        const {rsk, rpk} = mockRegisterProtocol(kpIdP, fixtures.rid);
        expect(rsk).to.not.be.null;
        expect(rpk).to.not.be.null;
    });

    it('Credential protocol', async () => {
        const kpIdP = await AIF_SIG.setupIdP(pp);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        expect(cred).not.to.be.empty;
    });

    it('RP authentication request', async () => {
        const kpIdP = await AIF_SIG.setupIdP(pp);
        const {privU, pubU} = AIF_SIG.aInit(fixtures.rid);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        const n = generateNonce();
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const authRp = AIF_SIG.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);

        expect(authRp).to.not.be.null;
    });

    it('IdP response', async () => {
        const kpIdP = await AIF_SIG.setupIdP(pp);
        const n = generateNonce();
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        const {privU, pubU} = AIF_SIG.aInit(fixtures.rid);
        const authRp = AIF_SIG.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);
        const t = AIF_SIG.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRp, pubU, n, ep);

        expect(t).to.not.be.null;
    });

    it('Finalize and verify token', async () => {
        const kpIdP = await AIF_SIG.setupIdP(pp);
        const n = generateNonce();
        const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
        const cred = mockCredentialProtocol(pp, kpIdP, fixtures.rid);
        const {privU, pubU} = AIF_SIG.aInit(fixtures.rid);
        const authRp = AIF_SIG.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);
        const t = AIF_SIG.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRp, pubU, n, ep);
        const tid = AIF_SIG.aFin(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, pubU, privU, n, ep, t);
        const b = AIF_SIG.vf(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, n, ep, tid);

        expect(b).to.be.true;
    });

})