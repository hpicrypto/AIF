const {AIF_SIG} = require("../src/schemes/aif-sig/aif-sig");
const {generateNonce, currentEpoch} = require("./schemes/func-mocks");
const {fixtures} = require("./schemes/test-fixtures");
const {bench} = require("./benchmark-utils");

async function benchmarkOps(count) {
    // Setup IdP
    const pp = AIF_SIG.setup();
    const kpIdP = await AIF_SIG.setupIdP();
    const n = generateNonce();
    const sid = generateNonce();
    const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
    // Setup User
    const {privU, pubU} = AIF_SIG.aInit(fixtures.rid);
    // Setup RP
    const rpJoin = AIF_SIG.join(kpIdP.ipk, fixtures.rid);
    const idPReg = AIF_SIG.reg(fixtures.rid, kpIdP.member, rpJoin.req);
    const {rsk, rpk} = {rsk: rpJoin.state.kpRP.sk, rpk: rpJoin.state.kpRP.pk};
    const rpCredReq = AIF_SIG.credReq(kpIdP.ipk, fixtures.rid, rsk, sid, ep);
    const idpCredIss = AIF_SIG.credIss(fixtures.rid, kpIdP.isk, kpIdP.member, sid, ep, rpCredReq.req);
    const cred = {rsk: rsk, ep: ep};
    const authRP = AIF_SIG.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);
    const t = AIF_SIG.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRP, pubU, n, ep);
    const tid = AIF_SIG.aFin(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, pubU, privU, n, ep, t);

    console.log(`IF_SIG benchmarks (count=${count})`);

    bench('SetupIdP', count, async _ => await AIF_SIG.setupIdP());
    bench('CredIss', count, _ => AIF_SIG.credIss(fixtures.rid, kpIdP.isk, kpIdP.member, sid, ep, rpCredReq.req));
    bench('AInit', count, _ => AIF_SIG.aInit(fixtures.rid));
    bench('ARegRP', count, _ => AIF_SIG.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep));
    bench('AResIdP', count, _ => AIF_SIG.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRP, pubU, n, ep));
    bench('AFin', count, _ => AIF_SIG.aFin(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, pubU, privU, n, ep, t));
    bench('Vf', count, _ => AIF_SIG.vf(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, n, ep, tid));
}

const count = process.env.BENCHMARK_COUNT || 100;
benchmarkOps(count).then(_ => console.log('done'));
