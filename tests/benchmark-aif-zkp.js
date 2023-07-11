const {AIF_ZKP} = require("../src/schemes/aif-zkp/aif-zkp");
const {generateNonce, currentEpoch} = require("./schemes/func-mocks");
const {bench} = require("./benchmark-utils");
const {fixtures} = require("./schemes/test-fixtures");

async function benchmarkOps(count) {
    const optimized = process.env.OPTIMIZED_PROOFS === '1';
    // Setup IdP
    const pp = AIF_ZKP.setup();
    const kpIdP = await AIF_ZKP.setupIdP();
    const n = generateNonce();
    const sid = generateNonce();
    const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
    // Setup User
    const {privU, pubU} = AIF_ZKP.aInit(fixtures.rid);
    // Setup RP
    const rpJoin = AIF_ZKP.join(kpIdP.ipk, fixtures.rid);
    const idPReg = AIF_ZKP.reg(fixtures.rid, kpIdP.member, rpJoin.req);
    const {rsk, rpk} = {rsk: rpJoin.state.kpRP.sk, rpk: rpJoin.state.kpRP.pk};

    const rpCredReq = AIF_ZKP.credReq(kpIdP.ipk, fixtures.rid, rsk, sid, ep);
    const idpCredIss = AIF_ZKP.credIss(fixtures.rid, kpIdP.isk, kpIdP.member, sid, ep, rpCredReq.req);
    const cred = {sigmaIdP: idpCredIss.res.sigmaIdP, ep: ep};

    const authRP = AIF_ZKP.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep, optimized);
    const t = AIF_ZKP.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRP, pubU, n, ep, optimized);
    const tid = AIF_ZKP.aFin(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, pubU, privU, n, ep, t);

    console.log(`IF_ZKP benchmarks (count=${count}; optimization=${optimized})`);

    bench('SetupIdP', count, async _ => await AIF_ZKP.setupIdP());
    bench('CredIss', count, _ => AIF_ZKP.credIss(fixtures.rid, kpIdP.isk, kpIdP.member, sid, ep, rpCredReq.req));
    bench('AInit', count, _ => AIF_ZKP.aInit(fixtures.rid));
    bench('ARegRP', count, _ => AIF_ZKP.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep, optimized));
    bench('AResIdP', count, _ => AIF_ZKP.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRP, pubU, n, ep, optimized));
    bench('AFin', count, _ => AIF_ZKP.aFin(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, pubU, privU, n, ep, t));
    bench('Vf', count, _ => AIF_ZKP.vf(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, n, ep, tid));
}

const count = process.env.BENCHMARK_COUNT || 100;
benchmarkOps(count).then(_ => console.log('done'));
