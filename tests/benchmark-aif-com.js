const {AIF_COM} = require("../src/schemes/aif-com/aif-com");
const {generateNonce, currentEpoch} = require("./schemes/func-mocks");
const {fixtures} = require("./schemes/test-fixtures");
const {bench} = require("./benchmark-utils");

async function benchmarkOps(count) {
    // Setup IdP
    const pp = AIF_COM.setup();
    const kpIdP = await AIF_COM.setupIdP();
    const n = generateNonce();
    const sid = generateNonce();
    const ep = currentEpoch(pp.epoch.start, pp.epoch.end);
    // Setup User
    const {privU, pubU} = AIF_COM.aInit(fixtures.rid);
    // Setup RP
    const rpJoin = AIF_COM.join(kpIdP.ipk, fixtures.rid);
    const idpReg = AIF_COM.reg(fixtures.rid, kpIdP.member, rpJoin.req);
    const {rsk, rpk} = {rsk: '', rpk: ''};
    const rpCredReq = AIF_COM.credReq(kpIdP.ipk, fixtures.rid, rsk, sid, ep);
    const idPCredIss = AIF_COM.credIss(fixtures.rid, kpIdP.isk, kpIdP.member, sid, ep, rpCredReq.req);
    const cred = '';
    const authRP = AIF_COM.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep);
    const t = AIF_COM.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRP, pubU, n, ep);
    const tid = AIF_COM.aFin(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, pubU, privU, n, ep, t);

    console.log(`IF_COM benchmarks (count=${count})`);

    bench('SetupIdP', count, async _ => await AIF_COM.setupIdP());
    bench('CredIss', count, _ => AIF_COM.credIss(fixtures.rid, kpIdP.isk, kpIdP.member, sid, ep, rpCredReq.req));
    bench('AInit', count, _ => AIF_COM.aInit(fixtures.rid));
    bench('ARegRP', count, _ => AIF_COM.aReqRP(kpIdP.ipk, fixtures.rid, cred, fixtures.uid, pubU, privU, n, ep));
    bench('AResIdP', count, _ => AIF_COM.aResIdP(kpIdP.ipk, kpIdP.isk, kpIdP.member, fixtures.uid, fixtures.ctx, authRP, pubU, n, ep));
    bench('AFin', count, _ => AIF_COM.aFin(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, pubU, privU, n, ep, t));
    bench('Vf', count, _ => AIF_COM.vf(kpIdP.ipk, fixtures.rid, fixtures.uid, fixtures.ctx, n, ep, tid));
}

const count = process.env.BENCHMARK_COUNT || 100;
benchmarkOps(count).then(_ => console.log('done'));
