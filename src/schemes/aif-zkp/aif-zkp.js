const {BLS12_381} = require("mcl-wasm");
const {SIG} = require("../../building-blocks/sig/rsa");
const {MMS} = require("../../building-blocks/mms/ps");
const {COM} = require("../../building-blocks/com/pc");
const {currentEpoch} = require("../../../tests/schemes/func-mocks");
const utils = require("../../utils/mcl");
const mcl = require("mcl-wasm");

function AuthenticatedImplicitFlowZKPScheme() {
    "use strict";

    let pp;

    return {

        setup: function (curve = BLS12_381) {
            // Public parameter
            pp = {
                curve: curve,
                epoch: {
                    start: new Date(new Date().setHours(0, 0, 0, 0)),
                    end: new Date(new Date().setHours(0, 0, 0, 0) + 24 * 60 * 60 * 1000)
                },
                SIG: {
                    signAlgo: 'rsa',
                    signAlgoLength: 2048,
                    hashAlgo: 'SHA256',
                },
                COM: {
                    g: null, h: null,
                }
            };
            return pp;
        },

        setupIdP: async function () {
            const member = [];
            const kpSIG = SIG.kGen(pp.SIG.signAlgoLength);
            await MMS.setup(pp.curve);
            const kpMMS = MMS.kGen(2);
            const {g, h} = await COM.setup(pp.curve);
            pp.COM.g = g;
            pp.COM.h = h;

            return {isk: {sk: kpSIG.sk, msk: kpMMS.sk}, member, ipk: {pk: kpSIG.pk, mpk: kpMMS.pk}}
        },

        join: function (ipk, rid) {
            const kpRP = SIG.kGen(pp.SIG.signAlgoLength);
            return {state: {kpRP: kpRP}, req: {rid: rid, rpk: kpRP.pk}}
        },

        reg: function (rid, member, req) {
            const {rpk} = req;
            if (member.find(rp => rp.rid === rid && rp.rpk === rpk))
                throw new Error('RP already registered');
            member.push({rid, rpk, i: member.length});
            return {state: {}, res: {}};
        },

        credReq: function (ipk, rid, rsk, sid, ep) {
            const sigmaRP = SIG.sign(rsk, sid);
            return {state: {}, req: {rid: rid, sigmaRP: sigmaRP}}
        },

        credIss: function (rid, isk, member, sid, ep, req) {
            const {sigmaRP} = req;
            const rp = member.find(rp => rp.rid === rid);
            if (rp === undefined || !SIG.vf(rp.rpk, sid, sigmaRP))
                throw new Error('Cannot verify RP signature');
            const sigmaIdP = MMS.sign(isk.msk, [rid, ep]);
            return {state: {}, res: {sigmaIdP: sigmaIdP}};
        },

        aInit: function (rid) {
            const {c, o} = COM.commit(pp.COM, rid);
            return {privU: o, pubU: c};
        },

        _randomizePSSignature: function (sigma) {
            const r = utils.getRandomZp(mcl);
            const t = utils.getRandomZp(mcl);
            const s1r = mcl.mul(sigma.one, r);
            const s2r = mcl.mul(sigma.two, r);
            const s1rt = mcl.mul(s1r, t);
            const s2rs1rt = mcl.add(s2r, s1rt);
            const rdmSig = {one: s1r, two: s2rs1rt};

            return {t: t, rdmSig: rdmSig};
        },

        // Naive NIZK generation without optimization; increase readability
        _genNIZKNotOptimized: function (ipk, rid, cred, uid, n, c, ep, o) {
            // Ensure commitment is well-formed
            if (!COM.open(pp.COM, rid, c, o))
                throw new Error('commitment does not open correctly');

            // Parse public parameter pp and ipk
            const g = pp.COM.g;
            const h = pp.COM.h;
            const gTilde = ipk.mpk.g;
            const Y1 = ipk.mpk.Y[0];
            const sessionElementsZp = utils.hashStringLstToZpLst(mcl, [uid, n, ep]);

            const ridZp = utils.hashToZp(mcl, rid);

            // Commitment announcement
            const uRid = utils.getRandomZp(mcl);
            const uH = utils.getRandomZp(mcl);
            const aC = mcl.add(mcl.mul(g, uRid), mcl.mul(h, uH));

            const {t, rdmSig} = this._randomizePSSignature(cred.sigmaIdP);

            // Signature announcement
            const uT = utils.getRandomZp(mcl);
            const aSig = mcl.mul(mcl.pow(mcl.pairing(rdmSig.one, Y1), uRid), mcl.pow(mcl.pairing(rdmSig.one, gTilde), uT));

            // Challenge
            const z = utils.hashToZp(mcl, '', c, aC, aSig, ...sessionElementsZp);

            // Responses
            const rRid = mcl.add(uRid, mcl.mul(ridZp, z));
            const rH = mcl.add(uH, mcl.mul(o, z));
            const rT = mcl.add(uT, mcl.mul(t, z));

            // pi
            return {sig: rdmSig, aC: aC, aSig: aSig, rRid: rRid, rH: rH, rT: rT};
        },

        // Optimization: Calculations of message randomizers (uY) are done in G2 before calculating the pairing
        _genNIZKOptimized: function (ipk, rid, cred, uid, n, c, ep, o) {
            // Ensure commitment is well-formed
            if (!COM.open(pp.COM, rid, c, o))
                throw new Error('commitment does not open correctly');

            // Parse public parameter pp and ipk
            const g = pp.COM.g;
            const h = pp.COM.h;
            const gTilde = ipk.mpk.g;
            const Y1 = ipk.mpk.Y[0];
            const sessionElementsZp = utils.hashStringLstToZpLst(mcl, [uid, n, ep]);

            const ridZp = utils.hashToZp(mcl, rid);

            // Commitment announcement
            const uRid = utils.getRandomZp(mcl);
            const uH = utils.getRandomZp(mcl);
            const aC = mcl.add(mcl.mul(g, uRid), mcl.mul(h, uH));

            const {t, rdmSig} = this._randomizePSSignature(cred.sigmaIdP);

            // Signature announcement
            const uT = utils.getRandomZp(mcl);

            // Moved uRid to G2 before calculating pairing
            const aSigG2 = mcl.add(mcl.mul(Y1, uRid), mcl.mul(gTilde, uT));
            const aSig = mcl.pairing(rdmSig.one, aSigG2);

            // Challenge
            const z = utils.hashToZp(mcl, '', c, aC, aSig, ...sessionElementsZp);

            // Responses
            const rRid = mcl.add(uRid, mcl.mul(ridZp, z));
            const rH = mcl.add(uH, mcl.mul(o, z));
            const rT = mcl.add(uT, mcl.mul(t, z));

            // pi
            return {sig: rdmSig, aC: aC, aSig: aSig, rRid: rRid, rH: rH, rT: rT};
        },

        // Naive NIZK verification without optimization; increase readability
        _vfNIZKNotOptimized: function (ipk, uid, n, ep, c, pi) {
            // Parse public parameter pp and ipk
            const g = pp.COM.g;
            const h = pp.COM.h;
            const gTilde = ipk.mpk.g;
            const X = ipk.mpk.X;
            const Y1 = ipk.mpk.Y[0];
            const Y2 = ipk.mpk.Y[1];
            const sessionElementsZp = utils.hashStringLstToZpLst(mcl, [uid, n, ep]);

            const z = utils.hashToZp(mcl, '', c, pi.aC, pi.aSig, ...sessionElementsZp);

            // commitment verification
            const lhsC = mcl.add(mcl.mul(c, z), pi.aC);
            const rhsC = mcl.add(mcl.mul(g, pi.rRid), mcl.mul(h, pi.rH));
            const comVerifies = lhsC.isEqual(rhsC);
            if (process.env.DEV && !comVerifies)
                console.log('commitment did not verify');

            // signature verification
            const epZp = utils.hashToZp(mcl, ep);
            const lhsP1 = mcl.pairing(pi.sig.two, gTilde);
            const lhsG2 = mcl.add(X, mcl.mul(Y2, epZp))
            const lhsP2 = mcl.pairing(pi.sig.one, lhsG2);
            const lhsP3 = mcl.mul(lhsP1, mcl.inv(lhsP2));
            const lhsP4 = mcl.mul(mcl.pow(lhsP3, z), pi.aSig);

            const rhsP1 = mcl.pow(mcl.pairing(pi.sig.one, Y1), pi.rRid);
            const rhsP2 = mcl.pow(mcl.pairing(pi.sig.one, gTilde), pi.rT);
            const rhsP3 = mcl.mul(rhsP1, rhsP2);

            const sigVerifies = lhsP4.isEqual(rhsP3);

            if (process.env.DEV && !sigVerifies)
                console.log('signature did not verify');

            return comVerifies && sigVerifies;
        },

        // Optimization: Calculations of the challenge (z) are moved to G1 and the revealed/hidden messages are moved to G2 before calculating the pairing
        _vfNIZKOptimized: function (ipk, uid, n, ep, c, pi) {
            // Parse public parameter pp and ipk
            const g = pp.COM.g;
            const h = pp.COM.h;
            const gTilde = ipk.mpk.g;
            const X = ipk.mpk.X;
            const Y1 = ipk.mpk.Y[0];
            const Y2 = ipk.mpk.Y[1];
            const sessionElementsZp = utils.hashStringLstToZpLst(mcl, [uid, n, ep]);

            const z = utils.hashToZp(mcl, '', c, pi.aC, pi.aSig, ...sessionElementsZp);

            // commitment verification
            const lhsC = mcl.add(mcl.mul(c, z), pi.aC);
            const rhsC = mcl.add(mcl.mul(g, pi.rRid), mcl.mul(h, pi.rH));
            const comVerifies = lhsC.isEqual(rhsC);
            if (!comVerifies)
                console.log('commitment did not verify');

            // signature verification
            const epZp = utils.hashToZp(mcl, ep);

            // Move z to G1; move ep to G2
            const lhsP1 = mcl.pairing(mcl.mul(pi.sig.two, z), gTilde);
            const lhsG2 = mcl.add(X, mcl.mul(Y2, epZp));
            const lhsP2 = mcl.pairing(mcl.mul(pi.sig.one, z), lhsG2);
            const lhsP3 = mcl.mul(lhsP1, mcl.inv(lhsP2));
            const lhsP4 = mcl.mul(lhsP3, pi.aSig);

            // Moved to G2
            const rhsG2 = mcl.add(mcl.mul(Y1, pi.rRid), mcl.mul(gTilde, pi.rT));
            const rhsP1 = mcl.pairing(pi.sig.one, rhsG2);

            const sigVerifies = lhsP4.isEqual(rhsP1);

            if (process.env.DEV && !sigVerifies)
                console.log('signature did not verify');

            return comVerifies && sigVerifies;
        },

        aReqRP: function (ipk, rid, cred, uid, pubU, privU, n, ep, optimized = false) {
            const cep = currentEpoch(pp.epoch.start, pp.epoch.end);

            if (ep !== cep || !COM.open(pp.COM, rid, pubU, privU))
                throw new Error('Epoch does not match or commitment does not match');

            const proof = {pi: null};
            if (!optimized) {
                proof.pi = this._genNIZKNotOptimized(ipk, rid, cred, uid, n, pubU, ep, privU);
            } else {
                proof.pi = this._genNIZKOptimized(ipk, rid, cred, uid, n, pubU, ep, privU);
            }
            return proof
        },

        aResIdP: function (ipk, isk, member, uid, ctx, authRP, pubU, n, ep, optimized = false) {
            let proofIsValid = false;
            if (!optimized) {
                proofIsValid = this._vfNIZKNotOptimized(ipk, uid, n, ep, pubU, authRP.pi);
            } else {
                proofIsValid = this._vfNIZKOptimized(ipk, uid, n, ep, pubU, authRP.pi);
            }

            if (!proofIsValid)
                throw new Error('RP authentication failed');

            return SIG.sign(isk.sk, 'test-token');
        },

        aFin: function (ipk, rid, uid, ctx, pubU, privU, n, ep, token) {
            if (!SIG.vf(ipk.pk, 'test-token', token) || !COM.open(pp.COM, rid, pubU, privU))
                throw new Error('IdP token signature does not verify or the commitment to rid is incorrect');
            return {t: token, c: pubU, o: privU};
        },

        vf: function (ipk, rid, uid, ctx, n, ep, tid) {
            return SIG.vf(ipk.pk, 'test-token', tid.t) && COM.open(pp.COM, rid, tid.c, tid.o);
        },

    };
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        AIF_ZKP: AuthenticatedImplicitFlowZKPScheme()
    };
}