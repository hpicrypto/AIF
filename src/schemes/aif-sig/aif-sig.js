const {SIG} = require("../../building-blocks/sig/rsa");
const {currentEpoch} = require("../../../tests/schemes/func-mocks");

function AuthenticatedImplicitFlowSIGScheme() {
    "use strict";

    let pp;

    return {

        setup: function () {
            // Public parameter
            pp = {
                epoch: {
                    start: new Date(new Date().setHours(0, 0, 0, 0)),
                    end: new Date(new Date().setHours(0, 0, 0, 0) + 24 * 60 * 60 * 1000)
                },
                SIG: {
                    signAlgo: 'rsa',
                    signAlgoLength: 2048,
                    hashAlgo: 'SHA256',
                },
            };
            return pp;
        },

        setupIdP: async function () {
            const member = [];
            const kpSIG = SIG.kGen(pp.SIG.signAlgoLength);

            return {isk: {sk: kpSIG.sk}, member, ipk: {pk: kpSIG.pk}}
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
            const sigmaRP = SIG.sign(rsk, '0'.concat(sid));
            return {state: {}, req: {rid: rid, sigmaRP: sigmaRP}}
        },

        credIss: function (rid, isk, member, sid, ep, req) {
            const {sigmaRP} = req;
            const rp = member.find(rp => rp.rid === rid);
            if (rp === undefined || !SIG.vf(rp.rpk, '0'.concat(sid), sigmaRP))
                throw new Error('Cannot verify RP signature');
            member[rp.i] = {rid: rp.rid, rpk: rp.rpk, i: rp.i, ep: ep};
            return {state: {}, res: {}};
        },

        aInit: function (rid) {
            return {privU: '', pubU: ''};
        },

        aReqRP: function (ipk, rid, cred, uid, pubU, privU, n, ep) {
            if (ep !== cred.ep || privU !== '')
                throw new Error('Epoch does not match or public user parameter not empty');
            return {
                rid: rid, sigma: SIG.sign(cred.rsk, '1'.concat([uid, n, pubU]))
            }
        },

        aResIdP: function (ipk, isk, member, uid, ctx, authRP, pubU, n, ep) {
            const rp = member.find(rp => rp.rid === authRP.rid);
            if (rp === undefined || !SIG.vf(rp.rpk, '1'.concat([uid, n, pubU]), authRP.sigma) || rp.ep !== ep)
                throw new Error('RP authentication failed');
            return SIG.sign(isk.sk, ''.concat([rp.rid, uid, ctx, n, ep]));
        },

        aFin: function (ipk, rid, uid, ctx, pubU, privU, n, ep, token) {
            if (!SIG.vf(ipk.pk, ''.concat([rid, uid, ctx, n, ep]), token))
                throw new Error('IdP token signature does not verify');
            return {t: token};
        },

        vf: function (ipk, rid, uid, ctx, n, ep, tid) {
            return SIG.vf(ipk.pk, ''.concat([rid, uid, ctx, n, ep]), tid.t);
        },
    };
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        AIF_SIG: AuthenticatedImplicitFlowSIGScheme()
    };
}