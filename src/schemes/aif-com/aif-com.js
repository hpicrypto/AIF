const {SIG} = require("../../building-blocks/sig/rsa");
const {COM} = require("../../building-blocks/com/pc");
const {BLS12_381} = require("mcl-wasm");

function AuthenticatedImplicitFlowCOMScheme() {
    "use strict";
    let pp;

    return {

        setup: function () {

            // Public parameter
            pp = {
                curve: BLS12_381,
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
                },
            };
            return pp;
        },

        setupIdP: async function () {
            const member = [];
            const kpSIG = SIG.kGen(pp.SIG.signAlgoLength);
            const {g, h} = await COM.setup(pp.curve);
            pp.COM.g = g;
            pp.COM.h = h;

            return {isk: {sk: kpSIG.sk}, member, ipk: {pk: kpSIG.pk}}
        },

        join: function (ipk, rid) {
            return {state: {}, req: {rid: rid}}
        },

        reg: function (rid, member, req) {
            if (member.find(rp => rp.rid === rid) !== undefined)
                throw new Error('RP already registered');

            member.push({rid, i: member.length});

            return {state: {}, res: {}};
        },

        credReq: function (ipk, rid, rsk, sid, ep) {
            return {state: {}, req: {rid: rid}}
        },

        credIss: function (rid, isk, M, sid, ep, req) {
            return {state: {}, res: {}};
        },

        aInit: function (rid) {
            const {c, o} = COM.commit(pp.COM, rid);
            return {privU: o, pubU: c};
        },

        aReqRP: function (ipk, rid, cred, uid, pubU, privU, n, e) {
            return '';
        },

        aResIdP: function (ipk, isk, member, uid, ctx, authRP, pubU, n, e) {
            return SIG.sign(isk.sk, ''.concat([pubU.serializeToHexStr(), uid, ctx, n, e]));
        },

        aFin: function (ipk, rid, uid, ctx, pubU, privU, n, e, token) {
            if (!SIG.vf(ipk.pk, ''.concat([pubU.serializeToHexStr(), uid, ctx, n, e]), token) || !COM.open(pp.COM, rid, pubU, privU))
                throw new Error('IdP token signature does not verify or the commitment to rid is incorrect');
            return {t: token, c: pubU, o: privU};
        },

        vf: function (ipk, rid, uid, ctx, n, e, tid) {
            return SIG.vf(ipk.pk, ''.concat([tid.c.serializeToHexStr(), uid, ctx, n, e]), tid.t) && COM.open(pp.COM, rid, tid.c, tid.o);
        },
    };
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        AIF_COM: AuthenticatedImplicitFlowCOMScheme()
    };
}