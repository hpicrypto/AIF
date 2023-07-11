const NodeRSA = require('node-rsa')

function RSAWrapper() {
    "use strict";

    const kp = {pk: null, sk: null};
    const RSA = new NodeRSA();

    return {

        // loadKeys: function (pk, sk = '') {
        //   RSA.importKey(pk);
        //   if (sk !== '')
        //     RSA.importKey(sk);
        // },

        kGen: function (secPar) {
            if (process.env.WITHOUT_RSA === '1')
                return kp;

            RSA.generateKeyPair(secPar);
            kp.sk = RSA.exportKey('pkcs8');
            kp.pk = RSA.exportKey('pkcs8-public');

            return kp;
        },

        sign: function (sk, m) {
            if (process.env.WITHOUT_RSA === '1')
                return {};

            if (sk !== kp.sk) {
                RSA.importKey(sk);
                kp.pk = null;
                kp.sk = sk;
            }

            return RSA.sign(m);
        },

        vf: function (pk, m, sigma) {
            if (process.env.WITHOUT_RSA === '1')
                return true;

            if (pk !== kp.pk) {
                RSA.importKey(pk);
                kp.pk = pk;
            }

            return RSA.verify(m, sigma);
        }
    };
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        SIG: RSAWrapper()
    };
}