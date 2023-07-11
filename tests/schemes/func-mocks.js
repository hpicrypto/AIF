const crypto = require("crypto");

// ********* Mock functionality for testing *********

// Take RP name and redirection URI
// https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
function generateRid(name, ruri) {
    const input = name.concat(ruri);
    return crypto.createHash('sha256').update(input, 'binary').digest('base64');
}

function generateNonce() {
    return crypto.randomBytes(16).toString('base64')
}

// return current epoch, e.g, last timestamp when epoch valid
function currentEpoch(start, end) {
    return ''.concat(start, '-', end);
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        generateRid,
        generateNonce,
        currentEpoch,
    };
}