const {generateRid} = require('./func-mocks');

// ********* Fixtures for testing *********

const fixtures = {
    uid: 'jon@doe.com',
    ctx: 'some-context-data',
    rid: generateRid('Example-RP-Name', 'https://example-rp-domain.com/'),
};

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        fixtures,
    };
}