function getRandomZp(mcl) {
    const r = new mcl.Fr();
    r.setByCSPRNG();
    return r;
}

function getRndGeneratorG1(mcl) {
    const r = getRandomZp(mcl);
    return mcl.hashAndMapToG1(r.getStr());
}

function getRndGeneratorG2(mcl) {
    const r = getRandomZp(mcl);
    return mcl.hashAndMapToG2(r.getStr());
}

// Takes string m and elements (Fr, G1, G2), concatenates their bytes, and hashes them to Fr.
function hashToZp(mcl, m, ...elements) {
    const bytes = elements.map(e => e.serialize()).flat();
    bytes.push(new TextEncoder().encode(m));

    let l = 0;
    for (const i in bytes)
        l += bytes[i].length;

    const hashInput = new Uint8Array(l);
    let offset = 0;
    for (const i in bytes) {
        hashInput.set(bytes[i], offset);
        offset += bytes[i].length;
    }

    return mcl.hashToFr(hashInput);
}

function hashStringLstToZpLst(mcl, strLst) {
    const zpLst = [];
    let b;

    for (const i in strLst) {
        b = new TextEncoder().encode(strLst[i]);
        zpLst.push(mcl.hashToFr(b));
    }

    return zpLst;
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        getRandomZp,
        hashToZp,
        hashStringLstToZpLst,
        getRndGeneratorG1,
        getRndGeneratorG2,
    };
}