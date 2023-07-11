function bench(label, count, func) {
    const start = performance.now()
    for (let i = 0; i < count; i++) {
        func()
    }
    const end = performance.now()
    const t = (end - start) / count
    const roundTime = (Math.round(t * 1000)) / 1000
    console.log(`${label} = ${roundTime} ms`);
}

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = {
        bench,
    };
}