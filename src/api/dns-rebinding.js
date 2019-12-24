var _this = this;
dnsRebinding = function (req, res, next) {
    if (req.headers.host !== "localhost:" + _this.port &&
        req.headers.host !== "127.0.0.1:" + _this.port) {
        next("DNS rebinding attack blocked");
    }
    else {
        next();
    }
};
