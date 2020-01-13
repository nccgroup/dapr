var SharedTypes;
(function (SharedTypes) {
    var Mode;
    (function (Mode) {
        Mode[Mode["READ"] = 0] = "READ";
        Mode[Mode["WRITE"] = 1] = "WRITE";
        Mode[Mode["READ_WRITE"] = 2] = "READ_WRITE";
        Mode[Mode["UNSURE"] = 3] = "UNSURE";
    })(Mode = SharedTypes.Mode || (SharedTypes.Mode = {}));
})(SharedTypes || (SharedTypes = {}));
