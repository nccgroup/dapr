"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const _ = require("lodash");
const assert = require("assert");
class Expression {
    constructor(text) {
        this.position = 0;
        this.parseTree = null;
        this.tokens = this.tokenize(text.trim());
        this.parseTree = this.parseExpr();
        console.log(this.parseTree);
    }
    peek() {
        return this.tokens[this.position];
    }
    consume(token) {
        assert.strictEqual(token, this.tokens[this.position]);
        this.position++;
    }
    tokenize(text) {
        const results = [];
        const tokenRegExp = /\s*([A-Za-z_][A-Za-z_0-9]*|[0-9]+|\S)\s*/g;
        let m;
        while ((m = tokenRegExp.exec(text)) !== null) {
            results.push(m[1]);
        }
        return results;
    }
    parsePrimaryExpr() {
        var t = this.peek();
        if (this.isNumber(t)) {
            this.consume(t);
            return { type: 'number', value: t };
        }
        else if (this.isName(t)) {
            this.consume(t);
            return { type: 'name', id: t };
        }
        else if (t === '(') {
            this.consume(t);
            var expr = this.parseExpr();
            if (this.peek() !== ')')
                throw new SyntaxError('expected )');
            this.consume(')');
            return expr;
        }
        else {
            throw new SyntaxError(`expected a number, a variable, or parentheses`);
        }
    }
    parseMulExpr() {
        var expr = this.parsePrimaryExpr();
        var t = this.peek();
        while (t === '*' || t === '/') {
            this.consume(t);
            var rhs = this.parsePrimaryExpr();
            expr = { type: t, left: expr, right: rhs };
            t = this.peek();
        }
        return expr;
    }
    parseExpr() {
        var expr = this.parseMulExpr();
        var t = this.peek();
        while (t === '+' || t === '-') {
            this.consume(t);
            var rhs = this.parseMulExpr();
            expr = { type: t, left: expr, right: rhs };
            t = this.peek();
        }
        return expr;
    }
    isNumber(token) {
        return token !== undefined && token.match(/^[0-9]+$/) !== null;
    }
    isName(token) {
        return token !== undefined && token.match(/^[A-Za-z][A-Za-z_0-9]*$/) !== null;
    }
    evaluate(obj, struct) {
        this.position = 0;
        switch (obj.type) {
            case 'name':
                const field = _.find(struct.fields, f => f.name === obj.id);
                if (!field) {
                    throw new Error(`Field ${obj.id} does not exist`);
                }
                return field.value;
                break;
            case '+': return this.evaluate(obj.left, struct) + this.evaluate(obj.right, struct);
            case '-': return this.evaluate(obj.left, struct) - this.evaluate(obj.right, struct);
            case '*': return this.evaluate(obj.left, struct) * this.evaluate(obj.right, struct);
            case '/': return this.evaluate(obj.left, struct) / this.evaluate(obj.right, struct);
        }
    }
    eval(struct) {
        return this.evaluate(this.parseTree, struct);
    }
}
exports.Expression = Expression;
//# sourceMappingURL=expression.js.map