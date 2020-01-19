import * as _ from "lodash";
import * as assert from "assert";

export class Expression {
  private position: number = 0;
  private tokens: string[];
  private parseTree: any = null;

  constructor(text: string) {
    this.tokens = this.tokenize(text.trim());
    this.parseTree = this.parseExpr();
    console.log(this.parseTree);
  }
  private peek(): string {
    return this.tokens[this.position];
  }
  private consume(token: string): void {
    assert.strictEqual(token, this.tokens[this.position]);
    this.position++;
  }
  private tokenize(text: string): string[] {
    const results = [];
    const tokenRegExp = /\s*([A-Za-z_][A-Za-z_0-9]*|[0-9]+|\S)\s*/g;
    let m;
    while ((m = tokenRegExp.exec(text)) !== null) {
      results.push(m[1]);
    }
    return results;
  }
  private parsePrimaryExpr(): any {
    var t = this.peek();

    if (this.isNumber(t)) {
      this.consume(t);
      return { type: "number", value: t };
    } else if (this.isName(t)) {
      this.consume(t);
      return { type: "name", id: t };
    } else if (t === "(") {
      this.consume(t);
      var expr = this.parseExpr();
      if (this.peek() !== ")") throw new SyntaxError("expected )");
      this.consume(")");
      return expr;
    } else {
      throw new SyntaxError(`expected a number, a variable, or parentheses`);
    }
  }
  private parseMulExpr(): any {
    var expr = this.parsePrimaryExpr();
    var t = this.peek();
    while (t === "*" || t === "/") {
      this.consume(t);
      var rhs = this.parsePrimaryExpr();
      expr = { type: t, left: expr, right: rhs };
      t = this.peek();
    }
    return expr;
  }
  private parseExpr(): any {
    var expr = this.parseMulExpr();
    var t = this.peek();
    while (t === "+" || t === "-") {
      this.consume(t);
      var rhs = this.parseMulExpr();
      expr = { type: t, left: expr, right: rhs };
      t = this.peek();
    }
    return expr;
  }
  private isNumber(token: string): boolean {
    return token !== undefined && token.match(/^[0-9]+$/) !== null;
  }
  private isName(token: string): boolean {
    return (
      token !== undefined && token.match(/^[A-Za-z][A-Za-z_0-9]*$/) !== null
    );
  }
  private evaluate(obj: any, struct: Struct): any {
    this.position = 0;
    switch (obj.type) {
      case "name":
        const field = _.find(struct.fields, f => f.name === obj.id);
        if (!field) {
          throw new Error(`Field ${obj.id} does not exist`);
        }
        return field.value;
        break;
      case "+":
        return (
          this.evaluate(obj.left, struct) + this.evaluate(obj.right, struct)
        );
      case "-":
        return (
          this.evaluate(obj.left, struct) - this.evaluate(obj.right, struct)
        );
      case "*":
        return (
          this.evaluate(obj.left, struct) * this.evaluate(obj.right, struct)
        );
      case "/":
        return (
          this.evaluate(obj.left, struct) / this.evaluate(obj.right, struct)
        );
    }
  }
  public eval(struct: SharedTypes.Struct): any {
    return this.evaluate(this.parseTree, struct);
  }
}
