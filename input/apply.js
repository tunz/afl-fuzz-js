function g() {}
function f() {
debugger;
g.apply(null, ['']);
}
f()
