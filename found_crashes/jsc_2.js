function f(arguments) {
var arguments;
f.apply(null, ['']);
}
f('')

// also on safari
// https://bugs.webkit.org/show_bug.cgi?id=141028
