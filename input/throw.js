(function() {
var a = 1, b = 2;
for(var i = 0; i < 1e5; i++) {
 if(a === b) {
  throw new Error;
 }
}
})();
