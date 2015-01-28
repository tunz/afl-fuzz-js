c = 30000;
a = [];
for (i = 0; i < 2 * c; i += 1) {
  a.push(i%c);
}
a.sort(function (x, y) { return x - y; });
print(a[2 * c - 2]);
