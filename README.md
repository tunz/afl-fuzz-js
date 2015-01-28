It is custom version of [afl-fuzz](http://lcamtuf.coredump.cx/afl/).

What is new experimentals in this custom fuzzer?
------------------------------------------------

1. Comment method

  This fuzzer is only targeting javascript. 
  So, we can extract keywords using comment.

  For example, If we test this one,

  ```js
  function abc() { print(1); }
  ```

  then, comment method will check like this.
  ```js
  /**/f/*unction abc() { print(1); }*/
  ```
  ```js
  /**/fu/*nction abc() { print(1); }*/
  ```
  ```js
  /**/fun/*ction abc() { print(1); }*/
  ```

  Then, at this point, the program flow will be changed.

  ```js
  /**/function/* abc() { print(1); }*/
  ```
  now, it saves 'function' as dictionary.

2. Threshold model

  If the program is using thread, then execution path will be changed.

  So, we ignore small change of execution path which can be caused by thread.

  But, Disadvantage of this model is that we cannot detect real small flow changes.
  We can only detect huge flow changes.

3. Speed improvement using ptrace

  The idea is come from Michal Zalewski's todo list.

  If we can make fork server after skipping initialization process, 
  fuzzer speed will be improved.

  I tried this idea using ptrace.

  First, Find first read or open point, which reads our input.
  After remembering the latest point before reading,
  restart application, and then make forkserver at the found point.

  This way is pretty good working in JavaScriptCore.
  Performance increases 2.5x

  But, in v8 case, v8 reads input on new thread.
  It is hard to make forkserver on new thread.
  There may be similar problems.
  So, this problem should be fixed.
