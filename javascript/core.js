function dump(pointer, length) {
  var buf = Memory.readByteArray(pointer, length);
  console.log(
    hexdump(buf, {
      offset: 0,
      length: length,
      header: true,
      ansi: true,
    })
  );
}

function b2s(array) {
  var result = '';
  for (var i = 0; i < array.length; i++) {
    result += String.fromCharCode(modulus(array[i], 256));
  }
  return result;
}

function zeroPadding(NUM, LEN) {
  return (Array(LEN).join('0') + NUM).slice(-LEN);
}

const COMPRESSION_LZ4 = 0x100;
const COMPRESSION_LZ4_RAW = 0x101;
const COMPRESSION_ZLIB = 0x205;
const COMPRESSION_LZMA = 0x306;
const COMPRESSION_LZFSE = 0x801;
const COMPRESSION_BROTLI = 0xb02;

const PS = Process.pointerSize;

var mach_task_self;
var mach_vm_read_overwrite;
var compression_encode_buffer;

var process_vm_readv;
var process_vm_writev;
var LZ4_compress_default;
var LZ4_compressBound;
var LZ4_compress_fast;

var g_Buffer;
var g_dstBuffer;
var g_Task;
var g_Mutex = true;

//Up to 10 threads can be handled simultaneously
var g_maxThread = 2;
g_Buffer = Memory.alloc(1048576 * g_maxThread);
g_dstBuffer = Memory.alloc(1048576 * g_maxThread);

function ReadProcessMemory_Init() {
  //console.log('RPM_CUSTOM_INIT');
  //iOS
  if (target_os == 'ios') {
    var mach_task_selfPtr = Module.findExportByName(null, 'mach_task_self');
    var mach_vm_read_overwritePtr = Module.findExportByName(null, 'mach_vm_read_overwrite');

    mach_task_self = new NativeFunction(mach_task_selfPtr, 'pointer', []);
    mach_vm_read_overwrite = new NativeFunction(mach_vm_read_overwritePtr, 'int', [
      'pointer',
      'long',
      'int',
      'pointer',
      'pointer',
    ]);

    var compression_encode_bufferPtr = Module.findExportByName(null, 'compression_encode_buffer');
    compression_encode_buffer = new NativeFunction(compression_encode_bufferPtr, 'int', [
      'pointer',
      'int',
      'pointer',
      'int',
      'pointer',
      'int',
    ]);
    g_Task = mach_task_self();
  }
  //Android
  else {
    Module.load('liblz4.so');

    var LZ4_compress_defaultPtr = Module.findExportByName('liblz4.so', 'LZ4_compress_default');
    LZ4_compress_default = new NativeFunction(LZ4_compress_defaultPtr, 'int', [
      'pointer',
      'pointer',
      'int',
      'int',
    ]);
    var LZ4_compress_fastPtr = Module.findExportByName('liblz4.so', 'LZ4_compress_default');
    LZ4_compress_fast = new NativeFunction(LZ4_compress_fastPtr, 'int', [
      'pointer',
      'pointer',
      'int',
      'int',
      'int',
    ]);
    var LZ4_compressBoundPtr = Module.findExportByName('liblz4.so', 'LZ4_compressBound');
    LZ4_compressBound = new NativeFunction(LZ4_compressBoundPtr, 'int', ['int']);
    var process_vm_readvPtr = Module.findExportByName(null, 'process_vm_readv');
    process_vm_readv = new NativeFunction(process_vm_readvPtr, 'int', [
      'int',
      'pointer',
      'int',
      'pointer',
      'int',
      'int',
    ]);
  }
}

var loop_count = 0;
function ReadProcessMemory_Custom(address, size) {
  loop_count++;
  var start_offset = (loop_count % g_maxThread) * 1048576;
  //iOS
  if (Process.platform == 'darwin') {
    var size_out = Memory.alloc(8);
    mach_vm_read_overwrite(g_Task, address, size, g_Buffer.add(start_offset), size_out);
    if (size_out.readUInt() == 0) {
      return false;
    } else {
      var compress_size = compression_encode_buffer(
        g_dstBuffer.add(start_offset),
        size,
        g_Buffer.add(start_offset),
        size,
        ptr(0),
        COMPRESSION_LZ4
      );
      var ret = ArrayBuffer.wrap(g_dstBuffer.add(start_offset), compress_size);
      return ret;
    }
  }
  //Android
  else {
    var local = Memory.alloc(32);
    var remote = Memory.alloc(32);
    local.writePointer(g_Buffer.add(start_offset));
    local.add(PS).writeUInt(size);
    remote.writePointer(ptr(address));
    remote.add(PS).writeUInt(size);
    var size_out = process_vm_readv(Process.id, local, 1, remote, 1, 0);
    if (size_out == -1) {
      return false;
    } else {
      var dstCapacity = LZ4_compressBound(size_out);
      var compress_size = LZ4_compress_default(
        g_Buffer.add(start_offset),
        g_dstBuffer.add(start_offset),
        size_out,
        dstCapacity
      );
      var ret = ArrayBuffer.wrap(g_dstBuffer.add(start_offset), compress_size + 4);
      g_dstBuffer.add(start_offset + compress_size).writeUInt(size_out);
      return ret;
    }
  }
}

var custom_read_memory = false;
var ignore_mapped_file = false;
var target_os = '';
rpc.exports = {
  setconfig: function (config) {
    custom_read_memory = config['extended_function']['custom_read_memory'];
    ignore_mapped_file = config['extended_function']['ignore_mapped_file'];
    target_os = config['general']['targetOS'];
    if (custom_read_memory && ['android', 'ios'].indexOf(target_os != -1)) {
      ReadProcessMemory_Init();
      //console.log('ReadProcessMemory_Custom Enabled!!');
    }
  },
  getinfo: function () {
    var info = { pid: Process.id, arch: Process.arch };
    return info;
  },
  readprocessmemory: function (address, size, flag) {
    try {
      if (ptr(address).isNull() == false) {
        if (custom_read_memory && ['android', 'ios'].indexOf(target_os) != -1 && flag) {
          var ret = ReadProcessMemory_Custom(address, size);
        } else {
          var ret = Memory.readByteArray(ptr(address), size);
        }
        return ret;
      } else {
        return false;
      }
    } catch (e) {
      return false;
    }
  },
  writeprocessmemory: function (address, buffer) {
    try {
      if (ptr(address).isNull() == false) {
        Memory.protect(ptr(address), buffer.length, 'rwx');
        return Memory.writeByteArray(ptr(address), buffer, buffer.length);
      } else {
        return false;
      }
    } catch (e) {
      console.log(e);
      return false;
    }
  },
  virtualqueryexfull: function (protect) {
    var regionList = Process.enumerateRanges(protect);
    var regionSize = Object.keys(regionList).length;
    var regionInfos = [];
    for (var i = 0; i < regionSize; i++) {
      var baseaddress = parseInt(regionList[i].base);
      var size = parseInt(regionList[i].size);
      try {
        var skip_flag = false;
        if (target_os == 'ios' && ignore_mapped_file) {
          try {
            if (regionList[i].file.path) {
              skip_flag = true;
            }
          } catch (e) {}
        } else if (target_os == 'android' && ignore_mapped_file) {
          try {
            if (regionList[i].file.path) {
              skip_flag = true;
            }
          } catch (e) {}
        }
        if (!skip_flag) {
          regionInfos.push([baseaddress, size]);
        } else {
        }
      } catch (e) {}
    }
    return regionInfos;
  },
  memoryscan: function (base, size, pattern) {
    try {
      var scanSync = Memory.scanSync(ptr(base), size, pattern);
    } catch (e) {
      return null;
    }
    return scanSync;
  },
  memoryfilter: function (address_infos) {
    var filterd = [];
    for (var i = 0; i < address_infos.length; i++) {
      var address_info = address_infos[i];
      var address = address_info[0];
      var size = address_info[1];
      var bytecode = address_info[2].replaceAll(' ', '');
      var bytes = Memory.readByteArray(ptr(address), size);
      var b = new Uint8Array(bytes);
      var str = '';
      for (var j = 0; j < b.length; j++) {
        str += zeroPadding(b[j].toString(16), 2);
      }
      var flag = true;
      for (var j = 0; j < bytecode.length; j++) {
        if (str[j] != bytecode[j] && bytecode[j] != '?') {
          flag = false;
          break;
        }
      }
      if (flag) {
        filterd.push({ address: address.toString(16), size: size });
      }
    }
    if (filterd.length == 0) return null;
    return filterd;
  },
  getsymbol: function (addresses) {
    var symbolinfo = [];
    for (var i = 0; i < addresses.length; i++) {
      var modulename = DebugSymbol.fromAddress(ptr(addresses[i])).moduleName;
      var address_str = DebugSymbol.fromAddress(ptr(addresses[i])).address;
      if (modulename == null) {
        symbolinfo.push(address_str);
      } else {
        var base = Process.findModuleByName(modulename).base;
        symbolinfo.push(`${modulename}!${(addresses[i] - base).toString(16)}`);
      }
    }
    return symbolinfo;
  },
  getmodule: function (name) {
    try {
      var module = Process.findModuleByName(name);
      return [module.name, module.base, module.size];
    } catch (e) {
      console.log(e);
      return false;
    }
  },
  enummodules:function(){
    return Process.enumerateModules();
  },
};
