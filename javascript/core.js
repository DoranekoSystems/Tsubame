const COMPRESSION_LZ4 = 0x100;
const COMPRESSION_LZ4_RAW = 0x101;
const COMPRESSION_ZLIB = 0x205;
const COMPRESSION_LZMA = 0x306;
const COMPRESSION_LZFSE = 0x801;
const COMPRESSION_BROTLI = 0xb02;

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
var g_maxThread = 10;
g_Buffer = Memory.alloc(1048576 * g_maxThread);
g_dstBuffer = Memory.alloc(1048576 * g_maxThread);

function ReadProcessMemory_Init() {
  console.log('RPM_CUSTOM_INIT');
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
      console.log('ReadProcessMemory_Custom Enabled!!');
    }
  },
  getinfo: function () {
    var pid = Process.id;
    var info = { pid: pid };
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
  virtualqueryexfull: function () {
    var regionList = Process.enumerateRanges('r--');
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
          } catch (e) { }
        } else if (target_os == 'android' && ignore_mapped_file) {
          try {
            if (regionList[i].file.path) {
              skip_flag = true;
            }
          } catch (e) { }
        }
        if (!skip_flag) {
          regionInfos.push([baseaddress, size]);
        } else {
        }
      } catch (e) { }
    }
    return regionInfos;
  },
  memoryscan: function (base, size, pattern) {
    try {
      var scanSync = Memory.scanSync(ptr(base), size, pattern);
    } catch (e) {
      return null;
    }
    return scanSync
  }
};
