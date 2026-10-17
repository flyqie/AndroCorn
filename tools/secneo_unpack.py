#!/usr/bin/env python3
"""SecNeo（梆梆安全）加固 APK 的通用脱壳工具。

用法::

    python secneo_unpack.py <app.apk> [-o unpacked] [--arch arm64]

流程（全部在用户态模拟器里完成，不需要真机/root）：

1. 从 APK 里取出 ``classes.dex`` 和 ``lib/<abi>/libDexHelper.so``；
2. 解析壳 dex，读出 ``com.secneo.apkwrapper.H`` 的静态字段与 ``<clinit>``
   写入的初值——这些是壳驱动 native 侧所需的 Java 上下文；
3. 用 AndroCorn（androidemu）加载壳 ``libDexHelper.so``，跑完它的
   ``init_array``；壳会自己解出内层 DexHelper 并 mmap 到匿名内存；
4. 在内存里找到内层 ELF，解析其动态符号表拿到 ``JNI_OnLoad``；
5. 以 ``JavaVM*`` 调用 ``JNI_OnLoad``，注册 21 个 native 方法；
6. 如果壳在保护逻辑里解引用空指针（它假定 ART 运行时一定存在），
   工具会自动定位那次符号查询并安装一个"假 ART 符号"垫片后重试；
7. 扫描整片内存，收集所有通过 SHA-1/Adler-32 校验的 dex，去重后
   打包成 multidex zip。

依赖（均已包含在仓库里）：

* ``AndroCorn`` —— 本工具所在的同级目录，或用 ``ANDROCORN_DIR`` 指定；
* 已应用的 AndroCorn 补丁：``pread64``、fork 的 ``getpid`` 语义、
  JNI 字段返回 NULL 时写 X0、``LongArray``、``DexCache`` 等
  （见同目录的 ``secneo_unpack.md``）。

限制：这是面向 SecNeo（DexHelper）家族的脱壳器。换壳/换代次时，
Java 侧的类名与字段名可能变化，用 ``--wrapper-class`` 调整。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import shutil
import struct
import sys
import zipfile
import zlib
from pathlib import Path

# 加固壳反调试失败时会 kill(getpid(), SIGKILL)；脱壳需要在自毁后继续。
os.environ.setdefault("ANDROCORN_IGNORE_SELFKILL", "1")


def _find_androcorn() -> Path:
    env = os.environ.get("ANDROCORN_DIR")
    if env:
        return Path(env).resolve()
    here = Path(__file__).resolve()
    for cand in (
        here.parent,                       # 直接放在 AndroCorn/tools/ 下
        here.parent.parent,                # 放在 AndroCorn/ 下
        here.parent.parent / "AndroCorn",  # 与 tools/ 同级的仓库
        here.parent / "AndroCorn",
        Path.cwd() / "AndroCorn",
    ):
        if (cand / "androidemu" / "__init__.py").exists():
            return cand
    raise SystemExit("找不到 AndroCorn，请用 ANDROCORN_DIR 环境变量指定其路径")


sys.path.insert(0, str(_find_androcorn()))

from unicorn import (  # noqa: E402
    UcError,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
)
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_LR,
    UC_ARM64_REG_PC,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
)

from androidemu.const import emu_const  # noqa: E402
from androidemu.core.emulator import Emulator  # noqa: E402
from androidemu.java.class_def import JavaClassDef  # noqa: E402
from androidemu.java.field_def import JavaFieldDef  # noqa: E402
from androidemu.java.classloader import JavaClassLoader  # noqa: E402
from androidemu.java.classes.android.app.application import Application  # noqa: E402
from androidemu.java.classes.android.content.package_manager import ApplicationInfo  # noqa: E402
from androidemu.java.classes.dalvik.system.dex_utils import (  # noqa: E402
    BaseDexClassLoader,
    DexFile,
    DexPathList,
    DexPathListElement,
    InMemoryDexClassLoader,
)
from androidemu.java.classes.java.io.file import File as JavaFile  # noqa: E402
from androidemu.java.classes.java.lang.array import LongArray  # noqa: E402
from androidemu.java.classes.java.lang.clazz import DexCache  # noqa: E402
from androidemu.java.classes.java.lang.string import String as JavaString  # noqa: E402
from androidemu.java.classes.java.lang.types import Boolean as JavaBoolean  # noqa: E402
from androidemu.utils.java.loader import load_mocks  # noqa: E402

log = logging.getLogger("secneo")

DEX_MAGICS = [b"dex\n035\x00", b"dex\n036\x00", b"dex\n037\x00",
              b"dex\n038\x00", b"dex\n039\x00", b"cdex001\x00"]


# ---------------------------------------------------------------------------
# 极简 DEX 解析（只为读出壳类的静态字段）
# ---------------------------------------------------------------------------


def _uleb(data: bytes, off: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7


class Dex:
    """够用的 DEX 读取器：字符串、类型、字段、类定义与 static_values。"""

    def __init__(self, data: bytes):
        self.data = data
        if data[:4] != b"dex\n":
            raise ValueError("不是 dex")
        g = lambda o: struct.unpack_from("<I", data, o)[0]  # noqa: E731
        self.n_str, self.off_str = g(56), g(60)
        self.n_type, self.off_type = g(64), g(68)
        self.n_field, self.off_field = g(80), g(84)
        self.n_method, self.off_method = g(88), g(92)
        self.n_cls, self.off_cls = g(96), g(100)
        self._strings: list[str] | None = None

    def string(self, idx: int) -> str:
        off = struct.unpack_from("<I", self.data, self.off_str + idx * 4)[0]
        _, p = _uleb(self.data, off)
        end = self.data.index(b"\x00", p)
        # MUTF-8 的 surrogate 对在这里不影响字段名
        return self.data[p:end].decode("utf-8", "replace")

    @property
    def strings(self) -> list[str]:
        if self._strings is None:
            self._strings = [self.string(i) for i in range(self.n_str)]
        return self._strings

    def type_at(self, idx: int) -> str:
        return self.string(struct.unpack_from("<I", self.data, self.off_type + idx * 4)[0])

    def field_at(self, idx: int) -> tuple[str, str]:
        # field_id_item = { ushort class_idx; ushort type_idx; uint name_idx; }
        base = self.off_field + idx * 8
        _class_idx, type_idx = struct.unpack_from("<HH", self.data, base)
        name_idx = struct.unpack_from("<I", self.data, base + 4)[0]
        return self.string(name_idx), self.type_at(type_idx)

    def field_ref(self, idx: int) -> tuple[str, str]:
        """返回 (宿主类描述符, 字段名)。"""
        base = self.off_field + idx * 8
        class_idx = struct.unpack_from("<H", self.data, base)[0]
        name_idx = struct.unpack_from("<I", self.data, base + 4)[0]
        return self.type_at(class_idx), self.string(name_idx)

    def _encoded_value(self, p: int):
        head = self.data[p]
        p += 1
        vtype, varg = head & 0x1F, head >> 5
        n = varg + 1
        if vtype == 0x1F:                      # BOOLEAN
            return ("bool", bool(varg)), p
        if vtype == 0x1E:                      # NULL
            return ("null", None), p
        raw = int.from_bytes(self.data[p:p + n], "little")
        if vtype == 0x17:                      # STRING
            return ("string", self.string(raw)), p + n
        if vtype in (0x00, 0x02, 0x03, 0x04):  # 整数
            signed = int.from_bytes(self.data[p:p + n], "little", signed=True)
            return ("int", signed), p + n
        if vtype == 0x18:                      # TYPE
            return ("type", self.type_at(raw)), p + n
        return (f"type{vtype:#x}", raw), p + n

    def static_fields(self, class_name: str) -> list[tuple[str, str, tuple]]:
        """返回 ``[(字段名, 类型描述符, 值), ...]``；无 static_values 时值为 None。"""
        for ci in range(self.n_cls):
            base = self.off_cls + ci * 32
            if self.type_at(struct.unpack_from("<I", self.data, base)[0]) != class_name:
                continue

            class_data_off = struct.unpack_from("<I", self.data, base + 24)[0]
            static_values_off = struct.unpack_from("<I", self.data, base + 28)[0]
            if not class_data_off:
                return []

            p = class_data_off
            sf, p = _uleb(self.data, p)
            p = _uleb(self.data, p)[1]   # instance fields
            p = _uleb(self.data, p)[1]   # direct methods
            p = _uleb(self.data, p)[1]   # virtual methods

            field_ids: list[int] = []
            fid = 0
            for _ in range(sf):
                diff, p = _uleb(self.data, p)
                fid += diff
                _acc, p = _uleb(self.data, p)
                field_ids.append(fid)

            values: list[tuple] = []
            if static_values_off:
                q = static_values_off
                count, q = _uleb(self.data, q)
                for _ in range(count):
                    value, q = self._encoded_value(q)
                    values.append(value)

            out = []
            for i, f in enumerate(field_ids):
                name, desc = self.field_at(f)
                out.append((name, desc, values[i] if i < len(values) else None))
            return out
        return []

    def _class_data_off(self, class_name: str) -> int | None:
        for ci in range(self.n_cls):
            base = self.off_cls + ci * 32
            if self.type_at(struct.unpack_from("<I", self.data, base)[0]) == class_name:
                return struct.unpack_from("<I", self.data, base + 24)[0] or None
        return None

    def _direct_methods(self, class_name: str) -> list[tuple[str, int]]:
        """返回 ``[(方法名, code_off), ...]``，只取 direct methods。"""
        off = self._class_data_off(class_name)
        if not off:
            return []
        p = off
        _sf, p = _uleb(self.data, p)
        _inf, p = _uleb(self.data, p)
        dm, p = _uleb(self.data, p)
        p = _uleb(self.data, p)[1]          # virtual methods 的个数

        # 跳过静态字段
        for _ in range(_sf):
            p = _uleb(self.data, p)[1]
            p = _uleb(self.data, p)[1]

        out = []
        midx = 0
        for _ in range(dm):
            diff, p = _uleb(self.data, p)
            midx += diff
            _acc, p = _uleb(self.data, p)
            code_off, p = _uleb(self.data, p)
            base = self.off_method + midx * 8
            name_idx = struct.unpack_from("<I", self.data, base + 4)[0]
            out.append((self.string(name_idx), code_off))
        return out

    def clinit_values(self, class_name: str) -> dict[str, tuple]:
        """从 ``<clinit>`` 的字节码里恢复静态字段初值。

        SecNeo 的壳类把初值写在 ``<clinit>`` 里（``static_values`` 为空）：
        ``const-string`` / ``const/4`` / ``sget-object`` / ``new-instance``
        之后紧跟 ``sput-object`` / ``sput``。这里按 DEX 指令格式（opcode 在
        低字节）逐条解码，维护一个小寄存器值表，遇到写壳类字段就记录。
        """
        code_off = None
        for name, off in self._direct_methods(class_name):
            if name == "<clinit>":
                code_off = off
                break
        if not code_off:
            return {}

        insns_size = struct.unpack_from("<I", self.data, code_off + 12)[0]
        start_off = code_off + 16
        units = list(struct.unpack_from(f"<{insns_size}H", self.data, start_off))
        n = len(units)

        regs: dict[int, tuple] = {}
        out: dict[str, tuple] = {}

        def put_field(field_idx: int, value: tuple) -> None:
            host, fname = self.field_ref(field_idx)
            if host == class_name:
                out[fname] = value

        i = 0
        while i < n:
            u0 = units[i]
            op = u0 & 0xFF
            aa = (u0 >> 8) & 0xFF

            if op == 0x1A and i + 1 < n:                      # const-string vAA, @BBBB
                regs[aa] = ("string", self.string(units[i + 1]))
                i += 2
                continue

            if op == 0x1B and i + 2 < n:                      # const-string/jumbo
                idx = units[i + 1] | (units[i + 2] << 16)
                regs[aa] = ("string", self.string(idx))
                i += 3
                continue

            if op == 0x12:                                    # const/4 vA, #+B
                a4 = (u0 >> 8) & 0xF
                lit = (u0 >> 12) & 0xF
                if lit & 0x8:
                    lit -= 0x10
                regs[a4] = ("int", lit)
                i += 1
                continue

            if op == 0x13 and i + 1 < n:                      # const/16 vAA, #+BBBB
                lit = struct.unpack("<h", struct.pack("<H", units[i + 1]))[0]
                regs[aa] = ("int", lit)
                i += 2
                continue

            if op == 0x14 and i + 2 < n:                      # const vAA, #+BBBBBBBB
                raw = units[i + 1] | (units[i + 2] << 16)
                regs[aa] = ("int", struct.unpack("<i", struct.pack("<I", raw))[0])
                i += 3
                continue

            if op == 0x22 and i + 1 < n:                      # new-instance vAA, type@BBBB
                regs[aa] = ("obj", self.type_at(units[i + 1]))
                i += 2
                continue

            if op == 0x62 and i + 1 < n:                      # sget-object vAA, field@BBBB
                host, fname = self.field_ref(units[i + 1])
                if host == "Ljava/lang/Boolean;" and fname == "FALSE":
                    regs[aa] = ("bool", False)
                elif host == "Ljava/lang/Boolean;" and fname == "TRUE":
                    regs[aa] = ("bool", True)
                i += 2
                continue

            if op == 0x69 and i + 1 < n:                      # sput-object vAA, field@BBBB
                if aa in regs:
                    put_field(units[i + 1], regs[aa])
                i += 2
                continue

            if op == 0x67 and i + 1 < n:                      # sput vAA, field@BBBB
                if aa in regs and regs[aa][0] == "int":
                    put_field(units[i + 1], regs[aa])
                i += 2
                continue

            if op in (0x68, 0x6A, 0x6B, 0x6C, 0x6D):
                # sput-wide / -boolean / -byte / -char / -short : 2 units
                i += 2
                continue

            i += 1

        return out

    def class_names(self) -> list[str]:
        return [
            self.type_at(struct.unpack_from("<I", self.data, self.off_cls + i * 32)[0])
            for i in range(self.n_cls)
        ]


# ---------------------------------------------------------------------------
# 极简 ELF 解析（只为找 JNI_OnLoad）
# ---------------------------------------------------------------------------


def elf_symbol(emu: Emulator, base: int, name: str) -> int | None:
    """按虚拟地址从模拟内存里解析 ELF 动态符号。

    壳把内层 .so 的不同 PT_LOAD 段映射到互不相邻的位置（段的 vaddr 与
    文件偏移也不相等），所以不能拿一段连续镜像当文件解析；这里统一用
    ``base + vaddr`` 做地址换算。
    """

    def read(va: int, size: int) -> bytes:
        return bytes(emu.mu.mem_read(base + va, size))

    if read(0, 4) != b"ELF":
        return None
    ehdr = read(0, 64)
    if ehdr[4] != 2:                       # 只处理 ELF64
        return None

    e_phoff = struct.unpack_from("<Q", ehdr, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", ehdr, 0x36)[0]
    e_phnum = struct.unpack_from("<H", ehdr, 0x38)[0]

    dyn_va = dyn_size = None
    try:
        phdrs = read(e_phoff, e_phentsize * e_phnum)
    except Exception:
        return None

    for i in range(e_phnum):
        off = i * e_phentsize
        p_type = struct.unpack_from("<I", phdrs, off)[0]
        if p_type == 2:                    # PT_DYNAMIC
            dyn_va = struct.unpack_from("<Q", phdrs, off + 0x10)[0]
            dyn_size = struct.unpack_from("<Q", phdrs, off + 0x20)[0]
            break
    if dyn_va is None:
        return None

    try:
        dyn = read(dyn_va, dyn_size)
    except Exception:
        return None

    symtab = strtab = None
    for off in range(0, dyn_size, 16):
        tag, val = struct.unpack_from("<QQ", dyn, off)
        if tag == 0:
            break
        if tag == 6:
            symtab = val
        elif tag == 5:
            strtab = val
    if symtab is None or strtab is None:
        return None

    # 逐个读符号：dynsym 通常远小于一页，但这里按 24 字节精确读取
    for i in range(4096):
        try:
            ent = read(symtab + i * 24, 24)
        except Exception:
            break
        st_name = struct.unpack_from("<I", ent, 0)[0]
        st_value = struct.unpack_from("<Q", ent, 8)[0]
        if st_name == 0 and i > 0 and st_value == 0:
            # 空表项之后通常没有更多符号，但不要过早退出
            continue
        if not st_name:
            continue
        try:
            raw = read(strtab + st_name, len(name) + 1)
        except Exception:
            continue
        if raw[:len(name)] == name.encode() and raw[len(name)] == 0:
            return st_value
    return None


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


class Unpacker:
    def __init__(
        self,
        apk: Path,
        out_dir: Path,
        *,
        arch: str = "arm64",
        wrapper_class: str = "Lcom/secneo/apkwrapper/H;",
        max_attempts: int = 4,
        keep_inner: bool = True,
    ):
        self.apk = apk
        self.out_dir = out_dir
        self.arch = arch
        self.wrapper_class = wrapper_class
        self.max_attempts = max_attempts
        self.keep_inner = keep_inner

        self.abi = {"arm64": "arm64-v8a", "arm": "armeabi-v7a"}[arch]
        self.emulator_arch = emu_const.ARCH_ARM64 if arch == "arm64" else emu_const.ARCH_ARM32

        self.stub_path: Path | None = None
        self.shell_dex: bytes | None = None
        self.shell: Dex | None = None
        self.pkg = ""
        self.wrapper_fields: list[tuple[str, str, tuple]] = []

        #: 每次重试追加一个"符号查询函数"的绝对地址；用于装假 ART 符号垫片
        self.resolver_hooks: list[int] = []
        self.attempt_log: list[dict] = []
        self._inner_size: int = 0

    # -- 准备 -----------------------------------------------------------

    def prepare(self) -> None:
        work = self.out_dir / "_work"
        work.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(self.apk) as z:
            names = z.namelist()
            stub_name = f"lib/{self.abi}/libDexHelper.so"
            if stub_name not in names:
                # 有的包把壳放在别的名字下
                cands = [n for n in names if n.startswith(f"lib/{self.abi}/")
                         and n.endswith(".so") and "DexHelper" in n]
                if not cands:
                    raise SystemExit(f"APK 里没有 lib/{self.abi}/libDexHelper.so")
                stub_name = cands[0]

            self.stub_path = work / Path(stub_name).name
            self.stub_path.write_bytes(z.read(stub_name))
            log.info("壳：%s（%d 字节）", stub_name, self.stub_path.stat().st_size)

            if "classes.dex" not in names:
                raise SystemExit("APK 里没有 classes.dex")
            self.shell_dex = z.read("classes.dex")
            self.shell = Dex(self.shell_dex)
            log.info("壳 dex：%d 字节，%d 个类", len(self.shell_dex), self.shell.n_cls)

        declared = self.shell.static_fields(self.wrapper_class)
        clinit = self.shell.clinit_values(self.wrapper_class)
        self.wrapper_fields = [
            (name, desc, value if value is not None else clinit.get(name))
            for name, desc, value in declared
        ]
        for name, _desc, value in self.wrapper_fields:
            if name == "PKGNAME" and value and value[0] == "string":
                self.pkg = value[1]
        if not self.pkg:
            self.pkg = "unknown.package"
        log.info("包名：%s；壳类静态字段 %d 个", self.pkg, len(self.wrapper_fields))

    # -- Java 侧对象模型 -------------------------------------------------

    def _ensure_class(self, emu: Emulator, desc: str):
        """按需为未知的对象类型注册一个空壳类。"""
        if not desc.startswith("L"):
            return None
        jvm = desc[1:-1]
        cls = emu.java_classloader.find_class_by_name(jvm)
        if cls is not None:
            return cls
        try:
            cls = JavaClassDef(
                f"Stub_{abs(hash(jvm)) & 0xFFFFFF:x}",
                (object,),
                {"__module__": __name__, "__init__": lambda self: None},
                jvm_name=jvm,
            )
            emu.java_classloader.add_class(cls)
            return cls
        except Exception:
            return None

    def _java_value(self, emu: Emulator, desc: str, name: str, value: tuple):
        """把 dex 里的静态初值转成 AndroCorn 的 Java 对象。"""
        kind = value[0] if value else "null"

        if desc == "Ljava/lang/String;":
            return JavaString(value[1] if kind == "string" else (name if value is None else ""))
        if desc == "Ljava/lang/Boolean;":
            return JavaBoolean(kind == "bool" and value[1])
        if desc == "I":
            return int(value[1]) if kind == "int" else 0
        if desc == "J":
            return int(value[1]) if kind == "int" else 0
        if desc == "Z":
            return bool(value[1]) if kind == "bool" else False
        # 其余对象类型
        if name == "sApp":
            return Application()
        if name == "sAppInfo":
            return ApplicationInfo(self.pkg)
        if kind == "obj":
            cls = self._ensure_class(emu, value[1])
            if cls is not None:
                try:
                    return cls()
                except Exception:
                    return None
        return None

    def _build_wrapper_class(self, emu: Emulator):
        fields = []
        for name, desc, value in self.wrapper_fields:
            jv = self._java_value(emu, desc, name, value)
            if jv is None:
                # JavaFieldDef 不接受静态字段值为 None；给一个 0 占位，
                # JNI 的 GetStaticObjectField 会把它当作 null 引用返回。
                if desc.startswith("L"):
                    jv = 0
                else:
                    jv = 0
            fields.append(JavaFieldDef(name, desc, True, jv))

        return JavaClassDef(
            "SecNeoWrapper",
            (object,),
            {"__module__": __name__, "__init__": lambda self: None},
            jvm_name=self.wrapper_class[1:-1],
            jvm_fields=fields,
        )

    def _register_java(self, emu: Emulator) -> None:
        load_mocks(emu.java_classloader)

        # ART 侧被壳反射访问的对象
        for cls in (DexCache, DexFile, BaseDexClassLoader, DexPathList,
                    DexPathListElement, InMemoryDexClassLoader, JavaClassLoader,
                    LongArray):
            try:
                emu.java_classloader.add_class(cls)
            except Exception:
                pass

        # 壳 dex 里的每个类都先注册成空壳，RegisterNatives 才不会找不到类
        for cls_name in self.shell.class_names():
            jvm = cls_name[1:-1] if cls_name.startswith("L") else cls_name
            if jvm == self.wrapper_class[1:-1]:
                continue
            try:
                emu.java_classloader.add_class(JavaClassDef(
                    f"Shell_{abs(hash(jvm)) & 0xFFFFFF:x}",
                    (object,),
                    {"__module__": __name__, "__init__": lambda self: None},
                    jvm_name=jvm,
                ))
            except Exception:
                pass

        emu.java_classloader.add_class(self._build_wrapper_class(emu))
        log.info("已注册 %d 个壳类与 %d 个 Java mock",
                 len(self.shell.class_names()), len(emu.java_classloader.class_by_name))

    # -- 模拟器启动 -------------------------------------------------------

    def _boot(self) -> tuple[Emulator, int]:
        emu = Emulator(
            vfs_root=str(_find_androcorn() / "vfs"),
            arch=self.emulator_arch,
        )
        self._register_java(emu)

        # APK 挂载点：ApplicationInfo.sourceDir / dataDir 都是壳自己读的
        data_dir = emu.vfs.vfs_root + f"/data/data/{self.pkg}"
        for sub in ("", ".cache", ".cache/oat", f".cache/oat/{self.abi}", "files"):
            Path(data_dir, sub).mkdir(parents=True, exist_ok=True)
        for virt in (
            f"/data/app/{self.pkg}-1.apk",
            f"/data/app/{self.pkg}/base.apk",
            f"/data/app/{self.pkg}.apk",
        ):
            try:
                emu.vfs.mount_file(virt, str(self.apk), uid=1000)
            except Exception:
                pass

        lib = emu.load_library(str(self.stub_path), do_init=True)
        log.info("外层壳已加载 @ %#x", lib.base)

        inner_base, inner_size = self._find_inner(emu, exclude=lib.base)
        self._inner_size = inner_size
        if inner_base is None:
            raise SystemExit("壳没有解出内层 .so（可能不是 SecNeo，或架构不符）")
        log.info("内层 .so @ %#x", inner_base)

        # 壳通过 DexFile.mCookie 找已加载的 dex；把 classes.dex 映射进去并伪造结构
        self._attach_shell_dex(emu)
        self._install_resolver_hooks(emu, inner_base)
        return emu, inner_base

    def _find_inner(self, emu: Emulator, *, exclude: int) -> tuple[int | None, int]:
        known = set()
        for mod in getattr(emu.linker, "modules", []):
            known.add(mod.base)
        known.add(exclude)

        for begin, end, _perms in emu.mu.mem_regions():
            size = end - begin + 1
            if size < 0x10000 or size > 0x800000 or begin in known:
                continue
            try:
                if bytes(emu.mu.mem_read(begin, 4)) != b"\x7fELF":
                    continue
            except Exception:
                continue
            return begin, size
        return None, 0

    def _attach_shell_dex(self, emu: Emulator) -> None:
        data = self.shell_dex
        addr = emu.memory.find_free_region(len(data))
        emu.memory.map(addr, len(data), UC_PROT_READ | UC_PROT_WRITE)
        chunk = 0x400000
        for off in range(0, len(data), chunk):
            emu.mu.mem_write(addr + off, data[off:off + chunk])

        struct_addr = emu.memory.find_free_region(0x1000)
        emu.memory.map(struct_addr, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        # 壳按 [cookie+8] 取 dex 数据指针（+0x20 恰好是 header 的 file_size）
        emu.mu.mem_write(struct_addr, struct.pack("<QQQQ", addr, addr, addr, len(data)))

        dx = DexFile()
        dx.mCookie = LongArray([struct_addr, struct_addr])
        emu.java_classloader.pathList = DexPathList([
            DexPathListElement(dex_file=dx, path=JavaFile(f"/data/app/{self.pkg}-1.apk"))
        ])
        log.info("classes.dex 已映射到 %#x，伪 DexFile @ %#x", addr, struct_addr)

    # -- 自动定位"符号查询函数" ------------------------------------------

    def _install_resolver_hooks(self, emu: Emulator, inner_base: int) -> None:
        if not self.resolver_hooks:
            return

        fake_obj = emu.memory.find_free_region(0x2000)
        emu.memory.map(fake_obj, 0x2000, UC_PROT_READ | UC_PROT_WRITE)
        emu.mu.mem_write(fake_obj, bytes(0x2000))

        fake_func = emu.memory.find_free_region(0x1000)
        emu.memory.map(fake_func, 0x1000, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        # mov w0, #0 ; ret
        emu.mu.mem_write(fake_func, bytes.fromhex("00008052c0035fd6"))

        slot_obj = emu.memory.find_free_region(0x1000)
        emu.memory.map(slot_obj, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        emu.mu.mem_write(slot_obj, struct.pack("<Q", fake_obj))

        slot_func = emu.memory.find_free_region(0x1000)
        emu.memory.map(slot_func, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        emu.mu.mem_write(slot_func, struct.pack("<Q", fake_func))

        def read_cstr(addr: int, limit: int = 256) -> str:
            try:
                return bytes(emu.mu.mem_read(addr, limit)).split(b"\x00")[0].decode("latin1")
            except Exception:
                return ""

        def after(_emu, ret, mods, name_ptr, *_rest):
            if ret not in (None, 0):
                return None
            name = read_cstr(name_ptr or 0)
            if not name.startswith("_Z"):
                return None
            log.info("  [ART] %s 未解析 -> 假符号", name)
            return slot_func if name.endswith("Ev") else slot_obj

        for addr in self.resolver_hooks:
            try:
                emu.hook_manager.inline(addr, 3, None, after)
                log.info("已安装符号垫片 @ %#x", addr)
            except Exception as exc:
                log.warning("符号垫片安装失败 %#x：%s", inner_base + off, exc)

    def _guess_resolver_offset(self, emu: Emulator, inner_base: int, err: UcError) -> int | None:
        """从崩溃点回溯最近的 ``bl``，把它当作符号查询函数。

        返回绝对地址（内层 .so 的各段并不连续，不能用 base+偏移表达）。
        """
        import capstone

        pc = emu.mu.reg_read(UC_ARM64_REG_PC)
        lr = emu.mu.reg_read(UC_ARM64_REG_LR)
        start = pc if pc != 0 else lr
        if start == 0:
            return None

        # 找到包含 start 的内存区，向下取最多 0x200 字节
        region = None
        for begin, end, _p in emu.mu.mem_regions():
            if begin <= start < end:
                region = (begin, end)
                break
        if region is None:
            return None

        begin, _end = region
        lo = max(begin, start - 0x200)
        try:
            blob = bytes(emu.mu.mem_read(lo, start - lo))
        except Exception:
            return None

        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        target = None
        for ins in md.disasm(blob, lo):
            if ins.mnemonic == "bl":
                try:
                    target = int(ins.op_str.lstrip("#"), 0)
                except ValueError:
                    target = None
        if target is None:
            return None

        log.info("推测符号查询函数：崩溃 PC=%#x，回溯到 bl -> %#x", pc, target)
        return target


    # -- 调用 JNI_OnLoad ---------------------------------------------------

    @staticmethod
    def _locate_jni_onload(emu: Emulator, base: int, size: int) -> int | None:
        """定位 ``JNI_OnLoad``。

        优先用动态符号表；但 SecNeo 会把 ``JNI_OnLoad`` 的 ``st_value``
        改成一个不可用的值（本例写的是 0x3FE498B4，真实值是 0x148B4），
        因此符号表不可信时改用行为特征：

        ``JNI_OnLoad(JavaVM*, void*)`` 必须先拿 ``JNIEnv``，典型指令是
        ``mov w2, #4``（JNI_VERSION_1_4）/``#6`` 加 ``movk w2, #1, lsl #16``
        ——这对立即数只在 JNI 入口出现一次。命中后向上回溯到函数起点。
        """
        # 1) 符号表（值必须在镜像范围内才算可信）
        sym = elf_symbol(emu, base, "JNI_OnLoad")
        if sym is not None and 0 < sym < size:
            return sym
        if sym is not None:
            log.info("符号表里的 JNI_OnLoad=%#x 不可用，改用特征扫描", sym)

        # 2) 行为特征扫描
        try:
            blob = bytes(emu.mu.mem_read(base, size))
        except Exception:
            return None
        if len(blob) < 64:
            return None

        text = struct.unpack_from(f"<{len(blob) // 4}I", blob, 0)
        movk = 0x72A00022          # movk w2, #1, lsl #16
        movs = (0x52800082, 0x528000C2)   # mov w2, #4 / #6

        hits = []
        for i in range(len(text) - 3):
            if text[i] in movs and text[i + 2] == movk:
                hits.append(i * 4)
        if not hits:
            return None

        def is_prologue(word: int) -> bool:
            # stp xN, xM, [sp, #-imm]!  /  stp x29, x30, [sp, #imm]
            if (word & 0xFFC00000) in (0xA9800000, 0xA9000000):
                return True
            # sub sp, sp, #imm
            if (word & 0xFFC003FF) == 0xD10003FF:
                return True
            return False

        for hit in hits:
            j = hit // 4
            start = None
            for k in range(j, max(0, j - 0x2000), -1):
                if text[k] == 0xD65F03C0 or (text[k] & 0x7C000000) == 0x14000000:
                    start = (k + 1) * 4
                    break
            if start is None:
                continue
            if is_prologue(struct.unpack_from("<I", blob, start)[0]):
                log.info("特征扫描命中 JNI_OnLoad @ %#x（偏移 %#x）", base + start, start)
                return start
        return None



    def _call_jni_onload(self, emu: Emulator, inner_base: int) -> int:
        sym = self._locate_jni_onload(emu, inner_base, self._inner_size)
        if sym is None:
            raise SystemExit("找不到 JNI_OnLoad（符号表不可用，特征扫描也没命中）")
        addr = inner_base + sym
        log.info("JNI_OnLoad @ %#x（偏移 %#x）", addr, sym)
        return emu.call_native(addr, emu.java_vm.address_ptr, 0) or 0

    # -- 主入口 ------------------------------------------------------------

    def run(self) -> dict:
        self.prepare()
        last_error = None

        for attempt in range(1, self.max_attempts + 1):
            log.info("=== 第 %d 次尝试 ===", attempt)
            emu = None
            inner_base = -1
            try:
                emu, inner_base = self._boot()
                ret = self._call_jni_onload(emu, inner_base)
                log.info("JNI_OnLoad 返回 %#x", ret)
                break
            except UcError as exc:
                last_error = exc
                log.warning("模拟中断：%s", exc)
                if emu is None:
                    raise
                off = self._guess_resolver_offset(emu, inner_base, exc)
                if off is None or off in self.resolver_hooks:
                    log.error("无法自动定位符号查询函数，停止重试")
                    break
                self.resolver_hooks.append(off)
            except Exception as exc:                 # JNI mock 缺失等
                last_error = exc
                log.warning("运行异常：%s", exc)
                break
        else:
            emu = None

        if emu is None:
            raise SystemExit(f"脱壳失败：{last_error}")

        if self.keep_inner:
            try:
                inner = bytes(emu.mu.mem_read(inner_base, self._inner_size))
                (self.out_dir / "inner_libDexHelper.so").write_bytes(inner)
            except Exception:
                pass

        dexes = self._collect_dexes(emu)
        report = self._write_outputs(dexes)
        report["attempts"] = attempt
        report["pkg"] = self.pkg
        return report

    # -- 产物 -------------------------------------------------------------

    def _collect_dexes(self, emu: Emulator) -> list[tuple[int, bytes]]:
        seen: dict[str, tuple[int, bytes]] = {}
        for begin, end, _perms in emu.mu.mem_regions():
            size = min(end - begin + 1, 0x4000000)
            try:
                data = bytes(emu.mu.mem_read(begin, size))
            except Exception:
                continue
            for magic in DEX_MAGICS:
                off = data.find(magic)
                while off >= 0:
                    dex = self._slice_dex(data, off)
                    if dex is not None:
                        digest = hashlib.sha256(dex).hexdigest()
                        seen.setdefault(digest, (begin + off, dex))
                    off = data.find(magic, off + 1)

        # 过滤 ART 的占位 dex（284 字节、0 个方法），按类数量降序排列
        out = []
        for addr, dex in seen.values():
            n_methods = struct.unpack_from("<I", dex, 88)[0]
            if n_methods == 0:
                log.debug("跳过占位 dex @ %#x（%d 字节）", addr, len(dex))
                continue
            out.append((addr, dex))
        out.sort(key=lambda item: struct.unpack_from("<I", item[1], 96)[0], reverse=True)
        return out

    @staticmethod
    def _slice_dex(data: bytes, off: int) -> bytes | None:
        if off + 0x70 > len(data):
            return None
        magic = data[off:off + 8]
        if magic.startswith(b"cdex"):
            return None
        fsz = struct.unpack_from("<I", data, off + 32)[0]
        hsz = struct.unpack_from("<I", data, off + 36)[0]
        endian = struct.unpack_from("<I", data, off + 40)[0]
        map_off = struct.unpack_from("<I", data, off + 52)[0]
        if not (0x70 <= fsz <= len(data) - off) or hsz != 0x70:
            return None
        if endian != 0x12345678 or not (0x70 <= map_off < fsz):
            return None
        if data[off + 8:off + 12] != b"dex\n" and magic != b"dex\n035\x00":
            pass
        body = data[off:off + fsz]
        if hashlib.sha1(body[32:]).digest() != body[12:32]:
            return None
        if zlib.adler32(body[12:]) & 0xFFFFFFFF != struct.unpack_from("<I", body, 8)[0]:
            return None
        return body

    def _write_outputs(self, dexes: list[tuple[int, bytes]]) -> dict:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        zip_path = self.out_dir / "app-dex.zip"
        entries = []
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as z:
            for i, (addr, dex) in enumerate(dexes):
                name = "classes.dex" if i == 0 else f"classes{i + 1}.dex"
                z.writestr(name, dex)
                n_cls = struct.unpack_from("<I", dex, 96)[0]
                n_meth = struct.unpack_from("<I", dex, 88)[0]
                entries.append({
                    "entry": name,
                    "addr": hex(addr),
                    "size": len(dex),
                    "classes": n_cls,
                    "methods": n_meth,
                    "sha256": hashlib.sha256(dex).hexdigest(),
                })

        report = {
            "apk": str(self.apk),
            "dex_count": len(entries),
            "dexes": entries,
            "zip": str(zip_path),
        }
        (self.out_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        log.info("共解出 %d 个 dex -> %s", len(entries), zip_path)
        return report


def main() -> int:
    ap = argparse.ArgumentParser(description="SecNeo（梆梆）加固 APK 通用脱壳工具")
    ap.add_argument("apk", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("unpacked"))
    ap.add_argument("--arch", choices=["arm64", "arm"], default="arm64")
    ap.add_argument("--wrapper-class", default="Lcom/secneo/apkwrapper/H;",
                    help="壳驱动类的 JVM 描述符（默认 Lcom/secneo/apkwrapper/H;）")
    ap.add_argument("--max-attempts", type=int, default=4)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    if not args.apk.is_file():
        raise SystemExit(f"APK 不存在：{args.apk}")

    unpacker = Unpacker(
        args.apk,
        args.out,
        arch=args.arch,
        wrapper_class=args.wrapper_class,
        max_attempts=args.max_attempts,
    )
    report = unpacker.run()

    print()
    print(f"包名      : {report['pkg']}")
    print(f"dex 数量  : {report['dex_count']}")
    for item in report["dexes"]:
        print(f"  {item['entry']:<14} {item['size']:>10,}  "
              f"{item['classes']:>5} 类  {item['methods']:>6} 方法  @{item['addr']}")
    print(f"输出      : {report['zip']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
