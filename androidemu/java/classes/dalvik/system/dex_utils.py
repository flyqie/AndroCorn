from androidemu.java.class_def import JavaClassDef
from androidemu.java.field_def import JavaFieldDef
from androidemu.java.method_def import java_method_def, JavaMethodDef
from androidemu.java.classes.java.lang.array import ObjectArray


class DexPathList(metaclass=JavaClassDef, jvm_name='dalvik/system/DexPathList',
                  jvm_fields=[
                      JavaFieldDef('dexElements', '[Ldalvik/system/DexPathList$Element;', False),
                  ]):
    def __init__(self, elements=None):
        self.dexElements = ObjectArray(elements or [])


class DexPathListElement(metaclass=JavaClassDef, jvm_name='dalvik/system/DexPathList$Element',
                         jvm_fields=[
                             JavaFieldDef('dexFile', 'Ldalvik/system/DexFile;', False),
                             JavaFieldDef('path', 'Ljava/io/File;', False),
                         ]):
    def __init__(self, dex_file=None, path=None):
        self.dexFile = dex_file
        self.path = path


class InMemoryDexClassLoader(metaclass=JavaClassDef, jvm_name='dalvik/system/InMemoryDexClassLoader',
                             jvm_fields=[
                                 JavaFieldDef('pathList', 'Ldalvik/system/DexPathList;', False),
                             ]):
    def __init__(self):
        self.pathList = DexPathList()

class BaseDexClassLoader(metaclass=JavaClassDef, jvm_name='dalvik/system/BaseDexClassLoader'):

    def __init__(self):
        pass

class DexFile(metaclass=JavaClassDef, jvm_name='dalvik/system/DexFile',
              jvm_fields=[
                  JavaFieldDef('mCookie', 'Ljava/lang/Object;', False),
                  JavaFieldDef('mFileName', 'Ljava/lang/String;', False),
              ]):
    
    def __init__(self):
        self.mCookie = 0
        self.mFileName = None

    @java_method_def(name='<init>', args_list=["jstring"], signature='(Ljava/lang/String;)V', native=False)
    def ctor(self, emu, *args, **kwargs):
        # print("DexFile_ctor %r"%args)
        return DexFile()