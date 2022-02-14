unpack.js

原理:

把所有的方法 类加载一遍 再hook openmemory

可以应对第二代壳（指令提取）





unpackdex.js是hook openmemory opencommpn dalvikopen的

只能脱整体壳 指令提取是空壳

frida -U -f com.xxx.xxx.xxx -l dupDex.js --no-pause



frida_dump

hook defineclass



frida-dexdump

内存遍历寻找dex035或是深度搜索 符合dex文件结构
