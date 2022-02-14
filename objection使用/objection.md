objection连接：

usb: objection -g 包名 explore

搜加载的so文件：memory list modules

查看库的导出函数:memory list exports libssl.so

在内存堆中搜索与执行：android heap search instances xxx.xxx.xxx.类名

调用 android heap execute 堆地址 方法名

在实例上执行js代码： android heap evaluate 堆地址 后就可以输入js

启动activity或者service android intent launch_activity 包名.活动名

​    查看当前可用的activity  android hooking list activities

查看可用的services service: android hooking list services

​      启动service        android intent launch_service 包名.活动名

列出内存中所有的类：android hooking list classes

内存中搜索所有的类:  android hooking search classes 关键词

内存中搜索所有的方法：android hooking search methods 关键词

列出类的所有方法     : android hooking list class_methods 类名

hook类的所有方法  ： android hooking watch class 类名

hook方法的参数，返回值和调用栈 : android hooking watch class_method 方法名 --dump-args --dump-return --dump-backtrace

hook 方法的所有重载 ： objection自动加载 

暴力搜索所有dalvik.system.DexClassLoader : **android** **heap** **search** **instances** **dalvik**.system.DexClassLoader

暴力搜内存:  memory search "64 65 78 0a 30 33 35 00"

把它拷贝下来  :  memory dump from_base 地址 大小 文件名











​        