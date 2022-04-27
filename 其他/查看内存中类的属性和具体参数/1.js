// Java.perform(function(){
//     var clz = Java.use("com.tencent.wework.foundation.model.pb.WwLoginKeys$LoginKeys")
//     var JavaString = Java.use("java.lang.String");
//     clz.mergeFrom.overload('com.google.protobuf.nano.CodedInputByteBufferNano').implementation = function(){
//             console.log("mergeFrom arg0:" + arguments[0])
//           //   console.log("CalcCST arg0:")
//             var fields = Java.cast(arguments[0].getClass(),Java.use('java.lang.Class')).getDeclaredFields();
//             //console.log(fields);
//             for (var j = 0; j < fields.length; j++) {
//                 var field = fields[j];
//                 field.setAccessible(true);
//                 var name = field.getName();
//                 var value =field.get(arguments[0])
//                 console.log("\t\tname:"+name+"\tvalue:"+value)}
//             return this.mergeFrom.apply(this,arguments)
//     }
// })

对于java 原生类 还可以用gson (自己写的 还没尝试看看)

使用Frida时，想要打印Java对象的内容，可以使用谷歌的gson包，可以非常优秀的将Java对象的内容，以json的格式打印出来。

但是有些时候，如果原apk里面，已经包含了该gson包，再Java.use就会重名取到原apk里的包，非常不方便。



我自己编译了个版本，改了包名，这样Java.use的时候就不会重名出错了，效果如下图：



使用方法：

解压，adb push到fridaserver同目录下之后
代码：
 复制代码 隐藏代码
Java.openClassFile("/data/local/tmp/r0gson.dex").load();
const gson = Java.use('com.r0ysue.gson.Gson');
console.log(gson.$new().toJson(xxx));