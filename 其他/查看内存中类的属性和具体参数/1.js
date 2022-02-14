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
