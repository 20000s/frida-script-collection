打印 [object object]

方法 1：先确认 object 是什么类型，比如要打印 p，先 console.log(p.$className) 查看 p 是什么数据类型，然后用 Java.cast 把 p 强制转为对应类型，强制转换之后，在调用转换后类型的输出方法，通常为 toString()
方法 2：使用 js 里面的 json 类，尝试 console.log(JSON.stringify(p))，可能打印不出来字符串，一般能打印出 p 的字节数组
方法 3：使用 objection 插件 wallbreak
