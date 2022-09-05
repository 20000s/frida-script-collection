//来自http://91fans.com.cn/post/findclassname/#gsc.tab=0
// 这个包下的类都遍历出来，这样不就可以知道这个类名的UTF-8 编码的转义了吗？
Java.enumerateLoadedClasses({
    onMatch: function(className) {
        if(className.indexOf('com.google.android.material.tooltip') >=0 ){
            console.log(className.toString());
            console.log(encodeURIComponent(className.toString()));
        }
    },
    onComplete:function(){
    }
});

// decodeURIComponent hook
var hookCls = Java.use(decodeURIComponent('com.google.android.material.tooltip.%DB%A4%DB%A4%DB%9F%DB%A6'));
//遍历方法名
//var hookCls = Java.use(decodeURIComponent('com.google.android.material.tooltip.%DB%A4%DB%A4%DB%9F%DB%A6'));
var methods = hookCls.class.getDeclaredMethods();

for (var i in methods) {
    console.log(methods[i].toString());
    console.log(encodeURIComponent(methods[i].toString().replace(/^.*?\.([^\s\.\(\)]+)\(.*?$/, "$1")));
}

//Hook这个成员函数的代码
hookCls[decodeURIComponent("%DB%9F%DB%A3%DB%A5%DB%9F%DB%A3")]
           .implementation = function () {
                        console.log("m1344 =============== ");
                        return "xxx";

           }