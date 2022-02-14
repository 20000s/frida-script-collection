Java.enumerateClassLoaders({
    "onMatch": function(loader) {
        if (loader.toString().startsWith("com.tencent.shadow.core.loader.classloaders.PluginClassLoader")) {
            Java.classFactory.loader = loader; // 将当前class factory中的loader指定为我们需要的
        }
    },
    "onComplete": function() {
     //   console.log("success :" + Java.classFactory.loader);
    }
});