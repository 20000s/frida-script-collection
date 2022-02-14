function hook_RegisterNatives(){
    var symbols = Module.enumerateSymbolsSync("libart.so");
    var addRegisterNatives = null;
    //搜索在art中加载native的函数 名字这么丑 因为c++名称粉碎
    for(var i = 0 ; i < symbols.length; ++i){
        var symbol = symbols[i];

         //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
         if(symbol.name.indexOf("art") >= 0 &&
            symbol.name.indexOf("JNI") >=0  &&
            symbol.name.indexOf("RegisterNatives") >= 0 &&
            symbol.name.indexOf("CheckJNI") < 0){
                addRegisterNatives = symbol.address;
                console.log("RegisterNatives is at ",symbol.address,symbol.name);
            }
    }
      //这里就是根据函数的参数读取了
    if(addRegisterNatives != null){
        Interceptor.attach(addRegisterNatives,{
            onEnter: function(args){
                console.log("[RegisterNatives] method_count:",args[3]);
                var env = args[0]
                var java_class = args[1]
                var class_name = Java.vm.tryGetEnv().getClassName(java_class);
                var methods_ptr = ptr(args[2]);

                var method_count = parseInt(args[3]);
                for(var i = 0 ; i < method_count ; ++i){
                    var name_ptr = Memory.readPointer(methods_ptr.add(i*Process.pointerSize*3));
                    var sig_ptr = Memory.readPointer(methods_ptr.add(i*Process.pointerSize*3+ Process.pointerSize));
                    var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i*Process.pointerSize*3+ 2* Process.pointerSize));
                    
                    var name = Memory.readCString(name_ptr);
                    var sig  = Memory.readCString(sig_ptr);
                    var find_module = Process.findModuleByAddress(fnPtr_ptr);
                    console.log("[RegisterNatives] java_class:",class_name,"name:",name,"sig:",sig,"fnPtr:",
                    fnPtr_ptr,"module_name:",find_module.name,"module_base:",find_module.base,"offset:",ptr(fnPtr_ptr)
                    .sub(find_module.base));
                }
            }
        });
    }

}
hook_RegisterNatives();