function hook_tridepid(){
    var fgets_ptr = Module.getExportByName("libc.so","fgets");
    var fgets = new NativeFunction(fgets_ptr,"pointer",["pointer","int","pointer"]);

    Interceptor.replace(fgets_ptr, new NativeCallback(function (buffer,n,filestream){
        var ret = fgets(buffer,n,filestream);
        var line = buffer.readUtf8String();
        if(line.indexOf("TracerPid") != -1){
            console.log("hook gets " + line + "'");
            buffer.writeUtf8String("TracerPid:\t0\n");
        }else{

        }
        return ret;
    },"pointer",["pointer","int","pointer"]));



}