function hookcallback(p){
    var fun = new NativeFunction(p,'int',['pointer','pointer'])
    var self = new NativeCallback(function(arg1,arg2){
        console.log("sasasas", fun(arg1,arg2))

        return 0;
    },'int',['pointer','pointer'])

    Interceptor.replace(fun,self)
}
function dlopentodo(){
    var cronet = Module.findBaseAddress("libsscronet.so")
    var ver = Module.findExportByName("libttboringssl.so","SSL_CTX_set_custom_verify");
    var custom_verify = new NativeFunction(ver,'pointer',['pointer','int','pointer']);
    var funarr = [];
    var index = 0;
    var self = new NativeCallback(function(arg1,arg2,arg3){
               hookcallback(arg3)
               console.log("custom verify called",arg2,arg3)
               return custom_verify(arg1,0,arg3)
    },'pointer',['pointer','int','pointer'])

    Interceptor.replace(ver,self)
}

function main2(){
    var android_dlopen_ext = Module.findExportByName(null,"android_dlopen_ext");
    console.log(android_dlopen_ext)
    if(android_dlopen_ext != null){
        Interceptor.attach(android_dlopen_ext,{
            onEnter:function(args){
                var soName = args[0].readCString()
                if(soName.indexOf("libsscronet.so") != -1){
                    this.hook = true
                }
            },
            onLeave:function(retval){
                if(this.hook){
                    dlopentodo()
                }
            }
        })
    }
}
main2()