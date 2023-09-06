// 打印list
   var iterator = rootHosts.iterator();
    while (iterator.hasNext()) {
        var element = iterator.next();
        console.log(element);
    }

//打印map
var Map = Java.use('java.util.Map');
    
var mapInstance = Java.cast(result, Map);

var keySet = mapInstance.keySet();
var iterator = keySet.iterator();
while (iterator.hasNext()) {
    var key = iterator.next();
    var value = mapInstance.get(key);
    console.log('Key:', key, 'Value:', value);
}