Activity["getIntent"].implementation = function() {
    let result = this["getIntent"]();
    var tmp = result.getExtras()
  if(tmp != null) {
    console.log("---------------- bundle contents--------------------")
    console.log("getintent :data " + result.getData() + " " + this)
   console.log("getintent.getExtras : " + tmp)
    console.log('---Bundle contents:---');
    var keySet = tmp.keySet();
    var iterator = keySet.iterator();
    while (iterator.hasNext()) {
      var key = iterator.next();
      var value = tmp.get(key);
      console.log(key + ': ' + value);
      if(value != null){
      if(value.toString().indexOf("Bundle") != -1) {
        console.log(value + '---Bundle contents:---');
        var value12 = Java.cast(value,Java.use('android.os.Bundle'))
        var keySet1 = value12.keySet();
        var iterator1 = keySet1.iterator();
        while (iterator1.hasNext()) {
            var key1 = iterator1.next();
            var value1 = value12.get(key1);
            console.log(key1 + ': ' + value1);
        }
        console.log(value + '---Bundle contents end---');
      }
    }
    }
    console.log("---------------- bundle content end--------------------")
}
    return result
}
