function showStacks3(str_tag) 
{
   var Exception=  Java.use("java.lang.Exception");
   var ins = Exception.$new("Exception");
   var straces = ins.getStackTrace();

   if (undefined == straces || null  == straces) 
   {
       return;
   }

   console.log("=============================" + str_tag + " Stack strat=======================");
   console.log("");

   for (var i = 0; i < straces.length; i++)
   {
       var str = "   " + straces[i].toString();
       console.log(str);
   }

   console.log("");
   console.log("=============================" + str_tag + " Stack end=======================\r\n");
   Exception.$dispose();
};