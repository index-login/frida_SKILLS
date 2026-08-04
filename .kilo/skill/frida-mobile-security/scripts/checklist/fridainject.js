// 一般用于基础frida hook测试，或者在frida hook代码注入成功后弹窗提示
if(Java.available){
    console.log("Java.available");
    try{
        Java.performNow(function(){
            var activity = Java.use("android.app.Activity");
            var builderCls = Java.use("android.app.AlertDialog$Builder");
            var StringCls = Java.use("java.lang.String");
            activity.onCreate.overload("android.os.Bundle").implementation=function(savedInstanceState){
            var builder = builderCls.$new(this);
            this.onCreate(savedInstanceState);
            builder.setTitle(StringCls.$new("危险提示"));
            builder.setMessage(StringCls.$new("Frida Hook代码注入成功!!!"));
            builder.create().show();
            }
        });
        console.log("java over hook");      
    } catch (err){
        console.log("[!]Exception:"+ +err.message);
    }
}