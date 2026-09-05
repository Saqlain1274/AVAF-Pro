"""
AVAF PRO
Runtime Storage Instrumentation
"""

STORAGE_HOOK = r"""

/*=========================================================
Helpers
=========================================================*/

function storageEvent(type,target,metadata={}){

    AVAF.emit(

        "storage",

        type,

        target,

        metadata

    );

}

function addStorageArtifact(value){

    if(!value)
        return;

    AVAF.artifacts.parameters.add(

        String(value)

    );

}


/*=========================================================
Initial localStorage Discovery
=========================================================*/

try{

    for(let i=0;i<localStorage.length;i++){

        const key=localStorage.key(i);

        addStorageArtifact(key);

        storageEvent(

            "localStorage",

            key,

            {

                existing:true

            }

        );

    }

}catch(e){}


/*=========================================================
Initial sessionStorage Discovery
=========================================================*/

try{

    for(let i=0;i<sessionStorage.length;i++){

        const key=sessionStorage.key(i);

        addStorageArtifact(key);

        storageEvent(

            "sessionStorage",

            key,

            {

                existing:true

            }

        );

    }

}catch(e){}


/*=========================================================
Hook Storage.setItem
=========================================================*/

{

    const originalSetItem=Storage.prototype.setItem;

    Storage.prototype.setItem=function(key,value){

        addStorageArtifact(key);

        storageEvent(

            this===window.localStorage

            ? "localStorage"

            : "sessionStorage",

            key,

            {

                valueLength:String(value).length

            }

        );

        return originalSetItem.apply(

            this,

            arguments

        );

    };

}
/*=========================================================
Initial Cookie Discovery
=========================================================*/

try{

    document.cookie

        .split(";")

        .map(x=>x.trim())

        .filter(Boolean)

        .forEach(cookie=>{

            const name=cookie.split("=")[0];

            if(!name)
                return;

            storageEvent(

                "cookie",

                name,

                {

                    existing:true

                }

            );

            addStorageArtifact(name);

            const lower=name.toLowerCase();

            if(

                lower.includes("csrf") ||

                lower.includes("token") ||

                lower.includes("jwt") ||

                lower.includes("auth") ||

                lower.includes("session") ||

                lower.includes("api")

            ){

                AVAF.emit(

                    "security",

                    "credential",

                    name

                );

            }

        });

}catch(e){}


/*=========================================================
Existing localStorage Secret Discovery
=========================================================*/

try{

    for(

        let i=0;

        i<localStorage.length;

        i++

    ){

        const key=localStorage.key(i);

        const value=localStorage.getItem(key) || "";

        const lower=key.toLowerCase();

        if(

            lower.includes("token") ||

            lower.includes("csrf") ||

            lower.includes("jwt") ||

            lower.includes("bearer") ||

            lower.includes("oauth") ||

            lower.includes("api") ||

            lower.includes("secret") ||

            lower.includes("session")

        ){

            AVAF.emit(

                "security",

                "storage-secret",

                key,

                {

                    length:value.length

                }

            );

        }

    }

}catch(e){}


/*=========================================================
Existing sessionStorage Secret Discovery
=========================================================*/

try{

    for(

        let i=0;

        i<sessionStorage.length;

        i++

    ){

        const key=sessionStorage.key(i);

        const value=sessionStorage.getItem(key) || "";

        const lower=key.toLowerCase();

        if(

            lower.includes("token") ||

            lower.includes("csrf") ||

            lower.includes("jwt") ||

            lower.includes("bearer") ||

            lower.includes("oauth") ||

            lower.includes("api") ||

            lower.includes("secret") ||

            lower.includes("session")

        ){

            AVAF.emit(

                "security",

                "storage-secret",

                key,

                {

                    length:value.length

                }

            );

        }

    }

}catch(e){}
/*=========================================================
Cookie Write Hook
=========================================================*/

{

    const descriptor = Object.getOwnPropertyDescriptor(

        Document.prototype,

        "cookie"

    );

    if(descriptor && descriptor.set){

        Object.defineProperty(

            document,

            "cookie",

            {

                configurable:true,

                enumerable:true,

                get(){

                    return descriptor.get.call(document);

                },

                set(value){

                    try{

                        const name=String(value)

                            .split("=")[0]

                            .trim();

                        addStorageArtifact(name);

                        storageEvent(

                            "cookie",

                            name,

                            {

                                runtime:true

                            }

                        );

                    }catch(e){}

                    return descriptor.set.call(

                        document,

                        value

                    );

                }

            }

        );

    }

}


/*=========================================================
postMessage
=========================================================*/

window.addEventListener(

    "message",

    event=>{

        AVAF.emit(

            "message",

            "postMessage",

            event.origin || "unknown"

        );

    }

);


/*=========================================================
BroadcastChannel
=========================================================*/

if(window.BroadcastChannel){

    const Original=window.BroadcastChannel;

    window.BroadcastChannel=class extends Original{

        constructor(name){

            AVAF.emit(

                "message",

                "BroadcastChannel",

                name

            );

            super(name);

        }

    };

}


/*=========================================================
Worker
=========================================================*/

if(window.Worker){

    const Original=window.Worker;

    window.Worker=class extends Original{

        constructor(script,options){

            AVAF.emit(

                "worker",

                "Worker",

                script

            );

            super(script,options);

        }

    };

}


/*=========================================================
SharedWorker
=========================================================*/

if(window.SharedWorker){

    const Original=window.SharedWorker;

    window.SharedWorker=class extends Original{

        constructor(script,options){

            AVAF.emit(

                "worker",

                "SharedWorker",

                script

            );

            super(script,options);

        }

    };

}


/*=========================================================
Service Worker
=========================================================*/

if(

    navigator.serviceWorker &&

    navigator.serviceWorker.register

){

    const original=navigator.serviceWorker.register;

    navigator.serviceWorker.register=function(url,options){

        AVAF.emit(

            "worker",

            "ServiceWorker",

            url

        );

        return original.apply(

            this,

            arguments

        );

    };

}


/*=========================================================
IndexedDB
=========================================================*/

if(window.indexedDB){

    const original=indexedDB.open;

    indexedDB.open=function(name,version){

        AVAF.emit(

            "storage",

            "indexedDB",

            name

        );

        return original.apply(

            this,

            arguments

        );

    };

}


/*=========================================================
Cache Storage
=========================================================*/

if(window.caches){

    const original=caches.open;

    caches.open=function(name){

        AVAF.emit(

            "storage",

            "cache",

            name

        );

        return original.apply(

            this,

            arguments

        );

    };

}


/*=========================================================
Clipboard
=========================================================*/

if(

    navigator.clipboard &&

    navigator.clipboard.writeText

){

    const original=navigator.clipboard.writeText;

    navigator.clipboard.writeText=function(text){

        AVAF.emit(

            "storage",

            "clipboard",

            "write"

        );

        return original.apply(

            this,

            arguments

        );

    };

}


/*=========================================================
JavaScript Errors
=========================================================*/

window.addEventListener(

    "error",

    event=>{

        AVAF.emit(

            "error",

            "javascript",

            event.message,

            {

                file:event.filename,

                line:event.lineno,

                column:event.colno

            }

        );

    }

);


/*=========================================================
Unhandled Promise Rejections
=========================================================*/

window.addEventListener(

    "unhandledrejection",

    event=>{

        AVAF.emit(

            "error",

            "promise",

            String(event.reason)

        );

    }

);

"""
