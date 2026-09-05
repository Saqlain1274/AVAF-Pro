"""
AVAF PRO
Runtime Network Instrumentation
"""

NETWORK_HOOK = r"""

/*==========================================================
 Runtime Network Instrumentation
==========================================================*/

console.info(

    "[AVAF]",

    "Installing Network Hooks"

);


/*==========================================================
 Helpers
==========================================================*/

AVAF.network={};

AVAF.network.emit=function(

    subtype,

    url,

    metadata={}

){

    url=AVAF.normalize(url);

    if(!url)
        return;

    AVAF.emit(

        "network",

        subtype,

        url,

        metadata

    );

};

AVAF.network.error=function(

    subtype,

    url,

    error

){

    AVAF.emit(

        "error",

        subtype,

        url,

        {

            message:String(error)

        }

    );

};


/*==========================================================
 Fetch API
==========================================================*/

AVAF.network.originalFetch=window.fetch;

window.fetch=async function(...args){

    const start=performance.now();

    const resource=args[0];

    const options=args[1] || {};

    const method=(

        options.method ||

        "GET"

    ).toUpperCase();

    const url=(

        typeof resource==="string"

            ? resource

            : resource.url

    );

    try{

        const response=

            await AVAF.network.originalFetch.apply(

                this,

                args

            );

        const duration=Math.round(

            performance.now()-start

        );

        AVAF.network.emit(

            "fetch",

            url,

            {

                method:method,

                status:response.status,

                duration:duration

            }

        );

        AVAF.addFetch(url);

        AVAF.addEndpoint(url);

        AVAF.addParameters(url);

        if(

            url.toLowerCase().includes(

                "graphql"

            )

        ){

            AVAF.addGraphQL(url);

        }

        return response;

    }

    catch(error){

        AVAF.network.error(

            "fetch",

            url,

            error

        );

        throw error;

    }

};

console.info(

    "[AVAF]",

    "Fetch Hook Installed"

);

/*==========================================================
 XMLHttpRequest
==========================================================*/

AVAF.network.originalOpen=XMLHttpRequest.prototype.open;

AVAF.network.originalSend=XMLHttpRequest.prototype.send;

XMLHttpRequest.prototype.open=function(

    method,

    url,

    ...args

){

    this.__avaf={

        method:(method || "GET").toUpperCase(),

        url:url,

        started:0

    };

    return AVAF.network.originalOpen.call(

        this,

        method,

        url,

        ...args

    );

};

XMLHttpRequest.prototype.send=function(body){

    if(this.__avaf){

        this.__avaf.started=performance.now();

    }

    this.addEventListener(

        "loadend",

        ()=>{

            if(!this.__avaf)
                return;

            const duration=Math.round(

                performance.now()

                -

                this.__avaf.started

            );

            AVAF.network.emit(

                "xhr",

                this.__avaf.url,

                {

                    method:this.__avaf.method,

                    status:this.status,

                    duration:duration

                }

            );

            AVAF.addXHR(

                this.__avaf.url

            );

            AVAF.addEndpoint(

                this.__avaf.url

            );

            AVAF.addParameters(

                this.__avaf.url

            );

            if(

                this.__avaf.url.toLowerCase().includes(

                    "graphql"

                )

            ){

                AVAF.addGraphQL(

                    this.__avaf.url

                );

            }

        }

    );

    return AVAF.network.originalSend.call(

        this,

        body

    );

};


/*==========================================================
 WebSocket
==========================================================*/

AVAF.network.originalWebSocket=window.WebSocket;

window.WebSocket=function(url,protocols){

    AVAF.network.emit(

        "websocket",

        url

    );

    AVAF.addWebSocket(url);

    AVAF.addEndpoint(url);

    return new AVAF.network.originalWebSocket(

        url,

        protocols

    );

};

window.WebSocket.prototype=

    AVAF.network.originalWebSocket.prototype;


/*==========================================================
 Beacon
==========================================================*/

if(navigator.sendBeacon){

    AVAF.network.originalBeacon=

        navigator.sendBeacon;

    navigator.sendBeacon=function(

        url,

        data

    ){

        AVAF.network.emit(

            "beacon",

            url,

            {

                size:data

                    ? String(data).length

                    :0

            }

        );

        AVAF.addEndpoint(url);

        AVAF.addParameters(url);

        return AVAF.network.originalBeacon.call(

            navigator,

            url,

            data

        );

    };

}


/*==========================================================
 EventSource
==========================================================*/

if(window.EventSource){

    AVAF.network.originalEventSource=

        window.EventSource;

    window.EventSource=function(

        url,

        config

    ){

        AVAF.network.emit(

            "eventsource",

            url

        );

        AVAF.addEndpoint(url);

        AVAF.addParameters(url);

        return new AVAF.network.originalEventSource(

            url,

            config

        );

    };

    window.EventSource.prototype=

        AVAF.network.originalEventSource.prototype;

}


/*==========================================================
 Ready
==========================================================*/

console.info(

    "[AVAF]",

    "Network Hooks Ready"

);

"""
