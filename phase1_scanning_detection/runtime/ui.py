"""
AVAF PRO
Runtime UI Instrumentation

Discovers runtime attack surfaces only.
"""

"""
===============================================================================
AVAF PRO

Runtime UI Instrumentation

Discovers runtime attack surface from the live DOM.

This file remains inside the Runtime IIFE.

===============================================================================
"""

UI_HOOK = r"""

/*=========================================================================
Helpers
=========================================================================*/

function addArtifact(type,value){

    if(value===undefined || value===null)
        return;

    value=String(value).trim();

    if(!value)
        return;

    if(!(type in AVAF.artifacts))
        return;

    AVAF.artifacts[type].add(value);

}


function addParameter(
    name,
    metadata = {}
){

    if(!name)
        return;

    name=String(name).trim();

    if(!name)
        return;

    /*
     * Preserve the simple artifact for compatibility.
     */
    AVAF.artifacts.parameters.add(
        name
    );

    /*
     * Preserve structured browser-observed
     * parameter evidence.
     */
    if(
        !AVAF.runtime ||
        !Array.isArray(
            AVAF.runtime.parameters
        )
    ){
        return;
    }

    const parameter = {

        name:name,

        value:
            metadata.value || "",

        type:
            metadata.type || "text",

        location:
            metadata.location || "runtime",

        url:
            metadata.url ||
            location.href

    };

    const signature =
        parameter.name +
        "|" +
        parameter.location +
        "|" +
        parameter.url;

    const exists =
        AVAF.runtime.parameters.some(
            function(item){

                if(!item)
                    return false;

                return (
                    String(
                        item.name || ""
                    ) +
                    "|" +
                    String(
                        item.location || ""
                    ) +
                    "|" +
                    String(
                        item.url || ""
                    )
                ) === signature;

            }
        );

    if(!exists){

        AVAF.runtime.parameters.push(
            parameter
        );

    }

}

function inspectLink(element){

    if(!(element instanceof HTMLAnchorElement))
        return;

    if(!element.href)
        return;

    addArtifact(

        "links",

        element.href

    );

    addArtifact(

        "pages",

        element.href

    );

    AVAF.emit(

        "navigation",

        "link",

        element.href,

        {

            target:element.target||"",

            rel:element.rel||""

        }

    );

}


function inspectRoute(){

    addArtifact(

        "routes",

        location.pathname

    );

    addArtifact(

        "pages",

        location.href

    );

}

function inspectParameters(element){

    if(
        !(element instanceof HTMLInputElement) &&
        !(element instanceof HTMLTextAreaElement) &&
        !(element instanceof HTMLSelectElement)
    ){
        return;
    }

    const name =
        String(
            element.name || ""
        ).trim();

    /*
     * Only a real form-control name is a
     * legitimate runtime parameter.
     *
     * id and data-testid are NOT parameters.
     */
    if(!name)
        return;

    addParameter(
        name,
        {
            value:
                element.value || "",

            type:
                element.type ||
                element.tagName.toLowerCase(),

            location:
                "runtime",

            url:
                location.href
        }
    );

}


function inspectGeneric(element){

    if(!(element instanceof Element))
        return;

    inspectParameters(

        element

    );

    if(element.matches("a[href]"))

        inspectLink(

            element

        );

}
/*=========================================================================
Form Discovery
=========================================================================*/

function inspectForm(form){

    if(!(form instanceof HTMLFormElement))
        return;

    const action=form.action || location.href;

    addArtifact("forms",action);

    addArtifact("pages",action);

    AVAF.emit(

        "form",

        "runtime",

        action,

        {

            method:(form.method || "GET").toUpperCase(),

            enctype:form.enctype || ""

        }

    );

    if(
        AVAF.runtime &&
        Array.isArray(AVAF.runtime.forms)
    ){

        const formRecord = {
            action:action,
            method:(form.method || "GET").toUpperCase(),
            url:location.href
        };

        const formSignature =
            formRecord.action + "|" +
            formRecord.method;

        if(
            !AVAF.runtime.forms.some(
                item =>
                    item.action + "|" +
                    item.method === formSignature
            )
        ){

            AVAF.runtime.forms.push(formRecord);

        }

    }

    form.querySelectorAll(
        "input,textarea,select"
    ).forEach(
        inspectInput
    );

}


/*=========================================================================
Input Discovery
=========================================================================*/

function inspectInput(input){

    if(!(input instanceof HTMLElement))
        return;

    if(input.name){

        addParameter(
            input.name,
            {
                value:input.value || "",
                type:input.type || input.tagName.toLowerCase(),
                location:"runtime",
                url:location.href
            }
        );

        if(
            AVAF.runtime &&
            Array.isArray(AVAF.runtime.controls)
        ){

            const control = {
                name:input.name,
                value:input.value || "",
                type:input.type || "text",
                url:location.href
            };

            const signature =
                control.url + "|" +
                control.name + "|" +
                control.type;

            if(
                !AVAF.runtime.controls.some(
                    item =>
                        item.url + "|" +
                        item.name + "|" +
                        item.type === signature
                )
            ){

                AVAF.runtime.controls.push(control);

            }

        }

    }

    if(input instanceof HTMLInputElement){

        const type=(

            input.type ||

            "text"

        ).toLowerCase();

        switch(type){

            case "password":

                AVAF.emit(

                    "security",

                    "password",

                    input.name || input.id || "password"

                );

                break;

            case "file":

                addArtifact(

                    "uploads",

                    input.name || input.id || "upload"

                );

                AVAF.emit(

                    "upload",

                    "file",

                    input.name || input.id || "upload",

                    {

                        accept:input.accept || "",

                        multiple:input.multiple

                    }

                );

                break;

            case "hidden":

            {

                const name=(

                    input.name ||

                    ""

                ).toLowerCase();

                if(

                    name.includes("csrf") ||

                    name.includes("token") ||

                    name.includes("jwt")

                ){

                    AVAF.emit(

                        "security",

                        "token",

                        name

                    );

                }

                break;

            }

        }

    }

}


/*=========================================================================
Button Discovery
=========================================================================*/

function inspectButton(button){

    if(!(button instanceof HTMLButtonElement))
        return;

    AVAF.emit(

        "ui",

        "button",

        button.innerText.trim(),

        {

            type:button.type || "submit"

        }

    );

}


/*=========================================================================
Iframe Discovery
=========================================================================*/

function inspectIframe(frame){

    if(!(frame instanceof HTMLIFrameElement))
        return;

    if(frame.src)

        addArtifact(

            "pages",

            frame.src

        );

    AVAF.emit(

        "iframe",

        "runtime",

        frame.src || "",

        {

            sandbox:

                frame.sandbox.value ||

                ""

        }

    );

}


/*=========================================================================
Master Inspector
=========================================================================*/

function inspectElement(element){

    if(!(element instanceof Element))
        return;

    inspectGeneric(

        element

    );

    if(

        element.matches("form")

    )

        inspectForm(

            element

        );

    if(

        element.matches(

            "input,textarea,select"

        )

    )

        inspectInput(

            element

        );

    if(

        element.matches(

            "button"

        )

    )

        inspectButton(

            element

        );

    if(

        element.matches(

            "iframe"

        )

    )

        inspectIframe(

            element

        );

}
/*=========================================================================
Initial Discovery
=========================================================================*/

function initialDiscovery(){

    document.querySelectorAll("*").forEach(

        inspectElement

    );

}

initialDiscovery();


/*=========================================================================
Mutation Observer
=========================================================================*/

const observer = new MutationObserver(

    mutations=>{

        for(const mutation of mutations){

            for(const node of mutation.addedNodes){

                if(!(node instanceof Element))
                    continue;

                inspectElement(node);

                node.querySelectorAll("*").forEach(

                    inspectElement

                );

            }

        }

    }

);


/*=========================================================================*
Safe DOM Observer Installation
=========================================================================*/

function installUIObserver(){

    const root = document.documentElement;

    if(

        !root ||

        typeof root.nodeType !== "number" ||

        root.nodeType !== 1

    ){

        return false;

    }

    try{

        observer.observe(

            root,

            {

                childList:true,

                subtree:true

            }

        );

        return true;

    }catch(error){

        console.warn(

            "[AVAF]",

            "UI MutationObserver installation failed",

            error

        );

        return false;

    }

}


function bootUIObserver(){

    if(installUIObserver())
        return;

    let attempts = 0;

    const maxAttempts = 100;

    function retry(){

        attempts++;

        if(installUIObserver())
            return;

        if(attempts >= maxAttempts){

            console.warn(

                "[AVAF]",

                "UI MutationObserver could not initialize"

            );

            return;

        }

        setTimeout(

            retry,

            25

        );

    }

    setTimeout(

        retry,

        0

    );

}


bootUIObserver();


/*=========================================================================
Anchor Click Discovery
=========================================================================*/

document.addEventListener(

    "click",

    event=>{

        const link=event.target.closest("a[href]");

        if(!link)
            return;

        addArtifact(

            "links",

            link.href

        );

        addArtifact(

            "pages",

            link.href

        );

        AVAF.emit(

            "navigation",

            "link_click",

            link.href

        );

    },

    true

);


/*=========================================================================
Form Submit Discovery
=========================================================================*/

document.addEventListener(

    "submit",

    event=>{

        const form=event.target;

        if(!(form instanceof HTMLFormElement))
            return;

        inspectForm(form);

        AVAF.emit(

            "form",

            "submit",

            form.action || location.href,

            {

                method:(form.method || "GET").toUpperCase()

            }

        );

    },

    true

);


/*=========================================================================
File Upload Discovery
=========================================================================*/

document.addEventListener(

    "change",

    event=>{

        const input=event.target;

        if(!(input instanceof HTMLInputElement))
            return;

        if(input.type!=="file")
            return;

        addArtifact(

            "uploads",

            input.name || input.id || "upload"

        );

        AVAF.emit(

            "upload",

            "selected",

            input.name || input.id || "upload",

            {

                files:input.files ? input.files.length : 0

            }

        );

    },

    true

);


/*=========================================================================
Periodic SPA Scan
=========================================================================*/

setInterval(

    ()=>{

        initialDiscovery();

    },

    2000

);


/*=========================================================================
Runtime Ready
=========================================================================*/

console.log(

    "[AVAF]",

    "UI Runtime Ready"

);
"""