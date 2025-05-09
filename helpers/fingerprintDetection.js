// Instrumentation code for fingerprint detection
(function() {
  const MAX_NUM_CALLS_TO_INTERCEPT = 100;
  const STACK_LINE_REGEXP = /(\()?(http[^)]+):[0-9]+:[0-9]+(\))?/;
  let accessCounts = {};  // keep the access and call counts for each property and function
  const ENABLE_CONSOLE_LOGS = false;
  const console_log = function() {
    if (ENABLE_CONSOLE_LOGS){
      console.log.apply(console, arguments);
    }
  };
  const getSourceFromStack = function() {
    const stack = new Error().stack.split("\n");
    stack.shift();  // remove our own intercepting functions from the stack
    stack.shift();
    const res = stack[1].match(STACK_LINE_REGEXP);
    return res ? res[2] : "UNKNOWN_SOURCE";
  }

  const interceptFunctionCall = function (elementType, funcName) {
    // save the original function using a closure
    const origFunc = elementType.prototype[funcName];
    // overwrite the object method with our own
    Object.defineProperty(elementType.prototype, funcName, {
      value: function () {
        // execute the original function
        const retVal = origFunc.apply(this, arguments);
        const calledFunc = `${elementType.name}.${funcName}`;
        // check and enforce the limits
        // increment the call countl init if needed
        accessCounts[calledFunc] = (accessCounts[calledFunc] || 0) + 1;
        const callCnt = accessCounts[calledFunc];  // just a shorthand
        if (callCnt >= MAX_NUM_CALLS_TO_INTERCEPT) {
          console_log(`Reached max number of calls for ${calledFunc}: ${callCnt}`);
          // revert the function to its original state
          Object.defineProperty(elementType.prototype, funcName, {
            value: function () {return origFunc.apply(this, arguments);}
          });
          return retVal;
        }
        // we still haven't reached the limit; we intercept the call
        console_log(`Intercepted call to ${calledFunc} ${callCnt} times`);
        const source = getSourceFromStack();
        const callDetails = {
          description: calledFunc,
          accessType: "call",
          args: arguments,
          retVal,
          source
        };
        console_log(`Calling calledAPIEvent with ${JSON.stringify(callDetails)}`);
        // send the call details to the node context
        window.calledAPIEvent(callDetails);
        return retVal;
      }
    });
  };
  const interceptPropAccess = function (elementType, propertyName) {
    // Limit api calls to intercept
    // save the original property descriptor using a closure
    const origObjPropDesc = Object.getOwnPropertyDescriptor(
      elementType.prototype,
      propertyName
    );
    // log property name
    const accessedProp = `${elementType.name}.${propertyName}`
    Object.defineProperty(elementType.prototype, propertyName, {
      enumerable: true,
      configurable: true,
      get: function () {
        let returnVal = origObjPropDesc.get.call(this);
        // check and enforce the limits
        accessCounts[accessedProp] = (accessCounts[accessedProp] || 0) + 1;
        const accessCnt = accessCounts[accessedProp];  // just a shorthand
        if (accessCnt >= MAX_NUM_CALLS_TO_INTERCEPT) {
          console_log(`Reached max number of accesses for ${accessedProp}: ${accessCnt} `);
          // revert the setter to its original state
          Object.defineProperty(elementType.prototype, propertyName, {
            get: function () {return origObjPropDesc.get.call(this);}
          });
          return;
        }
        // we still haven't reached the limit; we intercept the access
        console_log(`Intercepted property access (get) ${accessedProp} (${accessCnt} times)`);
        const source = getSourceFromStack();
        const callDetails = {
          description: accessedProp,
          accessType: "get",
          args: "",
          source,
        };
        // send the call details to the node context
        window.calledAPIEvent(callDetails);
        return returnVal;
      },
      set: function (value) {
        // set the given value using the original property setter
        origObjPropDesc.set.call(this, value);
        // check and enforce the limits
        accessCounts[accessedProp] = (accessCounts[accessedProp] || 0) + 1;
        const accessCnt = accessCounts[accessedProp];  // just a shorthand
        if (accessCnt >= MAX_NUM_CALLS_TO_INTERCEPT) {
          console_log(`Reached max number of accesses for ${accessedProp}: ${accessCnt} `);
          // revert the setter to its original state
          Object.defineProperty(elementType.prototype, propertyName, {
            set: function () {return origObjPropDesc.set.call(this, value);}
          });
          return;
        }
        // we still haven't reached the limit; we intercept the access
        console_log(`Intercepted property access (set) ${accessedProp} (${accessCnt} times)`);
        const source = getSourceFromStack();
        const callDetails = {
          description: accessedProp,
          accessType: "set",
          args: value,
          source,
        };
        // send the call details to the node context
        window.calledAPIEvent(callDetails);
      },
    });
  };
  //
  // // CANVAS FINGERPRINTING
  // // The canvas element text is written with fillText or strokeText methods.
  // interceptFunctionCall(CanvasRenderingContext2D, "fillText");
  // interceptFunctionCall(CanvasRenderingContext2D, "strokeText");
  // // The style is applied with fillStyle or strokeStyle properties.
  // interceptPropAccess(CanvasRenderingContext2D, "fillStyle");
  // interceptPropAccess(CanvasRenderingContext2D, "strokeStyle");
  // // The script calls toDataURL method to extract the image.
  // interceptFunctionCall(HTMLCanvasElement, "toDataURL");
  // // The script does not call save, restore or addEventListener methods on the canvas element
  // interceptFunctionCall(CanvasRenderingContext2D, "save");
  // interceptFunctionCall(CanvasRenderingContext2D, "restore");
  // interceptFunctionCall(CanvasRenderingContext2D, "addEventListener");
  // // TODO: check after inspecting canvas images whether we need to filter
  // // out "device class fingerprinting" attempts a la Picasso
  //
  // // CANVAS FONT FINGERPRINTING
  // // The script sets the font property on a canvas element to more than 20 different times.
  // interceptPropAccess(CanvasRenderingContext2D, "font");
  // // The script calls the measureText method of the rendering context more than 20 times.
  // interceptFunctionCall(CanvasRenderingContext2D, "measureText");
  // interceptFunctionCall(CanvasRenderingContext2D, "isPointInPath");
  //
  // // AUDIOCONTEXT FINGERPRINTING
  // // The script calls any of the createOscillator, createDynamicsCompressor, destination, startRendering, oncomplete method of the audio context.
  // interceptFunctionCall(OfflineAudioContext, "createOscillator");
  // interceptFunctionCall(OfflineAudioContext, "createDynamicsCompressor");
  // interceptPropAccess(BaseAudioContext, "destination");
  // interceptFunctionCall(OfflineAudioContext, "startRendering");
  // interceptPropAccess(OfflineAudioContext, "oncomplete");


  // WEBRTC FINGERPRINTING
  // The script calls createDataChannel or createOffer methods of the WebRTC peer connection.
  interceptFunctionCall(RTCPeerConnection, "createDataChannel"); // Label parameter can contain string
  interceptFunctionCall(RTCPeerConnection, "createOffer"); // Returns promise with "sdp" field; a string

  // The script calls onicecandidate or localDescription methods of the WebRTC peer connection.
  interceptPropAccess(RTCPeerConnection, "onicecandidate"); // Not sure if we can remove this yet TODO
  // interceptPropAccess(RTCPeerConnection, "localDescription"); // Removed because setLocalDesc is more interesting

  // From here on we extended the intercepts to extensively crawl WebRTC usage
  interceptFunctionCall(RTCPeerConnection, "setLocalDescription"); // FB showed to use this to exfiltrate data
  interceptFunctionCall(RTCPeerConnection, "setRemoteDescription"); // Interesting in the same way
  interceptFunctionCall(RTCPeerConnection, "addIceCandidate"); // Promising! Adds candidate which is a string normally containing information
  interceptFunctionCall(RTCPeerConnection, "createAnswer"); // Promising? Returns a promise containing SDP & type, also has unused options argument
  interceptFunctionCall(RTCPeerConnection, "setConfiguration"); // Could be promising because the configuration is shared (?) and can contain a lot of strings TODO also add the constructor then!
  // interceptFunctionCall(RTCPeerConnection, "setIdentityProvider"); // Sets strings. In particular username can be interesting TODO chrome does not support, remove?

  interceptFunctionCall(RTCDataChannel, "send");

  interceptFunctionCall(RTCRtpSender, "setParameters"); // Might be interesting because strings are set. In particular rid

  // interceptPropAccess(RTCDataChannel, "label"); Pure getter
  // interceptPropAccess(RTCDataChannel, "protocol"); Pure getter
  // interceptPropAccess(RTCDataChannel, "readyState"); Pure getter
  // interceptPropAccess(RTCPeerConnection, "iceGatheringState"); Pure getter
  // interceptPropAccess(RTCPeerConnection, "remoteDescription"); Pure getter
  // interceptPropAccess(RTCPeerConnection, "sctp"); Pure getter
  // interceptPropAccess(RTCPeerConnection, "signalingState"); Pure getter
  // interceptFunctionCall(RTCPeerConnection, "addStream"); // DEPRECATED MediaStream object contains ID which is string, but string cannot be set manually
  // interceptFunctionCall(RTCPeerConnection, "addTrack"); // MediaStreamTrack contains more strings, but idem
  // interceptFunctionCall(RTCPeerConnection, "addTransceiver"); // Similar to addTrack
  // interceptFunctionCall(RTCPeerConnection, "createDTMFSender"); // Not needed according to Gunes
  // interceptFunctionCall(RTCPeerConnection, "getStats"); // Selector parameter with mediastreamtrack, but decided not to look for those
  // interceptFunctionCall(RTCPeerConnection, "removeStream"); // Idem
  // interceptFunctionCall(RTCPeerConnection, "removeTrack"); // Idem


  // interceptFunctionCall(RTCPeerConnection, "restartIce"); // Can request ICE restarts in which candidates are shared, but we're only interested in the sharing itself
  // interceptPropAccess(RTCIceCandidate, "candidate"); Pure getter
  // interceptPropAccess(RTCPeerConnectionIceEvent, "candidate"); Pure getter
  // interceptPropAccess(RTCSessionDescription, "sdp"); Pure getter
})();