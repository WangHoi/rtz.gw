var rtz = rtz || {};
rtz.sessions = {};
rtz.webRTCAdapter = adapter;
rtz.noop = function() {};

rtz.init = function(options) {
	options = options || {};
	options.callback = (typeof options.callback == "function") ? options.callback : rtz.noop;
	if(rtz.initDone === true) {
		// Already initialized
		options.callback();
	} else {
		rtz.log = console.log.bind(console);
		rtz.error = console.error.bind(console);
		rtz.warn = console.warn.bind(console);
		rtz.info = console.info.bind(console);
		rtz.debug = console.debug.bind(console);
		rtz.trace = console.trace.bind(console);

		// Helper methods to attach/reattach a stream to a video element (previously part of adapter.js)
		rtz.attachMediaStream = function(element, stream) {
			if(rtz.webRTCAdapter.browserDetails.browser === 'chrome') {
				var chromever = rtz.webRTCAdapter.browserDetails.version;
				if(chromever >= 52) {
					element.srcObject = stream;
				} else if(typeof element.src !== 'undefined') {
					element.src = URL.createObjectURL(stream);
				} else {
					rtz.error("Error attaching stream to element");
				}
			} else {
				element.srcObject = stream;
			}
		};
		rtz.reattachMediaStream = function(to, from) {
			to.srcObject = from.srcObject;
		};
		// Detect tab close: make sure we don't loose existing onbeforeunload handlers
		// (note: for iOS we need to subscribe to a different event, 'pagehide', see
		// https://gist.github.com/thehunmonkgroup/6bee8941a49b86be31a787fe8f4b8cfe)
		var iOS = ['iPad', 'iPhone', 'iPod'].indexOf(navigator.platform) >= 0;
		var eventName = iOS ? 'pagehide' : 'beforeunload';
		var oldOBF = window["on" + eventName];
		window.addEventListener(eventName, function(event) {
			rtz.log("Closing window");
			for(var s in rtz.sessions) {
				if(rtz.sessions[s] !== null && rtz.sessions[s] !== undefined &&
						rtz.sessions[s].destroyOnUnload) {
					rtz.log("Destroying session " + s);
					rtz.sessions[s].destroy({asyncRequest: false, notifyDestroyed: false});
				}
			}
			if(oldOBF && typeof oldOBF == "function")
				oldOBF();
		});

		rtz.initDone = true;
		options.callback();
	}
};

rtz.isWebrtcSupported = function() {
	return window.RTCPeerConnection !== undefined && window.RTCPeerConnection !== null &&
		navigator.getUserMedia !== undefined && navigator.getUserMedia !== null;
};

rtz.randomString = function(len) {
	var charSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	var randomString = '';
	for (var i = 0; i < len; i++) {
		var randomPoz = Math.floor(Math.random() * charSet.length);
		randomString += charSet.substring(randomPoz,randomPoz+1);
	}
	return randomString;
};

function RtzSession(gatewayCallbacks) {
	if(rtz.initDone === undefined) {
		gatewayCallbacks.error("Library not initialized");
		return {};
	}
	if(!rtz.isWebrtcSupported()) {
		gatewayCallbacks.error("WebRTC not supported by this browser");
		return {};
	}
    rtz.log("Library initialized: " + rtz.initDone);
    
	gatewayCallbacks = gatewayCallbacks || {};
	gatewayCallbacks.success = (typeof gatewayCallbacks.success == "function") ? gatewayCallbacks.success : rtz.noop;
	gatewayCallbacks.error = (typeof gatewayCallbacks.error == "function") ? gatewayCallbacks.error : rtz.noop;
	gatewayCallbacks.destroyed = (typeof gatewayCallbacks.destroyed == "function") ? gatewayCallbacks.destroyed : rtz.noop;
	if(gatewayCallbacks.server === null || gatewayCallbacks.server === undefined) {
		gatewayCallbacks.error("Invalid server url");
		return {};
	}
	var ws = null;
	var wsHandlers = {};
	var wsKeepaliveTimeoutId = null;
    var server = gatewayCallbacks.server;
	this.destroyOnUnload = true;
	if(gatewayCallbacks.destroyOnUnload !== undefined && gatewayCallbacks.destroyOnUnload !== null)
		this.destroyOnUnload = (gatewayCallbacks.destroyOnUnload === true);

    var keepAlivePeriod = 25000;
	if(gatewayCallbacks.keepAlivePeriod !== undefined && gatewayCallbacks.keepAlivePeriod !== null)
		keepAlivePeriod = gatewayCallbacks.keepAlivePeriod;
	if(isNaN(keepAlivePeriod))
		keepAlivePeriod = 25000;

    var connected = false;
    var sessionId = null;
    var streamHandles = {};
    var that = this;
    var transactions = {};
    createSession(gatewayCallbacks);

    this.getServer = function() { return server; }
	this.isConnected = function() { return connected; };
	this.reconnect = function(callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : rtz.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : rtz.noop;
		callbacks["reconnect"] = true;
		createSession(callbacks);
	};
	this.getSessionId = function() { return sessionId; };
	this.destroy = function(callbacks) { destroySession(callbacks); };
	this.createHandle = function(callbacks) { createHandle(callbacks); };

	function handleEvent(json, skipTimeout) {
		if(json["type"] === "keepalive") {
			// Nothing happened
			rtz.debug("Got a keepalive on session " + sessionId);
			return;
		} else if(json["type"] === "ack") {
			// Just an ack, we can probably ignore
			rtz.debug("Got an ack on session " + sessionId);
			rtz.debug(json);
			var transaction = json["transaction"];
			if(transaction !== null && transaction !== undefined) {
				var reportSuccess = transactions[transaction];
				if(reportSuccess !== null && reportSuccess !== undefined) {
					reportSuccess(json);
				}
				delete transactions[transaction];
			}
			return;
		} else if(json["type"] === "success") {
			// Success!
			rtz.debug("Got a success on session " + sessionId);
			rtz.debug(json);
			var transaction = json["transaction"];
			if(transaction !== null && transaction !== undefined) {
				var reportSuccess = transactions[transaction];
				if(reportSuccess !== null && reportSuccess !== undefined) {
					reportSuccess(json);
				}
				delete transactions[transaction];
			}
			return;
		} else if(json["type"] === "trickle") {
			// We got a trickle candidate from rtz
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				rtz.warn("Missing sender...");
				return;
			}
			var streamHandle = streamHandles[sender];
			if(streamHandle === undefined || streamHandle === null) {
				rtz.debug("This handle is not attached to this session");
				return;
			}
			var candidate = json["candidate"];
			rtz.debug("Got a trickled candidate on session " + sessionId);
			rtz.debug(candidate);
			var config = streamHandle.webrtcStuff;
			if(config.pc && config.remoteSdp) {
				// Add candidate right now
				rtz.debug("Adding remote candidate:", candidate);
				if(!candidate || candidate.completed === true) {
					// end-of-candidates
					config.pc.addIceCandidate();
				} else {
					// New candidate
					config.pc.addIceCandidate(candidate);
				}
			} else {
				// We didn't do setRemoteDescription (trickle got here before the offer?)
				rtz.debug("We didn't do setRemoteDescription (trickle got here before the offer?), caching candidate");
				if(!config.candidates)
					config.candidates = [];
				config.candidates.push(candidate);
				rtz.debug(config.candidates);
			}
		} else if(json["type"] === "webrtcup") {
			// The PeerConnection with the server is up! Notify this
			rtz.debug("Got a webrtcup event on session " + sessionId);
			rtz.debug(json);
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				rtz.warn("Missing sender...");
				return;
			}
			var streamHandle = streamHandles[sender];
			if(streamHandle === undefined || streamHandle === null) {
				rtz.debug("This handle is not attached to this session");
				return;
			}
			streamHandle.webrtcState(true);
			return;
		} else if(json["type"] === "destroyed") {
			// Server asked us to destroy one of our handles
			rtz.debug("Got a destroyed event on session " + sessionId);
			rtz.debug(json);
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				rtz.warn("Missing sender...");
				return;
			}
			var streamHandle = streamHandles[sender];
			if(streamHandle === undefined || streamHandle === null) {
				// Don't warn here because destroyHandle causes this situation.
				return;
			}
			streamHandle.destroyed = true;
			streamHandle.ondestroyed();
			streamHandle.destroy();
		} else if(json["type"] === "media") {
			// Media started/stopped flowing
			rtz.debug("Got a media event on session " + sessionId);
			rtz.debug(json);
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				rtz.warn("Missing sender...");
				return;
			}
			var streamHandle = streamHandles[sender];
			if(streamHandle === undefined || streamHandle === null) {
				rtz.debug("This handle is not attached to this session");
				return;
			}
			streamHandle.mediaState(json["type"], json["receiving"]);
		} else if(json["type"] === "slowlink") {
			rtz.debug("Got a slowlink event on session " + sessionId);
			rtz.debug(json);
			// Trouble uplink or downlink
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				rtz.warn("Missing sender...");
				return;
			}
			var streamHandle = streamHandles[sender];
			if(streamHandle === undefined || streamHandle === null) {
				rtz.debug("This handle is not attached to this session");
				return;
			}
			streamHandle.slowLink(json["uplink"], json["nacks"]);
		} else if(json["type"] === "error") {
			// Oops, something wrong happened
			rtz.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
			rtz.debug(json);
			var transaction = json["transaction"];
			if(transaction !== null && transaction !== undefined) {
				var reportSuccess = transactions[transaction];
				if(reportSuccess !== null && reportSuccess !== undefined) {
					reportSuccess(json);
				}
				delete transactions[transaction];
			}
			return;
		} else if(json["type"] === "event") {
			rtz.debug("Got a server event on session " + sessionId);
			rtz.debug(json);
			var sender = json["sender"];
			if(sender === undefined || sender === null) {
				rtz.warn("Missing sender...");
				return;
			}
			var data = json["data"];
			rtz.debug(data);
			var streamHandle = streamHandles[sender];
			if(streamHandle === undefined || streamHandle === null) {
				rtz.warn("This handle is not attached to this session");
				return;
			}
			var jsep = json["jsep"];
			if(jsep !== undefined && jsep !== null) {
				rtz.debug("Handling SDP as well...");
				rtz.debug(jsep);
			}
			var callback = streamHandle.onmessage;
			if(callback !== null && callback !== undefined) {
				rtz.debug("Notifying application...");
				// Send to callback specified when attaching stream handle
				callback(data, jsep);
			} else {
				// Send to generic callback (?)
				rtz.debug("No provided notification callback");
			}
		} else if(json["type"] === "timeout") {
			rtz.error("Timeout on session " + sessionId);
			rtz.debug(json);
			if (websockets) {
				ws.close(3504, "Gateway timeout");
			}
			return;
		} else {
			rtz.warn("Unknown message/event  '" + json["type"] + "' on session " + sessionId);
			rtz.debug(json);
		}
	}

	// Private helper to send keep-alive messages on WebSockets
	function keepAlive() {
		if(server === null || !connected)
			return;
		wsKeepaliveTimeoutId = setTimeout(keepAlive, keepAlivePeriod);
		var request = { "type": "keepalive", "session_id": sessionId, "transaction": rtz.randomString(12) };
		ws.send(JSON.stringify(request));
	}

    function createSession(callbacks) {
		var transaction = rtz.randomString(12);
		var request = { "type": "createSession", "transaction": transaction };
		if(callbacks["reconnect"]) {
			// We're reconnecting, claim the session
			connected = false;
			request["type"] = "claim";
			request["session_id"] = sessionId;
			// If we were using websockets, ignore the old connection
            ws.onopen = null;
            ws.onerror = null;
            ws.onclose = null;
            if(wsKeepaliveTimeoutId) {
                clearTimeout(wsKeepaliveTimeoutId);
                wsKeepaliveTimeoutId = null;
            }
		}
        ws = new WebSocket(server);
        wsHandlers = {
            'error': function() {
                rtz.error("Error connecting to the rtz WebSockets server... " + server);
            },

            'open': function() {
                // We need to be notified about the success
                transactions[transaction] = function(json) {
                    rtz.debug(json);
                    if (json["type"] !== "success") {
                        rtz.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
                        callbacks.error(json["error"].reason);
                        return;
                    }
                    wsKeepaliveTimeoutId = setTimeout(keepAlive, keepAlivePeriod);
                    connected = true;
                    sessionId = json["session_id"] ? json["session_id"] : json["id"];
                    if(callbacks["reconnect"]) {
                        rtz.log("Claimed session: " + sessionId);
                    } else {
                        rtz.log("Created session: " + sessionId);
                    }
                    rtz.sessions[sessionId] = that;
                    callbacks.success();
                };
                ws.send(JSON.stringify(request));
            },

            'message': function(event) {
                handleEvent(JSON.parse(event.data));
            },

            'close': function() {
                if (server === null || !connected) {
                    return;
                }
                connected = false;
                // FIXME What if this is called when the page is closed?
                gatewayCallbacks.error("Lost connection to the server (is it down?)");
            }
        };

        for(var eventName in wsHandlers) {
            ws.addEventListener(eventName, wsHandlers[eventName]);
        }
	};

	// Private method to destroy a session
	function destroySession(callbacks) {
		callbacks = callbacks || {};
		// FIXME This method triggers a success even when we fail
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : rtz.noop;
		var asyncRequest = true;
		if(callbacks.asyncRequest !== undefined && callbacks.asyncRequest !== null)
			asyncRequest = (callbacks.asyncRequest === true);
		var notifyDestroyed = true;
		if(callbacks.notifyDestroyed !== undefined && callbacks.notifyDestroyed !== null)
			notifyDestroyed = (callbacks.notifyDestroyed === true);
		rtz.log("Destroying session " + sessionId + " (async=" + asyncRequest + ")");
		if(!connected) {
			rtz.warn("Is the server down? (connected=false)");
			callbacks.success();
			return;
		}
		if(sessionId === undefined || sessionId === null) {
			rtz.warn("No session to destroy");
			callbacks.success();
			if(notifyDestroyed)
				gatewayCallbacks.destroyed();
			return;
		}
		delete rtz.sessions[sessionId];
		// No need to destroy all handles first, rtz will do that itself
		var request = { "type": "destroySession", "transaction": rtz.randomString(12) };
        request["session_id"] = sessionId;

        var unbindWebSocket = function() {
            for(var eventName in wsHandlers) {
                ws.removeEventListener(eventName, wsHandlers[eventName]);
            }
            ws.removeEventListener('message', onUnbindMessage);
            ws.removeEventListener('error', onUnbindError);
            if(wsKeepaliveTimeoutId) {
                clearTimeout(wsKeepaliveTimeoutId);
            }
            ws.close();
        };

        var onUnbindMessage = function(event){
            var data = JSON.parse(event.data);
            if(data.session_id == request.session_id && data.transaction == request.transaction) {
                unbindWebSocket();
                callbacks.success();
                if(notifyDestroyed)
                    gatewayCallbacks.destroyed();
            }
        };
        var onUnbindError = function(event) {
            unbindWebSocket();
            callbacks.error("Failed to destroy the server: Is the server down?");
            if(notifyDestroyed)
                gatewayCallbacks.destroyed();
        };

        ws.addEventListener('message', onUnbindMessage);
        ws.addEventListener('error', onUnbindError);

        ws.send(JSON.stringify(request));
	};

	// Private method to create a stream handle
	function createHandle(callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : rtz.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : rtz.noop;
		callbacks.consentDialog = (typeof callbacks.consentDialog == "function") ? callbacks.consentDialog : rtz.noop;
		callbacks.iceState = (typeof callbacks.iceState == "function") ? callbacks.iceState : rtz.noop;
		callbacks.mediaState = (typeof callbacks.mediaState == "function") ? callbacks.mediaState : rtz.noop;
		callbacks.webrtcState = (typeof callbacks.webrtcState == "function") ? callbacks.webrtcState : rtz.noop;
		callbacks.slowLink = (typeof callbacks.slowLink == "function") ? callbacks.slowLink : rtz.noop;
		callbacks.onmessage = (typeof callbacks.onmessage == "function") ? callbacks.onmessage : rtz.noop;
		callbacks.onlocalstream = (typeof callbacks.onlocalstream == "function") ? callbacks.onlocalstream : rtz.noop;
		callbacks.onremotestream = (typeof callbacks.onremotestream == "function") ? callbacks.onremotestream : rtz.noop;
		callbacks.ondata = (typeof callbacks.ondata == "function") ? callbacks.ondata : rtz.noop;
		callbacks.ondataopen = (typeof callbacks.ondataopen == "function") ? callbacks.ondataopen : rtz.noop;
		callbacks.oncleanup = (typeof callbacks.oncleanup == "function") ? callbacks.oncleanup : rtz.noop;
		callbacks.ondestroyed = (typeof callbacks.ondestroyed == "function") ? callbacks.ondestroyed : rtz.noop;
		if(!connected) {
			rtz.warn("Is the server down? (connected=false)");
			callbacks.error("Is the server down? (connected=false)");
			return;
		}
		var opaqueId = callbacks.opaqueId;
		var url = callbacks.url;
		var transport = callbacks.transport || "udp";
		var min_delay = callbacks.min_delay || 0;
		var transaction = rtz.randomString(12);
		var request = {
			"type": "createHandle",
			"opaque_id": opaqueId,
			"transaction": transaction,
			"url": url,
			"transport": transport,
			"min_delay": min_delay
		};
        transactions[transaction] = function(json) {
            rtz.debug(json);
            if(json["type"] !== "success") {
                rtz.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
                callbacks.error("Ooops: " + json["error"].code + " " + json["error"].reason);
                return;
            }
            var handleId = json["id"];
            rtz.log("Created handle: " + handleId);
            var streamHandle = {
                session : that,
				id : handleId,
				url : url,
				transport : transport,
				min_delay : min_delay,
                destroyed : false,
                webrtcStuff : {
                    started : false,
                    myStream : null,
                    streamExternal : false,
                    remoteStream : null,
                    mySdp : null,
                    mediaConstraints : null,
                    pc : null,
                    dataChannel : null,
                    dtmfSender : null,
                    trickle : true,
                    iceDone : false,
                    volume : {
                        value : null,
                        timer : null
                    },
                    bitrate : {
                        value : null,
                        bsnow : null,
                        bsbefore : null,
                        tsnow : null,
                        tsbefore : null,
                        timer : null
                    }
                },
                getId : function() { return handleId; },
                //getBitrate : function() { return getBitrate(handleId); },
                send : function(callbacks) { sendMessage(handleId, callbacks); },
                //data : function(callbacks) { sendData(handleId, callbacks); },
                //dtmf : function(callbacks) { sendDtmf(handleId, callbacks); },
                //consentDialog : callbacks.consentDialog,
                iceState : callbacks.iceState,
                mediaState : callbacks.mediaState,
                webrtcState : callbacks.webrtcState,
                slowLink : callbacks.slowLink,
                onmessage : callbacks.onmessage,
                //createOffer : function(callbacks) { prepareWebrtc(handleId, callbacks); },
                createAnswer : function(callbacks) { prepareWebrtc(handleId, callbacks); },
                //handleRemoteJsep : function(callbacks) { prepareWebrtcPeer(handleId, callbacks); },
                //onlocalstream : callbacks.onlocalstream,
                onremotestream : callbacks.onremotestream,
                //ondata : callbacks.ondata,
                //ondataopen : callbacks.ondataopen,
                oncleanup : callbacks.oncleanup,
                ondestroyed : callbacks.ondestroyed,
                destroy : function(callbacks) { destroyHandle(handleId, callbacks); }
            };
            streamHandles[handleId] = streamHandle;
            callbacks.success(streamHandle);
        };
        request["session_id"] = sessionId;
        ws.send(JSON.stringify(request));
	};

	// Private method to send a message
	function sendMessage(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : rtz.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : rtz.noop;
		if(!connected) {
			rtz.warn("Is the server down? (connected=false)");
			callbacks.error("Is the server down? (connected=false)");
			return;
		}
		var streamHandle = streamHandles[handleId];
		if(streamHandle === null || streamHandle === undefined ||
				streamHandle.webrtcStuff === null || streamHandle.webrtcStuff === undefined) {
			rtz.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var message = callbacks.message;
		var jsep = callbacks.jsep;
		var transaction = rtz.randomString(12);
		var request = { "type": "message", "body": message, "transaction": transaction };
		if(jsep !== null && jsep !== undefined)
			request.jsep = jsep;
		rtz.debug("Sending message to server (handle=" + handleId + "):");
		rtz.debug(request);
        request["session_id"] = sessionId;
        request["handle_id"] = handleId;
        transactions[transaction] = function(json) {
            rtz.debug("Message sent!");
            rtz.debug(json);
            if(json["type"] === "success") {
                // We got a success, must have been a synchronous transaction
                rtz.log("Synchronous transaction successful");
                var data = json["data"];
                rtz.debug(data);
                callbacks.success(data);
                return;
            } else if(json["type"] !== "ack") {
                // Not a success and not an ack, must be an error
                if(json["error"] !== undefined && json["error"] !== null) {
                    rtz.error("Ooops: " + json["error"].code + " " + json["error"].reason);	// FIXME
                    callbacks.error(json["error"].code + " " + json["error"].reason);
                } else {
                    rtz.error("Unknown error");	// FIXME
                    callbacks.error("Unknown error");
                }
                return;
            }
            // If we got here, the server decided to handle the request asynchronously
            callbacks.success();
        };
        ws.send(JSON.stringify(request));
	};

	// Private method to send a trickle candidate
	function sendTrickleCandidate(handleId, candidate) {
		if(!connected) {
			rtz.warn("Is the server down? (connected=false)");
			return;
		}
		var pluginHandle = streamHandles[handleId];
		if(pluginHandle === null || pluginHandle === undefined ||
				pluginHandle.webrtcStuff === null || pluginHandle.webrtcStuff === undefined) {
			rtz.warn("Invalid handle");
			return;
		}
		var request = { "type": "trickle", "candidate": candidate, "transaction": rtz.randomString(12) };
		rtz.debug("Sending trickle candidate (handle=" + handleId + "):");
		rtz.debug(request);
        request["session_id"] = sessionId;
        request["handle_id"] = handleId;
        ws.send(JSON.stringify(request));
	};

	// Private method to destroy a stream handle
	function destroyHandle(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : rtz.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : rtz.noop;
		var asyncRequest = true;
		if(callbacks.asyncRequest !== undefined && callbacks.asyncRequest !== null)
			asyncRequest = (callbacks.asyncRequest === true);
		rtz.log("Destroying handle " + handleId + " (async=" + asyncRequest + ")");
		cleanupWebrtc(handleId);
		var streamHandle = streamHandles[handleId];
		if(streamHandle === null || streamHandle === undefined || streamHandle.destroyed) {
			// Plugin was already destroyed by server, calling destroy again will return a handle not found error, so just exit here
			delete streamHandles[handleId];
			callbacks.success();
			return;
		}""
		if(!connected) {
			rtz.warn("Is the server down? (connected=false)");
			callbacks.error("Is the server down? (connected=false)");
			return;
		}
		var request = { "type": "destroyHandle", "transaction": rtz.randomString(12) };
        request["session_id"] = sessionId;
        request["handle_id"] = handleId;
        ws.send(JSON.stringify(request));
        delete streamHandles[handleId];
        callbacks.success();
        return;
	}

	function createAnswer(handleId, media, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : rtz.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : rtz.noop;
		var streamHandle = streamHandles[handleId];
		if(streamHandle === null || streamHandle === undefined ||
				streamHandle.webrtcStuff === null || streamHandle.webrtcStuff === undefined) {
			rtz.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = streamHandle.webrtcStuff;
        rtz.log("Creating answer (iceDone=" + config.iceDone + ")");
		var mediaConstraints = {
            mandatory: {
                OfferToReceiveAudio: isAudioRecvEnabled(media),
                OfferToReceiveVideo: isVideoRecvEnabled(media)
            }
        };
		rtz.debug(mediaConstraints);
		config.pc.createAnswer(mediaConstraints)
			.then(function(answer) {
				rtz.debug(answer);
				rtz.log("Setting local description");
				config.mySdp = answer.sdp;
				config.pc.setLocalDescription(answer)
					.catch(callbacks.error);
				config.mediaConstraints = mediaConstraints;
				if(!config.iceDone && !config.trickle) {
					// Don't do anything until we have all candidates
					rtz.log("Waiting for all candidates...");
					return;
				}
				// JSON.stringify doesn't work on some WebRTC objects anymore
				// See https://code.google.com/p/chromium/issues/detail?id=467366
				var jsep = {
					"type": answer.type,
					"sdp": answer.sdp
				};
				callbacks.success(jsep);
			}, callbacks.error);
	}

	// WebRTC stuff
	function streamsDone(handleId, jsep, media, callbacks, stream) {
		var streamHandle = streamHandles[handleId];
		if(streamHandle === null || streamHandle === undefined ||
				streamHandle.webrtcStuff === null || streamHandle.webrtcStuff === undefined) {
			rtz.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = streamHandle.webrtcStuff;
		rtz.debug("streamsDone:", stream);
		if(stream) {
			rtz.debug("  -- Audio tracks:", stream.getAudioTracks());
			rtz.debug("  -- Video tracks:", stream.getVideoTracks());
		}
		// We're now capturing the new stream: check if we're updating or if it's a new thing
		var addTracks = false;
		// If we still need to create a PeerConnection, let's do that
		if(!config.pc) {
			var pc_config = {};
			//~ var pc_constraints = {'mandatory': {'MozDontOfferDataChannel':true}};
			var pc_constraints = {
				"optional": [{"DtlsSrtpKeyAgreement": true}]
			};
			// Any custom constraint to add?
			if(callbacks.rtcConstraints && typeof callbacks.rtcConstraints === 'object') {
				rtz.debug("Adding custom PeerConnection constraints:", callbacks.rtcConstraints);
				for(var i in callbacks.rtcConstraints) {
					pc_constraints.optional.push(callbacks.rtcConstraints[i]);
				}
			}
			rtz.log("Creating PeerConnection");
			rtz.debug(pc_constraints);
			config.pc = new RTCPeerConnection(pc_config, pc_constraints);
			rtz.debug(config.pc);
			if(config.pc.getStats) {	// FIXME
				config.volume = {};
				config.bitrate.value = "0 kbits/sec";
			}
			rtz.log("Preparing local SDP and gathering candidates (trickle=" + config.trickle + ")");
			config.pc.oniceconnectionstatechange = function(e) {
				if(config.pc)
					streamHandle.iceState(config.pc.iceConnectionState);
			};
			config.pc.onicecandidate = function(event) {
				if (event.candidate == null) {
					rtz.log("End of candidates.");
					config.iceDone = true;
                    // Notify end of candidates
                    sendTrickleCandidate(handleId, {"completed": true});
				} else {
					// JSON.stringify doesn't work on some WebRTC objects anymore
					// See https://code.google.com/p/chromium/issues/detail?id=467366
					var candidate = {
						"candidate": event.candidate.candidate,
						"sdpMid": event.candidate.sdpMid,
						"sdpMLineIndex": event.candidate.sdpMLineIndex
					};
					if(config.trickle === true) {
						// Send candidate
						sendTrickleCandidate(handleId, candidate);
					}
				}
			};
			config.pc.ontrack = function(event) {
				rtz.log("Handling Remote Track");
				rtz.debug(event);
				if(!event.streams)
					return;
				config.remoteStream = event.streams[0];
				streamHandle.onremotestream(config.remoteStream);
				if(event.track && !event.track.onended) {
					rtz.log("Adding onended callback to track:", event.track);
					event.track.onended = function(ev) {
						rtz.log("Remote track removed:", ev);
						if(config.remoteStream) {
							config.remoteStream.removeTrack(ev.target);
							streamHandle.onremotestream(config.remoteStream);
						}
					}
				}
			};
		}
		if(addTracks && stream !== null && stream !== undefined) {
			rtz.log('Adding local stream');
			stream.getTracks().forEach(function(track) {
				rtz.log('Adding local track:', track);
				config.pc.addTrack(track, stream);
			});
		}
		// Create offer/answer now
		if(jsep === null || jsep === undefined) {
			//createOffer(handleId, media, callbacks);
		} else {
			config.pc.setRemoteDescription(jsep)
				.then(function() {
					rtz.log("Remote description accepted!");
					config.remoteSdp = jsep.sdp;
					// Any trickle candidate we cached?
					if(config.candidates && config.candidates.length > 0) {
						for(var i in config.candidates) {
							var candidate = config.candidates[i];
							rtz.debug("Adding remote candidate:", candidate);
							if(!candidate || candidate.completed === true) {
								// end-of-candidates
								config.pc.addIceCandidate();
							} else {
								// New candidate
								config.pc.addIceCandidate(candidate);
							}
						}
						config.candidates = [];
					}
					// Create the answer now
					createAnswer(handleId, media, callbacks);
				}, callbacks.error);
		}
	}

    function prepareWebrtc(handleId, callbacks) {
		callbacks = callbacks || {};
		callbacks.success = (typeof callbacks.success == "function") ? callbacks.success : rtz.noop;
		callbacks.error = (typeof callbacks.error == "function") ? callbacks.error : webrtcError;
		var jsep = callbacks.jsep;
		callbacks.media = callbacks.media || { audio: true, video: true };
		var media = callbacks.media;
		var streamHandle = streamHandles[handleId];
		if(streamHandle === null || streamHandle === undefined ||
				streamHandle.webrtcStuff === null || streamHandle.webrtcStuff === undefined) {
			rtz.warn("Invalid handle");
			callbacks.error("Invalid handle");
			return;
		}
		var config = streamHandle.webrtcStuff;
		config.trickle = isTrickleEnabled(callbacks.trickle);
		// Are we updating a session?
		if(config.pc === undefined || config.pc === null) {
			// Nope, new PeerConnection
			media.update = false;
		} else if(config.pc !== undefined && config.pc !== null) {
			rtz.log("Updating existing media session");
			media.update = true;
		}
        // No need to do a getUserMedia, create offer/answer right away
        streamsDone(handleId, jsep, media, callbacks);
	}

	function cleanupWebrtc(handleId, hangupRequest) {
		rtz.log("Cleaning WebRTC stuff");
		var streamHandle = streamHandles[handleId];
		if(streamHandle === null || streamHandle === undefined) {
			// Nothing to clean
			return;
		}
		var config = streamHandle.webrtcStuff;
		if(config !== null && config !== undefined) {
			if(hangupRequest === true) {
				// Send a hangup request (we don't really care about the response)
				var request = { "type": "hangup", "transaction": rtz.randomString(12) };
				rtz.debug("Sending hangup request (handle=" + handleId + "):");
				rtz.debug(request);
				request["session_id"] = sessionId;
				request["handle_id"] = handleId;
				ws.send(JSON.stringify(request));
			}
			// Cleanup stack
			config.remoteStream = null;
			if(config.volume) {
				if(config.volume["local"] && config.volume["local"].timer)
					clearInterval(config.volume["local"].timer);
				if(config.volume["remote"] && config.volume["remote"].timer)
					clearInterval(config.volume["remote"].timer);
			}
			config.volume = {};
			if(config.bitrate.timer)
				clearInterval(config.bitrate.timer);
			config.bitrate.timer = null;
			config.bitrate.bsnow = null;
			config.bitrate.bsbefore = null;
			config.bitrate.tsnow = null;
			config.bitrate.tsbefore = null;
			config.bitrate.value = null;
			try {
				// Try a MediaStreamTrack.stop() for each track
				if(!config.streamExternal && config.myStream !== null && config.myStream !== undefined) {
					rtz.log("Stopping local stream tracks");
					var tracks = config.myStream.getTracks();
					for(var i in tracks) {
						var mst = tracks[i];
						rtz.log(mst);
						if(mst !== null && mst !== undefined)
							mst.stop();
					}
				}
			} catch(e) {
				// Do nothing if this fails
			}
			config.streamExternal = false;
			config.myStream = null;
			// Close PeerConnection
			try {
				config.pc.close();
			} catch(e) {
				// Do nothing
			}
			config.pc = null;
			config.candidates = null;
			config.mySdp = null;
			config.remoteSdp = null;
			config.iceDone = false;
			config.dataChannel = null;
			config.dtmfSender = null;
		}
		streamHandle.oncleanup();
	}

	// Helper methods to parse a media object
	function isAudioSendEnabled(media) {
		rtz.debug("isAudioSendEnabled:", media);
		if(media === undefined || media === null)
			return true;	// Default
		if(media.audio === false)
			return false;	// Generic audio has precedence
		if(media.audioSend === undefined || media.audioSend === null)
			return true;	// Default
		return (media.audioSend === true);
	}

	function isAudioSendRequired(media) {
		rtz.debug("isAudioSendRequired:", media);
		if(media === undefined || media === null)
			return false;	// Default
		if(media.audio === false || media.audioSend === false)
			return false;	// If we're not asking to capture audio, it's not required
		if(media.failIfNoAudio === undefined || media.failIfNoAudio === null)
			return false;	// Default
		return (media.failIfNoAudio === true);
	}

	function isAudioRecvEnabled(media) {
		rtz.debug("isAudioRecvEnabled:", media);
		if(media === undefined || media === null)
			return true;	// Default
		if(media.audio === false)
			return false;	// Generic audio has precedence
		if(media.audioRecv === undefined || media.audioRecv === null)
			return true;	// Default
		return (media.audioRecv === true);
	}

	function isVideoSendEnabled(media) {
		rtz.debug("isVideoSendEnabled:", media);
		if(media === undefined || media === null)
			return true;	// Default
		if(media.video === false)
			return false;	// Generic video has precedence
		if(media.videoSend === undefined || media.videoSend === null)
			return true;	// Default
		return (media.videoSend === true);
	}

	function isVideoSendRequired(media) {
		rtz.debug("isVideoSendRequired:", media);
		if(media === undefined || media === null)
			return false;	// Default
		if(media.video === false || media.videoSend === false)
			return false;	// If we're not asking to capture video, it's not required
		if(media.failIfNoVideo === undefined || media.failIfNoVideo === null)
			return false;	// Default
		return (media.failIfNoVideo === true);
	}

	function isVideoRecvEnabled(media) {
		rtz.debug("isVideoRecvEnabled:", media);
		if(media === undefined || media === null)
			return true;	// Default
		if(media.video === false)
			return false;	// Generic video has precedence
		if(media.videoRecv === undefined || media.videoRecv === null)
			return true;	// Default
		return (media.videoRecv === true);
	}

	function isScreenSendEnabled(media) {
		rtz.debug("isScreenSendEnabled:", media);
		if (media === undefined || media === null)
			return false;
		if (typeof media.video !== 'object' || typeof media.video.mandatory !== 'object')
			return false;
		var constraints = media.video.mandatory;
		if (constraints.chromeMediaSource)
			return constraints.chromeMediaSource === 'desktop' || constraints.chromeMediaSource === 'screen';
		else if (constraints.mozMediaSource)
			return constraints.mozMediaSource === 'window' || constraints.mozMediaSource === 'screen';
		else if (constraints.mediaSource)
			return constraints.mediaSource === 'window' || constraints.mediaSource === 'screen';
		return false;
	}

	function isDataEnabled(media) {
		rtz.debug("isDataEnabled:", media);
		if(rtz.webRTCAdapter.browserDetails.browser == "edge") {
			rtz.warn("Edge doesn't support data channels yet");
			return false;
		}
		if(media === undefined || media === null)
			return false;	// Default
		return (media.data === true);
	}

	function isTrickleEnabled(trickle) {
		rtz.debug("isTrickleEnabled:", trickle);
		if(trickle === undefined || trickle === null)
			return true;	// Default is true
		return (trickle === true);
	}
};
