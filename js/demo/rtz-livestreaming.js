//var server = 'ws://172.16.3.102:443/rtz';
var server = 'ws://172.16.3.103:443/rtz';
//var server = 'ws://172.20.226.86:443/rtz';
//var server = 'ws://192.168.2.55:443/rtz';
var rtzSession = null;

var opaqueId = "livestreaming-" + rtz.randomString(12);
var selectedStreamUrl = null;
var spinner = null;
var spinner_opts = {
	lines: 13, // The number of lines to draw
	length: 38, // The length of each line
	width: 17, // The line thickness
	radius: 45, // The radius of the inner circle
	scale: 1, // Scales overall size of the spinner
	corners: 1, // Corner roundness (0..1)
	color: '#ffffff', // CSS color or array of colors
	fadeColor: 'transparent', // CSS color or array of colors
	speed: 1, // Rounds per second
	rotate: 0, // The rotation offset
	animation: 'spinner-line-fade-quick', // The CSS animation name for the lines
	direction: 1, // 1: clockwise, -1: counterclockwise
	zIndex: 2e9, // The z-index (defaults to 2000000000)
	className: 'spinner video', // The CSS class to assign to the spinner
	top: '47%', // Top position relative to parent
	left: '50%', // Left position relative to parent
	shadow: '0 0 1px transparent', // Box-shadow for the lines
	position: 'absolute' // Element positioning
};

document.addEventListener('DOMContentLoaded', function() {
	// Initialize the library (all console debuggers enabled)
	rtz.init({debug: "all", callback: function() {
		// Make sure the browser supports WebRTC
		if(!rtz.isWebrtcSupported()) {
			window.alert("No WebRTC support... ");
			return;
		}
	}});
});

function startStream(url) {
	selectedStreamUrl = url;
	rtz.log("Selected stream url=" + selectedStreamUrl);
	if(selectedStreamUrl === undefined || selectedStreamUrl === null) {
		window.alert("not selected stream");
		return;
	}
	stopStream();
	
	// Create session
	rtzSession = new RtzSession({
		server: server,
		notifyDestroyed: true,
		success: function() {
			var rtzHandle = null;
			// Create a streaming handle
			rtzSession.createHandle({
				opaqueId: opaqueId,
				url: url,
				transport: "tcp",
				min_delay: 0 / 40,
				success: function(handle) {
					rtzHandle = handle;
				},
				error: function(error) {
					rtz.error("  -- Error create handle... ", error);
				},
				onmessage: function(msg, jsep) {
					rtz.debug(" ::: Got a message :::");
					rtz.debug(msg);
					var result = msg["result"];
					if(result !== null && result !== undefined) {
						if(result["status"] !== undefined && result["status"] !== null) {
							var status = result["status"];
							if(status === 'starting') {
								rtz.log("Starting, please wait...");
								if (!spinner) {
									spinner = new Spinner(spinner_opts).spin(document.getElementById('remotevideo').parentElement);
								} else {
									spinner.spin(document.getElementById('remotevideo').parentElement);
								}
							} else if(status === 'started') {
								rtz.log("Started");
								spinner.stop();
							} else if(status === 'stopped') {
								rtz.log("Stopped");
								stopStream();
							} else if(status === 'progress') {
								rtz.log("Progress: videotime=" + result['videotime']);
							}
						} else if(msg["streaming"] === "event") {
							rtz.log("streaming event: " + msg);
						}
					} else if(msg["error"] !== undefined && msg["error"] !== null) {
						rtz.error(msg["error"]);
						stopStream();
						return;
					}
					if(jsep !== undefined && jsep !== null) {
						rtz.debug("Handling SDP as well...");
						rtz.debug(jsep);
						// Offer from the plugin, let's answer
						rtzHandle.createAnswer(
							{
								jsep: jsep,
								// We want recvonly audio/video and, if negotiated, datachannels
								media: { audioSend: false, videoSend: false, data: true },
								success: function(jsep) {
									rtz.debug("Got SDP!");
									rtz.debug(jsep);
									var body = { "request": "start" };
									rtzHandle.send({"message": body, "jsep": jsep});
								},
								error: function(error) {
									rtz.error("WebRTC error:", error);
								}
							});
					}
				},
				onremotestream: function(stream) {
					rtz.debug(" ::: Got a remote stream :::");
					rtz.debug(stream);
					rtz.attachMediaStream(document.getElementById('remotevideo'), stream);
				},
				ondataopen: function(data) {
					rtz.log("The DataChannel is available!");
				},
				ondata: function(data) {
					rtz.debug("We got data from the DataChannel! " + data);
				},
				oncleanup: function() {
					rtz.log(" ::: Got a cleanup notification :::");
					rtz.attachMediaStream(document.getElementById('remotevideo'), null);
				}
			});
		},
		error: function(error) {
			rtz.error(error);
			//window.location.reload();
		},
		destroyed: function() {
			rtz.log("session destroyed");
			//window.location.reload();
		}
	});
}

function stopStream() {
	if(rtzSession === null)
		return;
	rtzSession.destroy();
	rtzSession = null;
}
