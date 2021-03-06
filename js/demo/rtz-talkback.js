var server = 'ws://172.16.3.102:9443/rtz';
//var server = 'ws://172.20.226.86:443/rtz';
//var server = 'ws://192.168.2.55:443/rtz';
//var server = 'ws://47.94.164.7:30002/rtz';

var rtzSession = null;
var rtzHandle = null;
var opaqueId = "talkback-" + rtz.randomString(12);

var spinner = null;

var myroom = 1234;	// Demo room
var myusername = null;
var myid = null;
var webrtcUp = false;
var audioenabled = false;


$(document).ready(function() {
	// Initialize the library (all console debuggers enabled)
	rtz.init({debug: "all", callback: function() {
		// Use a button to start the demo
		$('#start').one('click', function() {
			$(this).attr('disabled', true).unbind('click');
			// Make sure the browser supports WebRTC
			if(!rtz.isWebrtcSupported()) {
				bootbox.alert("No WebRTC support... ");
				return;
			}
			// Create session
			rtzSession = new RtzSession(
				{
					server: server,
					success: function() {
						// Create talkback
						rtzSession.createHandle(
							{
								type: "talkback",
								opaqueId: opaqueId,
								url: "rtmp://47.94.229.33:30004/live/testaudio",
								success: function(pluginHandle) {
									$('#details').remove();
									rtzHandle = pluginHandle;
									rtz.log("Talkback handle attached, id=" + rtzHandle.getId());
									$('#start').removeAttr('disabled').html("Stop")
										.click(function() {
											$(this).attr('disabled', true);
											rtzSession.destroy();
										});
								},
								error: function(error) {
									rtz.error("  -- Error attaching plugin...", error);
									//bootbox.alert("Error attaching plugin... " + error);
								},
								consentDialog: function(on) {
									rtz.debug("Consent dialog should be " + (on ? "on" : "off") + " now");
									if(on) {
										// Darken screen and show hint
										$.blockUI({ 
											message: '<div><img src="up_arrow.png"/></div>',
											css: {
												border: 'none',
												padding: '15px',
												backgroundColor: 'transparent',
												color: '#aaa',
												top: '10px',
												left: (navigator.mozGetUserMedia ? '-100px' : '300px')
											} });
									} else {
										// Restore screen
										$.unblockUI();
									}
								},
								onmessage: function(msg, jsep) {
									rtz.debug(" ::: Got a message :::");
									rtz.debug(msg);
									var result = msg["result"];
									rtz.debug("Result: " + result);
									if(result !== null && result !== undefined) {
										if(result["status"] !== undefined && result["status"] !== null) {
											var status = result["status"];
											if(status === 'preparing') {
												rtz.log("Starting, please wait...");
												if(!webrtcUp) {
													webrtcUp = true;
													// Publish our stream
													rtzHandle.createOffer(
														{
															media: { video: false, audio: true, audioRecv: true },
															success: function(jsep) {
																rtz.debug("Got SDP!");
																rtz.debug(jsep);
																var publish = { "request": "talkback", "muted": false };
																rtzHandle.send({"message": publish, "jsep": jsep});
															},
															error: function(error) {
																rtz.error("WebRTC error:", error);
																bootbox.alert("WebRTC error... " + JSON.stringify(error));
															}
														});
												}
											} else if(status === 'started') {

											} else if(status === 'stopped') {

											} else if(status === 'progress') {

											}
										}
									} else if(msg["error"] !== undefined && msg["error"] !== null) {
										rtz.error(msg["error"]);
										return;
									}
									if(jsep !== undefined && jsep !== null) {
										rtz.debug("Handling SDP as well...");
										rtz.debug(jsep);
										rtzHandle.handleRemoteJsep({jsep: jsep});
									}
								},
								onlocalstream: function(stream) {
									rtz.debug(" ::: Got a local stream :::");
									rtz.debug(stream);
									// We're not going to attach the local audio stream
									$('#audiojoin').hide();
									$('#room').removeClass('hide').show();
									$('#participant').removeClass('hide').html(myusername).show();
								},
								onremotestream: function(stream) {
									$('#room').removeClass('hide').show();
									var addButtons = false;
									if($('#roomaudio').length === 0) {
										addButtons = true;
										$('#mixedaudio').append('<audio class="rounded centered" id="roomaudio" width="100%" height="100%" autoplay/>');
									}
									rtz.attachMediaStream($('#roomaudio').get(0), stream);
									if(!addButtons)
										return;
									// Mute button
									audioenabled = true;
									$('#toggleaudio').click(
										function() {
											audioenabled = !audioenabled;
											if(audioenabled)
												$('#toggleaudio').html("Mute").removeClass("btn-success").addClass("btn-danger");
											else
												$('#toggleaudio').html("Unmute").removeClass("btn-danger").addClass("btn-success");
											rtzHandle.send({message: { "request": "configure", "muted": !audioenabled }});
										}).removeClass('hide').show();

								},
								oncleanup: function() {
									webrtcUp = false;
									rtz.log(" ::: Got a cleanup notification :::");
									$('#participant').empty().hide();
									$('#list').empty();
									$('#mixedaudio').empty();
									$('#room').hide();
								}
							});
					},
					error: function(error) {
						rtz.error(error);
						bootbox.alert(error, function() {
							window.location.reload();
						});
					},
					destroyed: function() {
						window.location.reload();
					}
				});
		});
	}});
});

function checkEnter(field, event) {
	var theCode = event.keyCode ? event.keyCode : event.which ? event.which : event.charCode;
	if(theCode == 13) {
		registerUsername();
		return false;
	} else {
		return true;
	}
}

function registerUsername() {
	if($('#username').length === 0) {
		// Create fields to register
		$('#register').click(registerUsername);
		$('#username').focus();
	} else {
		// Try a registration
		$('#username').attr('disabled', true);
		$('#register').attr('disabled', true).unbind('click');
		var username = $('#username').val();
		if(username === "") {
			$('#you')
				.removeClass().addClass('label label-warning')
				.html("Insert your display name (e.g., pippo)");
			$('#username').removeAttr('disabled');
			$('#register').removeAttr('disabled').click(registerUsername);
			return;
		}
		if(/[^a-zA-Z0-9]/.test(username)) {
			$('#you')
				.removeClass().addClass('label label-warning')
				.html('Input is not alphanumeric');
			$('#username').removeAttr('disabled').val("");
			$('#register').removeAttr('disabled').click(registerUsername);
			return;
		}
		var register = { "request": "join", "room": myroom, "display": username };
		myusername = username;
		rtzHandle.send({"message": register});
	}
}
