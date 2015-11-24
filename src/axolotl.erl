-module(axolotl).

%%% This module implements the facade = main API.

-include("../include/axolotl.hrl").
-include("../include/textsecure.hrl").
-include("../include/logger.hrl").

%% API
-export([connect/1, connect/2, send/2, send/3, recv/3, ttl/0, ttl/1]).

-export_types([version/0, key/0, key_pair/0, sign/0, registration_id/0, device_id/0,
	       remote/0, ttl/0]).
-type version() :: 2 | 3.
-type key() :: <<_:32>>.
-type key_pair() :: {Private_key :: key(), Public_key :: key()}.
-type sign() :: <<_:32>>.
-type registration_id() :: ?MIN_REGISTRATION_ID..?MAX_REGISTRATION_ID.
-type device_id() :: ?MIN_DEVICE_ID..?MAX_DEVICE_ID.
-type prekey_id() :: ?MIN_PREKEY_ID..?MAX_PREKEY_ID.
-type remote() :: term().
-type ttl() :: erlang:timestamp().

%%%===================================================================
%%% API
%%%===================================================================

%% TODO: in specs, make message structures more explicit with version
%% fields, Mac etc.

-spec connect(Remote) -> Result when
      Remote :: remote(),
      Result :: {ok, iodata()} | {error, Reason},
      Reason :: {already_paired, Remote}.
%% @doc Initiate session to a remote party. This function returns a
%% key exchange message which should be send to the remote peer. The
%% remote peer now should respond and return a matching key exchange
%% message which should be handed to connect/2. Calling this function
%% for a already existing session will return the error
%% already_paired.
%% @see axolotl:connect/2
connect(Remote) ->
    case session:whereis_session(Remote) of
	Pid when is_pid(Pid) orelse Pid =:= not_running ->
	    {error, {already_paired, Pid}};
	undefined ->
	    Resp_msg = kems:initiate(Remote),
	    {ok, <<?VERSION:4, ?VERSION:4, 
		   (textsecure:encode_msg(Resp_msg))/binary>>}
    end.

-spec connect(Remote, Key_exchg_msg) -> Result when
      Remote :: remote(),
      Key_exchg_msg :: iodata(),
      Result :: {ok, Key_exchg_msg} | ok | {error, Reason},
      Reason :: untrusted | not_found | {already_paired, Remote}.
%% @doc Complete session initialization. The remote peer returns a
%% matching key exchange message on receipt of our initial key
%% exchange message. The remote's key exchange message is matched
%% first to make sure it is in response of our's after which the key
%% material included by the remote peer in the message and a session
%% is installed. If a matching key exchange message is not found, the
%% function returns the not_found error. If a session is already in
%% place for the remote peer, the already_paired error is returned.
%%
%% TODO: Do someting with current version and maximum supported
%% version like upgrading the current version to the maximum version
%% both parties support. It is unclear from the reference
%% implementation how this is suppposed to work.
connect(Remote, <<Curr_version:4, _Max_version:4, Serialized/binary>>) ->
    case session:whereis_session(Remote) of
	Pid when is_pid(Pid) orelse Pid =:= not_running ->
	    {error, {already_paired, Pid}};
	undefined ->
	    Msg = textsecure:decode_msg(Serialized, key_exchange_message),
	    Remote_id = Msg#key_exchange_message.id,
	    Remote_dhi_pub = Msg#key_exchange_message.identityKey,
	    case identities:check(Remote_id, Remote_dhi_pub) of
		true ->
		    case kems:process(Remote, Curr_version, Msg) of
			{ok, Session_data, Ke_msg} ->
			    new_session(Remote, Curr_version, Session_data),
			    {ok, <<Curr_version:4, ?VERSION:4, 
				   (textsecure:encode_msg(Ke_msg))/binary>>};
			{ok, Session_data} ->
			    new_session(Remote, Curr_version, Session_data),
			    ok;
			ok ->
			    ok
		    end;
		_ ->
		    {error, untrusted}
	    end
    end.

-spec send(Remote, Msg) -> Result when
      Remote :: remote(),
      Msg :: iodata() | list(),
      Result :: {ok, Whisper_msg} | {error, Reason},
      Whisper_msg :: binary(),
      Reason :: term().
%% @doc Send a message to the remote peer for a existing session. The
%% message is encrypted and a encoded Whispermessage is returned. When
%% there is no session available for this remote peer, an axception is
%% genereated with the value no_session, which can be the trigger to
%% fetch a prekey bundle for the remote peer and resend the message as
%% a prekey whisper message.
send(Remote, Msg) when is_list(Msg) ->
    send(Remote, list_to_binary(Msg));
send(Remote, Msg) ->
    {Curr_version, Whisper_msg, Mac_ctxt} = session:encode(Remote, Msg),
    Blob = <<Curr_version:4, ?VERSION:4, 
	     (textsecure:encode_msg(Whisper_msg))/binary>>,
    Mac = crypto:hmac_final_n(crypto:hmac_update(Mac_ctxt, Blob), 8),
    {ok, <<Blob/binary, Mac/binary>>}.

-spec send(Remote, Prekey_bundle, Msg) -> Result when
      Remote :: remote(),
      Prekey_bundle :: #prekey_bundle{},
      Msg :: iodata() | list(),
      Result :: {ok, Prekey_whisper_msg} | {error, Reason},
      Prekey_whisper_msg :: binary(),
      Reason :: term().
%% @doc Send a message to a remote peer as a prekey whisper message and
%% also initiate a new session with the remote peer. This function is
%% used to initiate a asynchroneous sessuion with a remote peer by
%% using a prekey bundle from the remote peer to create the session at
%% this side of the connection. On receipt of the prekey whisper
%% session, the remote side will establish it's part of the session.
%%
%% TODO: POTENTIAL INCOMPATIBILITY: In libaxolotl-java, a new session
%% is started (session is overwritten) if the session is already
%% available. In this implementation, an already started error is
%% being returned, which seems to be more correct. The session could
%% still have unprocessed messages (in transit).
send(Remote, Prekey_bundle, Msg) ->      
    {Curr_version, Session_data, Pkmsg} = prekeys:pkb2pkmsg(Prekey_bundle),
    %% We send -> we are Alice.
    new_session(Remote, Curr_version, alice, Session_data),
    {ok, Emb_msg} = send(Remote, Msg),
    Blob = textsecure:encode_msg(Pkmsg#prekey_whisper_message{message = Emb_msg}),
    {ok, <<Curr_version:4, ?VERSION:4, Blob/binary>>}.

-spec recv(Remote, Type, Blob) -> Result when
      Remote :: remote(),
      Type :: pkmsg | msg,
      Blob :: binary(),
      Result :: {ok, Msg} | {error, Reason},
      Reason :: illegal_msg | untrusted,
      Msg :: iodata().
%% @doc Receive a encrypted message from a remote peer and decrypt
%% it. The received message can either be a whisper message (msg) when a
%% session has been established previously, or it should eb a prekey
%% whisper message (pkmsg) if there is not yet a session in place. Receiving a
%% prekey whisper messgae for a alredy established session should be
%% alright and the embedded whisper message should be decrypted
%% properly with the other data being discarded.
%%
%% TODO: POTENTIAL INCOMPATIBILITY: Check prekey whisper message
%% handling for old sessions. In libaxolotl-java the embeeded message
%% in PrekeyWhisper messages for exitsing sessions are processed as
%% normal WhisperMessgaes. The way PrekeyWhisper messages are handled
%% in libaxolotl-java differs between version 2 and 3. In Version 3,
%% if a session is available, the embeded message is processed. In
%% version 2, if a session is available and the prekey is not in
%% store, a new session is started. So, if for version 2, a prekey is
%% in store, a new session will be started even if a session was
%% already in place!
recv(Remote, pkmsg, <<Curr_version:4, _Max_version:4, Serialized/binary>>) ->
    Pkmsg = textsecure:decode_msg(Serialized, prekey_whisper_message),
    Remote_id = Pkmsg#prekey_whisper_message.registrationId,
    Remote_dhi_pub = Pkmsg#prekey_whisper_message.identityKey,
    case identities:check(Remote_id, Remote_dhi_pub) of
	true ->
	    {Session_data, Embedded_msg} = prekeys:pkmsg2msg(Curr_version, Pkmsg),
	    case session:whereis_session(Remote) of
		undefined ->
		    %% We receive ->we are Bob.
		    new_session(Remote, Curr_version, bob, Session_data);
		_ ->
		    %% Session already in place. Don't build new session but
		    %% make the embedded message fall thru. The call to
		    %% prekeys:pkmsg2msg() did however delete the prekeys used
		    %% by this message, which is NOT how this is implemented
		    %% in libaxolotl-java where these keys are kept in store.
		    ok
	    end,
	    recv(Remote, msg, Embedded_msg);
	false ->
	    {error, untrusted}
    end;
recv(Remote, msg, <<Version:1/binary, Blob/binary>>) ->
    <<Curr_version:4, _Max_version:4>> = Version,
    L = byte_size(Blob) - 8,
    <<Serialized:L/binary, RMac:8/binary>> = Blob,
    Whisper_msg = textsecure:decode_msg(Serialized, whisper_message),
    {Plain_msg, Mac_ctxt} = session:decode(Remote, Curr_version, Whisper_msg),
    LMac_ctxt = crypto:hmac_update(Mac_ctxt, <<Version/binary, Serialized/binary>>),
    LMac = crypto:hmac_final_n(LMac_ctxt, 8),
    case RMac == LMac of
	true ->
	    {ok, Plain_msg};
	_ ->
	    {error, illegal_msg}
    end.
    
-spec ttl() -> erlang:timestamp().
%% @doc Return the current time in the same form as the time to live.
%% @see axolotl:ttl/1
ttl() ->
    os:timestamp().

-spec ttl(TTL :: integer()) -> erlang:timestamp().
%% @doc Calculate the maximum time to live value. The argument passed
%% in is the period to live as a number of seconds, starting now.
ttl(TTL) ->    
    {Mega_secs, Secs, Micro_secs} = os:timestamp(),
    {Mega_secs + ((Secs + TTL) div 1000000), (Secs + TTL) rem 1000000, Micro_secs}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private
new_session(Remote, Version, Session_data) ->
    {ok, _Child} = axolotl_sup:add_session([Remote, Version, Session_data]).

%% @private
new_session(Remote, Version, Role, Session_data) ->
    {ok, _Child} = axolotl_sup:add_session([Remote, Version, Role, Session_data]).    
