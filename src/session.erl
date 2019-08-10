-module(session).

%%% @doc Implement session, i.e. the communication between the local
%%% peer and one remote peer.

%% TODO: Scrub stale ratchet keys. Messages that are lost and not
%% resent leave a stale ractchet key that should be removed
%% eventually. See stage_cks() below.

%% TODO: stop on unexpected messages. This occurs for example on
%% version mismatch. Should this also lead to removing the session
%% from storage?

-behaviour(gen_fsm).

-include("../include/axolotl.hrl").
-include("../include/textsecure.hrl").
-include("../include/logger.hrl").

%% API
-export([start_link/1, whereis_session/1, encode/2, decode/3]).

%% gen_fsm callbacks
-export([init/1, handle_info/3, terminate/3, code_change/4,
	 start_new_ratchet/2, start_new_ratchet/3, 
	 ratcheting/2, ratcheting/3,
	 handle_event/3, handle_sync_event/4]).

-export_types([key/0, device_id/0, remote/0, session_data/0]).
-type session_data() :: {Dhi :: axolotl:key_pair(), 
			 Dhb :: axolotl:key_pair(), 
			 Dhr :: undefined | axolotl:key_pair(), 
			 Dhir_pub :: axolotl:key(),
			 Dhbr_pub :: axolotl:key(),
			 Dhrr_pub :: undefined | axolotl:key()}
		      | {Dhi :: axolotl:key_pair(), 
			 Dhb :: axolotl:key_pair(), 
			 Dhr :: undefined | axolotl:key_pair(), 
			 Dh1 :: undefined | axolotl:key_pair(), 
			 Dhir_pub :: axolotl:key(),
			 Dhbr_pub :: axolotl:key(),
			 Dhrr_pub :: undefined | axolotl:key(),
			 Dh1r_pub :: undefined | axolotl:key()}.

-record(state, {remote :: axolotl:remote(), 
		version :: 2 | 3,
		dhi  :: {axolotl:key(), axolotl:key()},
		dhr  :: {axolotl:key(), axolotl:key()},
		dhir_pub  :: axolotl:key(),
		dhrr_pub  :: axolotl:key(),
		rk :: axolotl:key(),
		cks :: axolotl:key(),
		ckr :: axolotl:key(),
		ns = 0 :: integer(), pns = 0 :: integer(),
		nr = 0 :: integer(), pnr = 0 :: integer(),
		ckr_stage = [] :: [tuple()] 
	       }).

%%%===================================================================
%%% API
%%%===================================================================

start_link([Remote | _] = Args_list) ->
    gen_fsm:start_link({local, Remote}, ?MODULE, Args_list, []);
start_link(Remote) ->
    gen_fsm:start_link({local, Remote}, ?MODULE, [Remote], []).

-spec whereis_session(Remote) -> Result when
      Remote :: axolotl:remote(),
      Result :: pid() | not_running | undefined.
%% @doc Lookup a session both in the running processes and in storage.
whereis_session(Remote) ->
    case whereis(Remote) of
	Pid when is_pid(Pid) ->
	    Pid;
	undefined ->
	    case mnesia:dirty_read(session, Remote) of
		[_Session] ->
		    not_running;
		[] ->
		    undefined
	    end
    end.

-spec encode(Remote, Msg) -> Whisper_message when
      Remote :: axolotl:remote(),
      Msg :: iodata(),
      Whisper_message :: {Version, #whisper_message{}, Mac_ctxt},
      Version :: axolotl:version(),
      Mac_ctxt :: binary().
%% @doc Encode plain text message and return used protocol version,
%% WhisperMessage and hash context for Mac.
encode(Remote, Msg) ->
    try
	gen_fsm:sync_send_event(Remote, {encode, Msg})
    catch 
	_:_ ->
	    {ok, Pid} = axolotl_sup:add_session([Remote]),
	    gen_fsm:sync_send_event(Pid, {encode, Msg})
    end.

-spec decode(Remote, Version, Whisper_msg) -> {Msg, Mac_ctxt} when
      Remote :: axolotl:remote(),
      Version :: axolotl:version(),
      Whisper_msg :: #whisper_message{},
      Msg :: iodata(),
      Mac_ctxt :: binary(). % NO REAL BINARY BUT NIF-THING
%% @doc Decode a WhisperMessage and return plain text message.  
%%
%% TODO: Is it really necessary to pass the version as argument? It
%% will make the application crash if the other peer decides to start
%% using a different version, which is correct behaviour. It is
%% impossible to upgrade / downgrade versions for a running session.
decode(Remote, Version, Whisper_msg) ->
    try
	gen_fsm:sync_send_all_state_event(Remote, {decode, Version, Whisper_msg})
    catch 
	_:_ ->
	    {ok, Pid} = axolotl_sup:add_session([Remote]),
	    gen_fsm:sync_send_all_state_event(Pid, {decode, Version, Whisper_msg})
    end.

%%%===================================================================
%%% gen_fsm callbacks
%%%===================================================================

%% @private
init([Remote]) ->
    case mnesia:dirty_read(session, Remote) of
	[#session{state_name = State_name, state = State}] ->
	    {ok, State_name, State};
	[] ->
	    {stop, {not_found, Remote}};
	Error ->
	    {stop, Error}
    end;
init([Remote, Version, Session_data]) ->
    {_Dhi, {_, Dhb_pub}, _Dhr, _Dh1, _Dhir_pub, Dhbr_pub, _Dhrr_pub, _Dh1r_pub} = Session_data,
    case (Dhb_pub < Dhbr_pub) of
	true -> % Alice
	    init([Remote, Version, alice, Session_data]);
	false -> % Bob ... or undetermined
	    case (Dhb_pub > Dhbr_pub) of
		true -> % Bob
		    init([Remote, Version, bob, Session_data]);
		false ->
		    {stop, no_role}
	    end
    end;
init([Remote, Version, alice, Session_data]) ->
    {{Dhi_priv, _} = Dhi, {Dhb_priv, _}, _Dhr, _Dh1, 
     Dhir_pub, Dhbr_pub, Dhrr_pub, Dh1r_pub} = Session_data,
    Secret = crypto:hash(sha256, 
			 case Version of
			     2 ->
				 <<(gen_DH(Dhbr_pub, Dhi_priv))/binary, 
				   (gen_DH(Dhir_pub, Dhb_priv))/binary, 
				   (gen_DH(Dhbr_pub, Dhb_priv))/binary
				 >>;
			     3 when Dh1r_pub =/= undefined ->
				 <<(discontinuity_bytes())/binary,
				   (gen_DH(Dhbr_pub, Dhi_priv))/binary, 
				   (gen_DH(Dhir_pub, Dhb_priv))/binary, 
				   (gen_DH(Dhbr_pub, Dhb_priv))/binary,
				   (gen_DH(Dh1r_pub, Dhb_priv))/binary
				 >>;
			     3 ->
				 <<(discontinuity_bytes())/binary,
				   (gen_DH(Dhbr_pub, Dhi_priv))/binary, 
				   (gen_DH(Dhir_pub, Dhb_priv))/binary, 
				   (gen_DH(Dhbr_pub, Dhb_priv))/binary
				 >>
			 end),
    {RK, CK} = make_root(Version, Secret),
    State_name = start_new_ratchet,
    State = #state{remote = Remote, version = Version, 
		   dhi = Dhi, dhir_pub = Dhir_pub, dhrr_pub = Dhrr_pub, 
		   rk = RK, ckr = CK},
    store_and_return({ok, State_name, State});
init([Remote, Version, bob, Session_data]) ->
    {{Dhi_priv, _} = Dhi, {Dhb_priv, _}, Dhr, Dh1,
     Dhir_pub, Dhbr_pub, _Dhrr_pub, _Dh1r_pub} = Session_data,
    Secret = crypto:hash(sha256, 
			 case Version of
			     2 ->
				 <<(gen_DH(Dhir_pub, Dhb_priv))/binary, 
				   (gen_DH(Dhbr_pub, Dhi_priv))/binary, 
				   (gen_DH(Dhbr_pub, Dhb_priv))/binary
				 >>;
			     3 when Dh1 =/= undefined ->
				 {Dh1_priv, _} = Dh1,
				 <<(discontinuity_bytes())/binary,
				   (gen_DH(Dhir_pub, Dhb_priv))/binary, 
				   (gen_DH(Dhbr_pub, Dhi_priv))/binary, 
				   (gen_DH(Dhbr_pub, Dhb_priv))/binary,
				   (gen_DH(Dhbr_pub, Dh1_priv))/binary
				 >>;
			     3 ->
				 <<(discontinuity_bytes())/binary,
				   (gen_DH(Dhir_pub, Dhb_priv))/binary, 
				   (gen_DH(Dhbr_pub, Dhi_priv))/binary, 
				   (gen_DH(Dhbr_pub, Dhb_priv))/binary
				 >>
			 end),
    {RK, CK} = make_root(Version, Secret),
    State_name = ratcheting,
    State = #state{remote = Remote, version = Version, 
		   dhi = Dhi, dhr = Dhr, dhir_pub = Dhir_pub,
		   rk = RK, cks = CK},
    store_and_return({ok, State_name, State}).

%% @private
start_new_ratchet({encode, Plain_msg}, _From, 
		  #state{version = Version, dhi = {_, Dhi_pub}, rk = RK, ns = Ns, 
			 dhir_pub = Dhir_pub, dhrr_pub = Dhrr_pub} = State) ->
    Dhr = {Dhr_priv, Dhr_pub} = gen_key_pair(),
    {New_RK, CKs} = make_chain(Version, RK, Dhrr_pub, Dhr_priv),
    PNs = max(Ns - 1, 0),
    Reply = do_encode(Version, Plain_msg, CKs, 0, PNs, Dhi_pub, Dhr_pub, Dhir_pub),
    New_CKs = pull_chain(CKs),
    New_state = State#state{rk = New_RK, cks = New_CKs, ns = 1, pns = PNs, dhr = Dhr},
    Next_state_name = ratcheting,
    store_and_return({reply, Reply, Next_state_name, New_state});
start_new_ratchet(Event, _From, State) ->
    ?ERROR_MSG("Unexpected call: Event ~p, State ~p", [Event, State]),
    {reply, {error, skipped}, start_new_ratchet, State}.

%% @private
start_new_ratchet(Event, State) ->
    ?ERROR_MSG("Unexpected call: Event ~p, State ~p", [Event, State]),
    {next_state, start_new_ratchet, State}.

%% @private
ratcheting({encode, Plain_msg}, _From, 
	   #state{version = Version, dhi = {_, Dhi_pub}, dhir_pub = Dhir_pub,
		  cks = CKs, ns = Ns, pns = PNs, dhr = {_, Dhr_pub}} = State) ->
    Reply = do_encode(Version, Plain_msg, CKs, Ns, PNs, Dhi_pub, Dhr_pub, Dhir_pub),
    New_CKs = pull_chain(CKs),
    New_state = State#state{cks = New_CKs, ns = Ns + 1},
    Next_state_name = ratcheting,
    store_and_return({reply, Reply, Next_state_name, New_state});
ratcheting(Event, _From, State) ->
    ?ERROR_MSG("Unexpected call: Event ~p, State ~p", [Event, State]),
    {reply, {error, skipped}, start_new_ratchet, State}.

%% @private
ratcheting(Event, State) ->
    ?ERROR_MSG("Unexpected call: Event ~p, State ~p", [Event, State]),
    {next_state, ratcheting, State}.

%% @private
handle_sync_event({decode, Version, #whisper_message{ratchetKey = DHp, 
						     counter = Np, 
						     ciphertext = Cipher_msg}}, 
		  _From, State_name, 
		  #state{version = Version, dhi = {_, Dhi_pub}, dhir_pub = Dhir_pub, 
			 dhrr_pub = Dhrr_pub, nr = Nr, ckr = CKr} = State) 
  when DHp =:= Dhrr_pub, Np =:= Nr ->
    %% We're still on the same chain and we get exactly the message
    %% number we're expecting
    Reply = do_decode(Version, Cipher_msg, CKr, Nr, Dhi_pub, Dhir_pub),
    New_CKr = pull_chain(CKr),
    New_state = State#state{ckr = New_CKr, nr = Np + 1},
    store_and_return({reply, Reply, State_name, New_state});
handle_sync_event({decode, Version, #whisper_message{ratchetKey = DHp, 
						     counter = Np, 
						     ciphertext = Cipher_msg}}, 
		  _From, State_name, 
		  #state{version = Version, dhi = {_, Dhi_pub}, dhir_pub = Dhir_pub,
			 dhrr_pub = Dhrr_pub, nr = Nr, 
			 ckr_stage = CKr_stage} = State) 
  when DHp =:= Dhrr_pub, Np < Nr ->
    %% We're still on the same chain, but the message received is
    %% a delayed one.
    {_, CKp, _} = lists:keyfind({Dhrr_pub, Np}, 1, CKr_stage),
    New_CKr_stage = lists:keydelete({Dhrr_pub, Np}, 1, CKr_stage),
    Reply = do_decode(Version, Cipher_msg, CKp, Np, Dhi_pub, Dhir_pub),
    New_state = State#state{ckr_stage = New_CKr_stage},
    store_and_return({reply, Reply, State_name, New_state});
handle_sync_event({decode, Version, #whisper_message{ratchetKey = DHp, 
						     counter = Np, 
						     ciphertext = Cipher_msg}}, 
		  _From, State_name, 
		  #state{version = Version, dhi = {_, Dhi_pub}, dhir_pub = Dhir_pub,
			 dhrr_pub = Dhrr_pub, nr = Nr, ckr = CKr, 
			 ckr_stage = CKr_stage} = State) 
  when DHp =:= Dhrr_pub, Np > Nr ->
    %% We're still on the same chain, but the message received is
    %% ahead of the message we're expecting

    %% TODO: libaxolotl limits the number of messages ahead to 2000. I
    %% assume this may happen in a very rare occasion and we'll just
    %% go for the Erlang way, i.e. let it crash if something like that
    %% would ever happen.

    %% Pull chain as many times as needed and store the chain keys for
    %% later use
    {New_CKr_stage, CKp} = stage_cks(CKr_stage, Dhrr_pub, CKr, Nr, Np - 1),
    Reply = do_decode(Version, Cipher_msg, CKp, Np, Dhi_pub, Dhir_pub),
    %% Pull chain once more since we are done with the current key
    New_CKr = pull_chain(CKp),
    New_state = State#state{ckr = New_CKr, nr = Np + 1, ckr_stage = New_CKr_stage},
    store_and_return({reply, Reply, State_name, New_state});
handle_sync_event({decode, Version, #whisper_message{ratchetKey = DHp, 
						     counter = Np, 
						     previousCounter = PNp, 
						     ciphertext = Cipher_msg}}, 
		  _From, State_name, 
		  #state{version = Version, dhi = {_, Dhi_pub}, dhir_pub = Dhir_pub,
			 dhrr_pub = Dhrr_pub, ckr_stage = CKr_stage} = State) 
  when DHp =/= Dhrr_pub ->
    %% This might be an old messgae from an old chain. Search the
    %% staged chain keys for this message. If found, just decypher and
    %% we're done. If not found, this is a message on a new chain.
    case lists:keyfind({DHp, Np}, 1, CKr_stage) of
	{_, CKp, _} ->  % Found message on old chain
	    New_CKr_stage = lists:keydelete({DHp, Np}, 1, CKr_stage),
	    Reply = do_decode(Version, Cipher_msg, CKp, Np, Dhi_pub, Dhir_pub),
	    New_state = State#state{ckr_stage = New_CKr_stage},
	    store_and_return({reply, Reply, State_name, New_state});
	false ->  % it is a new chain
	    case State_name of
		ratcheting -> 
		    #state{rk = RK, ckr = CKr, nr = Nr, dhr = Dhr} = State,
		    
		    %% A new chain is started by the sender.
		    
		    %% First finish the last chain if needed, i.e. if PNp >
		    %% Nr, the last chain wasn't finished yet and messages
		    %% from that chain are still on the way to us. Add the
		    %% chain keys for the last chain to the staged chain
		    %% keys. NB: Nr will be greater than PNp when the last
		    %% chain was finished, so the following list comprehension
		    %% will do nothing. NB: Dhrr_pub can be undefined in case...??
		    CKr_stage_1 = case Dhrr_pub of
				      undefined ->
					  CKr_stage;
				      _ ->
					  {CS, _} = stage_cks(CKr_stage, Dhrr_pub, CKr, Nr, PNp),
					  CS
				  end,

		    %% With a new chain, we have to calculate a new root key
		    %% and a new chain key.
		    {Dhr_priv, _Dhr_pub} = Dhr,
		    {New_RK, CK} = make_chain(Version, RK, DHp, Dhr_priv),
		    
		    %% Next, the message received may be ahead of other
		    %% messages on the new chain, so lets pull the chain as much
		    %% as needed and store the chain keys
		    {New_CKr_stage, CKp} = stage_cks(CKr_stage_1, DHp, CK, 0, Np - 1),
		    Reply = do_decode(Version, Cipher_msg, CKp, Np, Dhi_pub, Dhir_pub),
		    %% Pull chain once more since we are done with the current key
		    New_CKr = pull_chain(CKp),
		    New_state_name = start_new_ratchet,
		    New_state = State#state{dhrr_pub = DHp, dhr = undefined, 
					    rk = New_RK, ckr = New_CKr, nr = Np + 1,
					    ckr_stage = New_CKr_stage},
		    store_and_return({reply, Reply, New_state_name, New_state});
		start_new_ratchet ->
		    %% When we are not ratcheting, we did already
		    %% receive a messga which updated the ratcket DH
		    %% key and this should never be done more than
		    %% once. The sender and receiver are hopelessly
		    %% out of sync so we just bomb out.
		    {stop, {error, undecryptable}, State}
	    end
    end;
handle_sync_event(Request, _From, State_name, State) ->
    ?ERROR_MSG("Unexpected call: Request ~p, State_name ~p, State ~p", [Request, State_name, State]),
    {reply, {error, skipped}, State_name, State}.

%% @private
handle_event(Event, State_name, State) ->
    ?ERROR_MSG("Unexpected call: Event ~p, State_name ~p, State ~p", [Event, State_name, State]),
    {next_state, State_name, State}.

%% @private
handle_info(Info, State_name, State) ->
    ?ERROR_MSG("Unexpected call: Info ~p, State_name ~p, State ~p", [Info, State_name, State]),
    {next_state, State_name, State}.

%% @private
terminate(_Reason, _State_name, _State) ->
    ok.

%% @private
code_change(_OldVsn, State_name, State, _Extra) ->
    {ok, State_name, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @private
gen_key_pair() ->
    gen_key_pair(crypto:strong_rand_bytes(32)).

%% @private
gen_key_pair(Secret) -> % when is_binary(Secret), byte_size(Secret) == 32 ->
    Private_key = curve25519:make_private(Secret),
    Public_key = curve25519:make_public(Private_key),
    {Private_key, Public_key}.

%% @private
get_shared_secret(Pub, Priv) ->
    Shared_secret = curve25519:make_shared(Pub, Priv),
    crypto:hash(sha256, <<"curve25519-shared:", Shared_secret/binary>>).

%% @private
gen_DH(Pub, Priv) ->
    {Key, _} = gen_key_pair(Priv),
    get_shared_secret(Pub, Key).

%% @private
derive_secrets(3, IKM, Info, L) ->
    hkdf:derive_secrets(sha256, IKM, Info, L);
derive_secrets(2, IKM, Info, L) ->
    derive_secrets(2, IKM, Info, <<>>, L).
derive_secrets(3, IKM, Info, Salt, L) ->
    hkdf:derive_secrets(sha256, IKM, Info, Salt, L);
derive_secrets(2, IKM, Info, Salt, L) ->
    PRK = hkdf:extract(sha256, Salt, IKM),
    Hl = 32, % sha256 == 32 bytes
    N = L div Hl + case (L rem Hl) of
		       0 ->
			   0;
		       _ ->
			   1
		   end,
    expandv2(PRK, Info, 0, N, <<>>, <<>>).  % 0 instead of 1
    
%% @private 
%% @doc Non standard extract with the constant concatenated to the
%% end of each T(n) starting with 0 instaed of 1 as in RFC 5869.
expandv2(_PRK, _Info, I, N, _Prev, Acc) 
  when I =:= N ->  % == instead of >
    Acc;
expandv2(PRK, Info, I, N, Prev, Acc) ->
    Ti = crypto:hmac(sha256, PRK, <<Prev/binary, Info/binary, I:8>>),
    expandv2(PRK, Info, I + 1, N, Ti, <<Acc/binary, Ti/binary>>).

%% @private
make_root(Version, Shared_secret) ->
    <<RK:32/binary, 
      CK:32/binary>> = derive_secrets(Version, Shared_secret, <<"WhisperText">>, 64),
    {RK, CK}.

%% @private
make_chain(Version, RK, Dhrr_pub, Dhr_priv) ->
    Shared_secret = curve25519:make_shared(Dhrr_pub, Dhr_priv),
    Shared_secret_ = crypto:hash(sha256, 
				 <<"curve25519-shared:", 
				   Shared_secret/binary>>),
    <<New_RK:32/binary, 
      CK:32/binary>> = derive_secrets(Version, Shared_secret_, <<"WhisperRatchet">>,
				      RK, 64),
    {New_RK, CK}.

%% @private
pull_chain(CK) ->
    crypto:hmac(sha256, CK, <<2>>).

%% @private
%% Store chain keys for messages from ratches (chains) that are still
%% to be received. The function returns the staged chain keys and the
%% chain key that should be used for processing the current
%% message. If N_first is greater than N_last, the passed in list of
%% staged chain keys and the chain key (CK) will be returned by the
%% function. The number of chain keys is limited to 2000
%%
%% TODO: Add timestamp for each entry so we can scrub (very) old chain
%% keys. The third argument in the list is intended for this.
stage_cks(CKr_stage, Dhrr_pub, CKr, Nr_first, Nr_last) 
  when Nr_first =< Nr_last andalso Nr_last - Nr_first =< 2000 ->
    New_CKr_stage = [ {{Dhrr_pub, Nr_first}, CKr, []} | CKr_stage ],
    New_CKr = pull_chain(CKr),
    stage_cks(New_CKr_stage, Dhrr_pub, New_CKr, Nr_first + 1, Nr_last);
stage_cks(CKr_stage, _Dhrr_pub, CKr, _Nr_first, _Nr_last) ->
    {CKr_stage, CKr}.
   
%% @private
discontinuity_bytes() ->
    << <<16#ff>> || _ <- lists:seq(1, 32) >>.

%% @private
%% TODO: Some implementations pad with just zero's and put the pad
%% length in the last byte. Other implementations, notably
%% python-axolotl use the pad length as the value of the pad bytes,
%% which makes the last byte the pad value automaticaly.) Yet another
%% implementation uses random bytes as padding and store the pad
%% length in the last byte.  So, which one to use?
pad(Data, Block_size) when Block_size > 0, Block_size =< 255 ->
    L = byte_size(Data),
    PL = Block_size - (L rem Block_size),
    Padding = << <<PL>> || _ <- lists:seq(1, PL) >>,
    <<Data/binary, Padding/binary>>.

%% @private
unpad(Data) ->
    Pad_length = binary:last(Data),
    Data_length = byte_size(Data) - Pad_length,
    <<Data:Data_length/binary>>.

msg_cipher_key_and_iv(2, CK, N) ->
    %% Version 2
    MK = crypto:hmac(sha256, CK, <<1>>),
    <<Cipher_key:32/binary, 
      Mac_key:32/binary>> = derive_secrets(2, MK, <<"WhisperMessageKeys">>, 64),
    %% ...the high 4 bytes of the counter corresponding to the
    %% "counter" value...
    Ivec = <<N:32, 0:96>>, % makes 16 Bytes
    {Cipher_key, Ivec, Mac_key};
msg_cipher_key_and_iv(3, CK, _N) ->
    %% Version 3
    MK = crypto:hmac(sha256, CK, <<1>>),
    %% <<Cipher_key:32/binary, 
    %%   Mac_key:32/binary,
    %%   Ivec:16/binary>> = derive_secrets(3, MK, <<"WhisperMessageKeys">>, 80),

    %% TODO: Check compatibility with the official protocol. The
    %% derived Cipher_key was 32 bytes, but the crypto lib only
    %% accepts 16 bytes for the aes_128_cbc cypher, which is
    %% correct. One could use aes_256_cbc with a 32 bytes long key,
    %% but the original implementation did explicitly use 128.
    <<Cipher_key:16/binary, 
      Mac_key:32/binary,
      Ivec:16/binary>> = derive_secrets(3, MK, <<"WhisperMessageKeys">>, 64),
    {Cipher_key, Ivec, Mac_key}.

%% @private
encrypt_msg(2, Plain_msg, CKs, Ns) ->
    {Cipher_key, Ivec, Mac_key} = msg_cipher_key_and_iv(2, CKs, Ns),
    Stream_state = crypto:stream_init(aes_128_ctr, Cipher_key, Ivec),
    {_New_stream_state, Cipher_msg} = crypto:stream_encrypt(Stream_state, Plain_msg),
    {Cipher_msg, Mac_key};
encrypt_msg(Version, Plain_msg, CKs, Ns) ->
    Block_size = 16,  % 128 bits
    Padded_msg = pad(Plain_msg, Block_size),
    {Cipher_key, Ivec, Mac_key} = msg_cipher_key_and_iv(Version, CKs, Ns),
    Cipher_msg = crypto:crypto_one_time(aes_128_cbc, Cipher_key, Ivec, Padded_msg, true),
    {Cipher_msg, Mac_key}.

%% @private
do_encode(Version, Plain_msg, CKs, Ns, PNs, Dhi_pub, Dhr_pub, Dhir_pub) ->
    {Cipher_msg, Mac_key} = encrypt_msg(Version, Plain_msg, CKs, Ns),
    Whisper_msg = #whisper_message{ratchetKey = Dhr_pub, 
				   counter = Ns, 
				   previousCounter = PNs, 
				   ciphertext = Cipher_msg},
    Mac_ctxt_init = crypto:hmac_init(sha256, Mac_key),
    Mac_ctxt = case Version of
		   3 -> 
		       Mac_ctxt1 = crypto:hmac_update(Mac_ctxt_init, Dhi_pub),
		       crypto:hmac_update(Mac_ctxt1, Dhir_pub);
		   2 ->
		       Mac_ctxt_init
	       end,
    {Version, Whisper_msg, Mac_ctxt}.

%% @private
decrypt_msg(2, Cipher_msg, CKr, Nr) ->
    {Cipher_key, Ivec, Mac_key} = msg_cipher_key_and_iv(2, CKr, Nr),
    Stream_state = crypto:stream_init(aes_ctr, Cipher_key, Ivec),
    {_New_stream_state, Plain_msg} = crypto:stream_decrypt(Stream_state, Cipher_msg),
    {Plain_msg, Mac_key};
decrypt_msg(Version, Cipher_msg, CKr, Nr) ->
    {Cipher_key, Ivec, Mac_key} = msg_cipher_key_and_iv(Version, CKr, Nr),
    Plain_msg = crypto:crypto_one_time(aes_128_cbc, Cipher_key, Ivec, Cipher_msg, false),
    {unpad(Plain_msg), Mac_key}.

%% @private
do_decode(Version, Cipher_msg, CKr, Nr, Dhi_pub, Dhir_pub) ->
    {Plain_msg, Mac_key} = decrypt_msg(Version, Cipher_msg, CKr, Nr),
    Mac_ctxt_init = crypto:hmac_init(sha256, Mac_key),
    Mac_ctxt = case Version of
		   3 -> 
		       Mac_ctxt1 = crypto:hmac_update(Mac_ctxt_init, Dhir_pub),
		       crypto:hmac_update(Mac_ctxt1, Dhi_pub);
		   2 ->
		       Mac_ctxt_init
	       end,
    {Plain_msg, Mac_ctxt}.

%% @private
store_and_return({ok, State_name, State} = Result) ->
    case store_session(State_name, State) of
	ok ->
	    Result;
	{error, Reason} ->
	    {stop, {store_session_failed, Reason}}
    end;
store_and_return({reply, _Reply, State_name, State} = Result) ->
    case store_session(State_name, State) of
	ok ->
	    Result;
	{error, Reason} ->
	    {stop, {store_session_failed, Reason}, State}
    end.
%% store_and_return({next_state, State_name, State} = Result) ->
%%     case store_session(State_name, State) of
%% 	ok ->
%% 	    Result;
%% 	{error, Reason} ->
%% 	    {stop, {store_session_failed, Reason}, State}
%%     end.
    
store_session(State_name, State) ->
    Session = #session{remote = State#state.remote, 
		       state_name = State_name, 
		       state = State},
    case mnesia:transaction(fun() -> mnesia:write(Session) end) of
	{atomic, ok} ->
	    ok;
	Error ->
	    {error, Error}
    end.
    
    
