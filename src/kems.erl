-module(kems).

%%% @doc This module takes care of generating and storing key exchange message data.

-behaviour(gen_server).

-include("../include/axolotl.hrl").
-include("../include/textsecure.hrl").
-include("../include/logger.hrl").

%% API
-export([start_link/3, initiate/1, process/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(INITIATE_FLAG, 1).
-define(RESPONSE_FLAG, 2).
-define(SIMULTAENOUS_INITIATE_FLAG, 4).
-define(SCRUB_INTV, (60 * 1000)). % 1 minute scrubbing interval

-export_types([kem_id/0]).
-type kem_id() :: ?MIN_KEM_ID..?MAX_KEM_ID.

-record(state, {id, device_id, dhi}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Id, Device_id, Dhi) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Id, Device_id, Dhi], []).

-spec initiate(Remote) -> Result when
      Remote :: axolotl:remote(),
      Result :: #key_exchange_message{}.
%% @doc Generate key exchange message data. A key exchange mesage
%% (KEM) has a randomly generated id which is used to match the id in
%% the response from the other peer. This id is chosen randomly to
%% make it unpredictable. Also, a KEM contains a public handshake
%% (base) key and public initial ratchet key. These keys are in the
%% specs refered to as A0/B0 and A1/B1 resp. If this function is
%% called repeatedly, the old KEM is deleted and a new one is issued.
initiate(Remote) ->
    gen_server:call(?SERVER, {initiate, Remote}).

-spec process(Remote, Version, Msg) -> Result when
      Remote :: axolotl:remote(),
      Version :: axolotl:version(),
      Msg :: #key_exchange_message{},
      Result :: {ok, Session_data, Resp_msg} 
	      | {ok, Session_data} 
	      | ok 
	      | {error, Reason},
      Session_data :: session:session_data(),
      Resp_msg :: #key_exchange_message{},
      Reason :: term().
%% @doc Process the ersponse from the other peer.
process(Remote, Version, Msg) ->
    <<Kem_id:27, _Flags:2, Flags:3>> = <<(Msg#key_exchange_message.id):32>>,
    Dhir_pub = Msg#key_exchange_message.identityKey,
    Dhbr_pub = Msg#key_exchange_message.baseKey,
    Dhrr_pub = Msg#key_exchange_message.ratchetKey,
    case Version of
	2 ->
	    gen_server:call(?SERVER, {Remote, Flags, Kem_id, Dhir_pub, 
				      Dhbr_pub, Dhrr_pub});
	_ ->
	    Dhbr_sign = Msg#key_exchange_message.baseKeySignature,
	    case curve25519:verify(Dhir_pub, Dhbr_pub, Dhbr_sign) of
		true ->
		    gen_server:call(?SERVER, {Remote, Flags, Kem_id, Dhir_pub, 
					      Dhbr_pub, Dhrr_pub});
		false ->
		    {error, bad_signature}
	    end
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([Id, Device_id, Dhi]) ->
    ok = mnesia:wait_for_tables([kem], 4000),
    erlang:send_after(?SCRUB_INTV, self(), scrub),
    {ok, #state{id = Id, device_id = Device_id, dhi = Dhi}}.

%% @private
handle_call({initiate, Remote}, _From, #state{dhi = Dhi} = State) ->
    {Dhi_priv, Dhi_pub} = Dhi,
    Kem_id = crypto:rand_uniform(?MIN_KEM_ID, ?MAX_KEM_ID),
    {_Dhb_priv, Dhb_pub} = Dhb = curve25519:key_pair(), % A0 / B0
    Dhb_sign = curve25519:sign(Dhi_priv, Dhb_pub),
    {_Dhr_priv, Dhr_pub} = Dhr = curve25519:key_pair(), % A1 / B1
    Kem = #kem{remote = Remote, kem_id = Kem_id, dhb = Dhb, dhr = Dhr, 
	       ttl = axolotl:ttl(?KEM_TTL)},	
    ok = mnesia:dirty_write(Kem),
    %% id in KeyExchangeMessages is NOT the peer's id but a unique id for matching
    %% KeyExchangeMessages.
    Msg = #key_exchange_message{id = (Kem_id bsl 5) bor ?INITIATE_FLAG,
				baseKey = Dhb_pub, 
				ratchetKey  = Dhr_pub, 
				identityKey = Dhi_pub, 
				baseKeySignature = Dhb_sign},
    {reply, Msg, State};
handle_call({Remote, ?INITIATE_FLAG, Kem_id, Dhir_pub, Dhbr_pub, Dhrr_pub}, _From, 
	    #state{dhi = Dhi} = State) ->
    {Dhi_priv, Dhi_pub} = Dhi,
    case mnesia:dirty_read(kem, Remote) of
	[] ->
	    Dhb = curve25519:key_pair(),
	    Dhr = curve25519:key_pair(),
	    Flags = ?RESPONSE_FLAG;
	[Old_kem] ->
	    mnesia:dirty_delete(kem, Remote),
	    Dhb = Old_kem#kem.dhb,
	    Dhr = Old_kem#kem.dhr,
	    Flags = ?RESPONSE_FLAG + ?SIMULTAENOUS_INITIATE_FLAG
    end,
    {_Dhb_priv, Dhb_pub} = Dhb, % A0 / B0
    Dhb_sign = curve25519:sign(Dhi_priv, Dhb_pub),
    {_Dhr_priv, Dhr_pub} = Dhr, % A1 / B1
    Resp_msg = #key_exchange_message{id = (Kem_id bsl 5) bor Flags,
				     baseKey = Dhb_pub, 
				     ratchetKey  = Dhr_pub, 
				     identityKey = Dhi_pub, 
				     baseKeySignature = Dhb_sign},
    Session_data = {Dhi, Dhb, Dhr, undefined, Dhir_pub, Dhbr_pub, Dhrr_pub, undefined},
    {reply, {ok, Session_data, Resp_msg}, State};    
handle_call({Remote, ?RESPONSE_FLAG + ?SIMULTAENOUS_INITIATE_FLAG,
	     _Kem_id, _Dhir_pub, _Dhbr_pub, _Dhrr_pub}, _From, State) ->
    case mnesia:dirty_read(kem, Remote) of
	[_Old_kem] ->
	    mnesia:dirty_delete(kem, Remote),
	    {reply, ok, State};
	[] ->
	    {reply, {error, not_found}, State}
    end;
handle_call({Remote, ?RESPONSE_FLAG, Kem_id, Dhir_pub, Dhbr_pub, Dhrr_pub}, _From, 
	    #state{dhi = Dhi} = State) ->
    case mnesia:dirty_read(kem, Remote) of
	[Old_kem] when Old_kem#kem.kem_id =:= Kem_id ->
	    mnesia:dirty_delete(kem, Remote),
	    Dhb = Old_kem#kem.dhb,
	    Dhr = Old_kem#kem.dhr,
	    Session_data = {Dhi, Dhb, Dhr, undefined, Dhir_pub, Dhbr_pub, Dhrr_pub, undefined},
	    {reply, {ok, Session_data}, State};
	[] ->
	    {reply, {error, not_found}, State}
    end;
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% @private
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private KeyExchange messages older than their Time to Live should
%% be removed from storage. So, a connect that doesn't get a response
%% within the ttl period, looses it's kem.
handle_info(scrub, State) ->
    Now = axolotl:ttl(),
    F = fun() ->
		mnesia:foldl(
		  fun(Record, Ids) ->
			  case Record#kem.ttl of
			      TTL when TTL =< Now ->
				  mnesia:dirty_delete_object(Record),
				  [Record#kem.remote | Ids];
			      _ ->
				  Ids
			  end
		  end, [], kem)
	end,
    {atomic, _} = mnesia:transaction(F),
    erlang:send_after(?SCRUB_INTV, self(), scrub),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
