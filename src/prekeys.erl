-module(prekeys).

%%% @doc

-behaviour(gen_server).

-include("../include/axolotl.hrl").
-include("../include/textsecure.hrl").
-include("../include/logger.hrl").

%% API
-export([start_link/3, pkmsg2msg/2, pkb2pkmsg/1, generate/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {id, device_id, dhi}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Id, Device_id, Dhi) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Id, Device_id, Dhi], []).

-spec generate(N) -> Result when
      N :: pos_integer(),
      Result :: {Id :: axolotl:registration_id(), 
		 Device_id :: axolotl:device_id(),
		 Dhi_pub :: axolotl:key(),  
		 Signed_prekey :: #signed_prekey{}, 
		 Last_resort_prekey :: #prekey{}, 
		 Prekeys :: [#prekey{}]}.
%% @doc Generate a number of prekeys and return as a list. After
%% generating the list with prekeys, the user application should make
%% these prekeys available externally for remote peers to be able to
%% use them.
generate(N) ->
    gen_server:call(?SERVER, {generate, N}).

-spec pkmsg2msg(Version, Pkmsg) -> Result when
      Version :: 2 | 3,
      Pkmsg :: #prekey_whisper_message{},
      Result :: {Session_data :: tuple(), Embedded_msg :: binary()}.
%% @doc Extract prekey material from message, check with local pending
%% prekeys and return data for new session and the embedded whisper
%% message.
pkmsg2msg(Version, Pkmsg) ->
    gen_server:call(?SERVER, {pkmsg2msg, Version, Pkmsg}).
	    
-spec pkb2pkmsg(Prekey_bundle) -> Result when
      Prekey_bundle :: #prekey_bundle{},
      Result :: {Version :: 2 | 3, Session_data :: tuple(), #prekey_whisper_message{}}.
%% @doc Extract data from the prekey bundle, generate base and ratchet
%% keys and return as session data. This function will process a
%% prekey bundle retrieved from a remote server, according to the
%% either version 2 or higher.
pkb2pkmsg(Pkb) ->
    gen_server:call(?SERVER, {pkb2pkmsg, Pkb}).

%% %===================================================================
%% % gen_server callbacks
%% %===================================================================

%% @private
init([Id, Device_id, Dhi]) ->
    ok = mnesia:wait_for_tables([prekey_base, prekey, signed_prekey], 4000),
    case mnesia:table_info(prekey_base, size) of
	0 ->
	    Last_resort_prekey = create_prekey(?MAX_PREKEY_ID + 1),
	    Last_id = ?MIN_PREKEY_ID,
	    Prekey_base = #prekey_base{key = 'base', 
				       last_prekey_id = Last_id, 
				       last_signed_prekey_id = Last_id, 
				       last_resort_prekey = Last_resort_prekey},
	    mnesia:dirty_write(Prekey_base);
	1 ->
	    ok
    end,
    {ok, #state{id = Id, device_id = Device_id, dhi = Dhi}}.

%% @private
handle_call({pkmsg2msg, 3, Pkmsg}, _From, #state{dhi = Dhi} = State) 
  when Pkmsg#prekey_whisper_message.signedPreKeyId =/= ?MAX_PREKEY_ID + 1 ->
    Signed_prekey_id = Pkmsg#prekey_whisper_message.signedPreKeyId,
    [Signed_prekey] = mnesia:dirty_read(signed_prekey, Signed_prekey_id),
    Dhb = Dhr = Signed_prekey#signed_prekey.signed_prekey,
    Dh1 = case Pkmsg#prekey_whisper_message.preKeyId of
		 undefined ->
		     undefined;
		 Prekey_id ->
		     Prekey = get_and_delete(Prekey_id),
		     Prekey#prekey.prekey
	     end,
    Dhir_pub = Pkmsg#prekey_whisper_message.identityKey,
    Dhbr_pub = Pkmsg#prekey_whisper_message.baseKey,
    Session_data = {Dhi, Dhb, Dhr, Dh1, Dhir_pub, Dhbr_pub, undefined, undefined},
    Msg = Pkmsg#prekey_whisper_message.message,
    {reply, {Session_data, Msg}, State};
handle_call({pkmsg2msg, 2, Pkmsg}, _From, #state{dhi = Dhi} = State) 
  when Pkmsg#prekey_whisper_message.preKeyId =/= ?MAX_PREKEY_ID + 1 ->
    Prekey = get_and_delete(Pkmsg#prekey_whisper_message.preKeyId),
    Dhb = Dhr = Prekey#prekey.prekey,
    Dhir_pub = Pkmsg#prekey_whisper_message.identityKey,
    Dhbr_pub = Pkmsg#prekey_whisper_message.baseKey,
    Session_data = {Dhi, Dhb, Dhr, undefined, Dhir_pub, Dhbr_pub, undefined, undefined},
    Msg = Pkmsg#prekey_whisper_message.message,
    {reply, {Session_data, Msg}, State};
handle_call({generate, N}, _From, #state{id = Id, device_id = Device_id, 
					 dhi = {Dhi_priv, Dhi_pub}} = State) ->
    [Prekey_base] = mnesia:dirty_read(prekey_base, 'base'),
    Start_prekey_id = Prekey_base#prekey_base.last_prekey_id,
    Start_signed_prekey_id = Prekey_base#prekey_base.last_signed_prekey_id,
    {Last_prekey_id, Prekeys} = create_prekeys(Start_prekey_id, N),
    {Last_signed_prekey_id, 
     Signed_prekey} = create_signed_prekey(Start_signed_prekey_id, Dhi_priv),
    keep_signed_prekeys(?NUMBER_OF_SIGNED_PREKEYS),
    Last_resort_prekey = Prekey_base#prekey_base.last_resort_prekey,
    mnesia:dirty_write(Prekey_base#prekey_base{last_prekey_id = Last_prekey_id,
					       last_signed_prekey_id = Last_signed_prekey_id}),
    Reply = {Id, Device_id, Dhi_pub, Signed_prekey, Last_resort_prekey, Prekeys},
    {reply, Reply, State};
handle_call({pkb2pkmsg, Pkb}, _From, #state{id = Id, dhi = Dhi} = State) 
  when is_integer(Pkb#prekey_bundle.signed_prekey_id) ->
    #prekey_bundle{identity_key_pub = Dhir_pub,
		   signed_prekey_id = Signed_prekey_id,
		   signed_prekey_pub = Dhbr_pub,
		   signed_prekey_sign = Sign} = Pkb,
    case curve25519:verify(Dhir_pub, Dhbr_pub, Sign) of
	true ->
	    {_, Dhi_pub} = Dhi,
	    {_, Dhb_pub} = Dhb = curve25519:key_pair(),
	    Dhrr_pub = Dhbr_pub,  % TODO: is this correct?
	    Session_data = {Dhi, Dhb, undefined, undefined, Dhir_pub, Dhbr_pub, Dhrr_pub, undefined},
	    Pkmsg = #prekey_whisper_message{registrationId = Id,
					    signedPreKeyId = Signed_prekey_id,
					    baseKey = Dhb_pub,
					    identityKey = Dhi_pub},
	    {reply, {3, Session_data, Pkmsg}, State} ;
	false ->
	    {reply, {error, invalid_signature}, State}
    end;
handle_call({pkb2pkmsg, Pkb}, _From, #state{id = Id, dhi = Dhi} = State) ->
    #prekey_bundle{identity_key_pub = Dhir_pub,
		   prekey_id = Prekey_id,
		   prekey_pub = Dhbr_pub} = Pkb,
    {_, Dhi_pub} = Dhi,
    {_, Dhb_pub} = Dhb = curve25519:key_pair(),
    Dhrr_pub = Dhbr_pub,  % TODO: is this correct?
    Session_data = {Dhi, Dhb, undefined, undefined, Dhir_pub, Dhbr_pub, Dhrr_pub, undefined},
    Pkmsg = #prekey_whisper_message{registrationId = Id,
				    preKeyId = Prekey_id,
				    baseKey = Dhb_pub,
				    identityKey = Dhi_pub},
    {reply, {2, Session_data, Pkmsg}, State};
handle_call(_Generate, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% @private
handle_cast(_Msg, State) ->
    {noreply, State}.

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

%% @private 
%% @doc Prekeys are generated using a recursive function
%% started here.
create_prekeys(Start_id, N) ->
    create_prekeys(Start_id, N, []).

%% @private 
create_prekeys(0, N, Prekeys) ->
    %% Skip Prekey id of 0.
    create_prekeys(?MIN_PREKEY_ID, N, Prekeys);
create_prekeys(Prekey_id, 0, Prekeys) ->
    %% TODO: is reverse realy necessary?
    {Prekey_id, lists:reverse(Prekeys)};
create_prekeys(Prekey_id, N, Prekeys) ->
    Prekey = create_prekey(Prekey_id),
    create_prekeys((Prekey_id + 1) rem (?MAX_PREKEY_ID + 1), N - 1, [Prekey | Prekeys]).

%% @private 
create_prekey(Prekey_id) ->
    Key_pair = curve25519:key_pair(),
    Prekey = #prekey{prekey_id = Prekey_id, prekey = Key_pair},
    mnesia:dirty_write(Prekey),
    Prekey.

%% @private 
create_signed_prekey(0, Dhi_priv) ->
    create_signed_prekey(?MIN_PREKEY_ID, Dhi_priv);
create_signed_prekey(Signed_prekey_id, Dhi_priv) ->
    Ttl = axolotl:ttl(),
    Signed_prekey = {_priv, Signed_prekey_pub} = curve25519:key_pair(),
    Signature = curve25519:sign(Dhi_priv, Signed_prekey_pub),
    SPrekey = #signed_prekey{signed_prekey_id = Signed_prekey_id, 
			     signed_prekey = Signed_prekey,
			     signed_prekey_sign = Signature,
			     ttl = Ttl},
    mnesia:dirty_write(SPrekey),
    {(Signed_prekey_id + 1) rem (?MAX_PREKEY_ID + 1), SPrekey}.
    
%% @private 
%% @doc remove signed prekeys if their number exceeds N by removing
%% the oldest signed prekeys first.  Since we have only (very) few
%% signed keys in store, we don't mind performance at the moment.
keep_signed_prekeys(N) ->
    case mnesia:table_info(signed_prekey, size) of
	Nr when Nr > N ->
	    %% For all records on storgae, fetch their timestamp and
	    %% their id and return this as a list of timestamp - id
	    %% tuples.
	    F = fun() ->
			mnesia:foldl(
			  fun(Record, Acc) ->
				  #signed_prekey{signed_prekey_id = Signed_prekey_id,
						 ttl = Ttl} = Record,
				  [ {Ttl, Signed_prekey_id} | Acc]
			  end, [], signed_prekey)
		end,
	    {atomic, L1} = mnesia:transaction(F),
	    %% Now sort the list so we get a list with the oldest
	    %% signed keys first.
	    L2 = lists:sort(L1),
	    %% Delete as many records as needed, using the list.
	    keep_signed_prekeys(Nr - N, L2);
	_ ->
	    ok
    end.

%% @private 
keep_signed_prekeys(0, _L) ->
    ok;
keep_signed_prekeys(N, [{_Ttl, Signed_prekey_id} | T]) ->
    mnesia:dirty_delete(signed_prekey, Signed_prekey_id),
    keep_signed_prekeys(N - 1, T).

%% @private 
get_and_delete(Prekey_id) ->
    [Prekey] = mnesia:dirty_read(prekey, Prekey_id),
    mnesia:dirty_delete(prekey, Prekey_id),
    Prekey.
