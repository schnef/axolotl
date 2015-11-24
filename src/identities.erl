-module(identities).

%%% @doc

-behaviour(gen_server).

-include("../include/axolotl.hrl").
-include("../include/textsecure.hrl").
-include("../include/logger.hrl").

%% API
-export([start_link/0, add/3, check/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

-spec add(Remote, Registration_id, Dhi_pub) -> Result when
      Remote :: axolotl:remote(),
      Registration_id :: axolotl:registration_id(),
      Dhi_pub :: axolotl:key(),
      Result :: ok | {error, Reason},
      Reason :: term().
%% @doc
add(Remote, Registration_id, Dhi_pub) ->
    gen_server:call(?SERVER, {add, Remote, Registration_id, Dhi_pub}).

-spec check(Registration_id, Dhi_pub) -> Result when
      Registration_id :: axolotl:registration_id(),
      Dhi_pub :: axolotl:key(),
      Result :: true | false.
check(Registration_id, Dhi_pub) ->
    gen_server:call(?SERVER, {check, Registration_id, Dhi_pub}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
init([]) ->
    ok = mnesia:wait_for_tables([identity], 4000),
    {ok, #state{}}.

%% @private
handle_call({add, Remote, Registration_id, Dhi_pub}, _From, State) ->
    Reply = case mnesia:dirty_read(identity, Dhi_pub) of
		[_Identity] ->
		    {error, already_exists};
		[] ->
		    Identity = #identity{dhi_pub = Dhi_pub, remote = Remote, 
					 registration_id = Registration_id}, 
		    mnesia:dirty_write(Identity),
		    ok
	    end,
    {reply, Reply, State};
handle_call({check, Registration_id, Dhi_pub}, _From, State) ->
    Reply = case mnesia:dirty_read(identity, Dhi_pub) of
		[#identity{registration_id = Registration_id}] ->
		    true;
		_ ->
		    false
	    end,
    {reply, Reply, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% @private
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
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
