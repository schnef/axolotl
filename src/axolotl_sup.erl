-module(axolotl_sup).

-behaviour(supervisor).

%% API
-export([start_link/3, add_session/1]).

%% Supervisor callbacks
-export([init/1]).

%% ===================================================================
%% API functions
%% ===================================================================

start_link(Id, Device_id, Dhi) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Id, Device_id, Dhi]).

add_session([Remote | _] = Args_list) ->
    Child = {Remote, {session, start_link, [Args_list]}, 
	     permanent, 5000, worker, [session]},
    supervisor:start_child(?MODULE, Child).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

%% @private
%% Use old tuple form for childspecs for compatibility.
init([Id, Device_id, Dhi]) ->
    {ok, { {one_for_one, 5, 10}, 
	   [{identities, {identities, start_link, []},
	     permanent, 5000, worker, [identities]},
	    {prekeys, {prekeys, start_link, [Id, Device_id, Dhi]},
	     permanent, 5000, worker, [prekeys]},
	    {kems, {kems, start_link, [Id, Device_id, Dhi]},
	     permanent, 5000, worker, [kems]}]
	 } }.

