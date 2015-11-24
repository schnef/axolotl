-module(axolotl_app).

-behaviour(application).

-include("../include/axolotl.hrl").
-include("../include/logger.hrl").

%% Application callbacks
-export([start/2, stop/1]).

%% ===================================================================
%% Application callbacks
%% ===================================================================

start(_StartType, _StartArgs) ->
    mnesia:start(),
    case mnesia:system_info(tables) of
	[schema] ->
	    {atomic,ok} = do_create_db(),
	    Id = crypto:rand_uniform(?MIN_REGISTRATION_ID, ?MAX_REGISTRATION_ID),
	    Device_id = crypto:rand_uniform(?MIN_DEVICE_ID, ?MAX_DEVICE_ID),
	    Dhi = curve25519:key_pair(),
	    ok = mnesia:dirty_write(#self{node = node(), id = Id, device_id = Device_id, dhi = Dhi});
	_ ->
	    mnesia:wait_for_tables([self], 4000),
	    [#self{id = Id, device_id = Device_id, dhi = Dhi}] = mnesia:dirty_read(self, node())
    end,
    axolotl_sup:start_link(Id, Device_id, Dhi).

stop(_State) ->
    ok.

do_create_db() ->
    mnesia:stop(),
    mnesia:create_schema([node()]),
    mnesia:start(),
    recreate_tables().

%% @doc (re)create tables. The self table has one record which holds
%% the local party's data such as id, identity key etc. The ke table
%% stores the issued key exchanges which are kept to check if a key
%% exchange response is valid. The pk table is the list of previously
%% issued and still unused prekeys. The session table stores the
%% session state of each open session.
recreate_tables() ->
    try
	mnesia:delete_table(self),
	mnesia:delete_table(identity),
	mnesia:delete_table(kem),
	mnesia:delete_table(prekey_base),
	mnesia:delete_table(prekey),
	mnesia:delete_table(session)
    after
	ok
    end,
    mnesia:create_table(self,
			[{attributes, record_info(fields, self)},
			 {type, set},
			 {disc_copies, [node()]}
			]),
    mnesia:create_table(identity,
			[{attributes, record_info(fields, identity)},
			 {type, set},
			 {disc_copies, [node()]}
			]),
    mnesia:create_table(kem,
			[{attributes, record_info(fields, kem)},
			 {type, set},
			 {disc_copies, [node()]}
			]),
    mnesia:create_table(prekey_base,
			[{attributes, record_info(fields, prekey_base)},
			 {type, set},
			 {disc_copies, [node()]}
			]),
    mnesia:create_table(prekey,
			[{attributes, record_info(fields, prekey)},
			 {type, set},
			 {disc_copies, [node()]}
			]),
    mnesia:create_table(signed_prekey,
			[{attributes, record_info(fields, signed_prekey)},
			 {type, set},
			 {disc_copies, [node()]}
			]),
    mnesia:create_table(session,
			[{attributes, record_info(fields, session)},
			 {type, set},
			 {disc_copies, [node()]}
			]).
