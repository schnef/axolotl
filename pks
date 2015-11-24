#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp enable

%% This is not code, this is a junkyard!!

%% {Id, Device_id, Dhi_pub, Signed_prekey, Last_resort_prekey, Prekeys}
%% Signed_prekey :: {Signed_prekey_id, Signed_prekey, Signature}.
%% Prekeys :: [{Prekey_id, Prekey}].
%% Last_resort_prekey :: {Prekey_id, Prekey}}

-mode(compile).
-export([maintenance_loop/0, io_loop/0]).

-include_lib("stdlib/include/qlc.hrl").
-record(peer,          {peer, 
			registration_id, 
			device_id,
			identity_key_pub,
			last_resort_prekey}).
-record(prekey,        {key,
			prekey_id,
			prekey_pub,
			timestamp}).
-record(signed_prekey, {key,
			signed_prekey_id,
			signed_prekey_pub,
			signed_prekey_sign,
			ttl}).

main(_) ->
    net_kernel:start([pks, shortnames]),
    mnesia:start(),
    case mnesia:system_info(tables) of
	[schema] ->
	    {atomic, ok} = create_db();
	_ ->
	    ok % recreate_tables()
    end,
    Pid_recv = spawn(?MODULE, io_loop, []),
    register(io_loop, Pid_recv),
    Pid_send = spawn(?MODULE, maintenance_loop, []),
    register(maintenance_loop, Pid_send),
    cmd_loop(),
    mnesia:stop().
    
cmd_loop() ->
    case io:get_line("pks> ") of
	eof ->	
	    io:format("~nDone~n"),
	    halt();
	Text ->	
	    case string:strip(Text, both, $\n) of
		":o" ->
		    observer:start();
		":d" ->
		    debugger:start();
		[] ->
		    ok;
		Cmd -> 
		    io:format(" ** Unknown command ~p~n", [Cmd])
	    end,
	    cmd_loop()
    end.

io_loop() ->
    receive
	{hello, From, Peer} when is_pid(From) ->
	    %% io:format("Hello from peer ~p [~p]~n", [Peer, From]),
	    case mnesia:dirty_read(peer, Peer) of
		[#peer{registration_id = Registration_id, device_id = Device_id}] ->
		    Client = {Registration_id, Device_id},
		    case pks_check(Client) of
			ok ->
			    ok;
			{error, shortage} ->
			    From ! {prekeys, generate}
		    end;
		[] ->
		    From ! {prekeys, generate}
	    end;
	{upload, Peer, {Id, Device_id, Identity_key_pub, Signed_pk, Last_resort_pk, Pks}} ->
	    io:format("Peer ~p uploads prekeys~n", [Peer]),
	    Timestamp = os:timestamp(),
	    F = fun() ->
			mnesia:write(#peer{peer = Peer, 
					   registration_id = Id, 
					   device_id = Device_id,
					   identity_key_pub = Identity_key_pub,
					   last_resort_prekey = Last_resort_pk}),
			{Signed_prekey_id, 
			 Signed_prekey_pub, 
			 Signed_prekey_sign, 
			 Ttl} = Signed_pk,
			mnesia:write(#signed_prekey{key = {Id, Device_id},
						    signed_prekey_id = Signed_prekey_id,
						    signed_prekey_pub = Signed_prekey_pub,
						    signed_prekey_sign = Signed_prekey_sign,
						    ttl = Ttl}),
			%%io:format("Write ~p~n", [Prekey_bundles]),
			[ mnesia:write(#prekey{key = {Id, Device_id},
					       prekey_id = Prekey_id,
					       prekey_pub = Prekey_pub,
					       timestamp = Timestamp}) 
			  || {Prekey_id, Prekey_pub} <- Pks ]
		end,
	    {atomic, _} = mnesia:transaction(F);
	{fetch, From, Peer} when is_pid(From) ->
	    io:format("Peer ~p requests prekey_bundle for peer ~p~n", [From, Peer]),
	    F = fun() ->
			[#peer{peer = Peer, 
			       registration_id = Registration_id, 
			       device_id = Device_id,
			       identity_key_pub = Identity_key_pub}] = mnesia:read(peer, Peer),
			Key = {Registration_id, Device_id},
			[#signed_prekey{signed_prekey_id = Signed_prekey_id,
					signed_prekey_pub = Signed_prekey_pub,
					signed_prekey_sign = Signed_prekey_sign,
					ttl = Ttl}] = mnesia:read(signed_prekey, Key),
			[Prekey | _] = mnesia:read(prekey, Key),
			#prekey{prekey_id = Prekey_id, prekey_pub = Prekey_pub} = Prekey,
			mnesia:delete_object(Prekey),
			{Registration_id,
			 Device_id,
			 Identity_key_pub,
			 Prekey_id,
			 Prekey_pub,
			 Signed_prekey_id,
			 Signed_prekey_pub,
			 Signed_prekey_sign,
			 Ttl}
		end,
	    case mnesia:transaction(F) of
		{atomic, Prekey_bundle} ->
		    From ! {prekey_bundle, Prekey_bundle};
		_ ->
		    io:format("Tectching prekey bundle failed.~n")
	    end;
	Msg ->
	    io:format(" ** Recv: Ignored msg: ~p~n", [Msg])
    end,
    io_loop().
    
maintenance_loop() -> 
    receive
	Msg ->
	    io:format(" ** Maintenance: Ignored msg: ~p~n", [Msg])
    end,
    maintenance_loop().
    
pks_check(Client) ->
    io:format("Review client ~p prekeys~n", [Client]),
    Prekeys = do(qlc:q([Prekey#prekey.key
			|| Prekey <- mnesia:table(prekey),
			   Prekey#prekey.key =:= Client])),
    case length(Prekeys) of
	N when N < 20 ->
	    {error, shortage};
	_ ->
	    ok
    end.

do(Q) ->
    F = fun() ->
		qlc:e(Q) 
	end,
    {atomic, Val} = mnesia:transaction(F),
    Val.
    
create_db() ->
    mnesia:stop(),
    mnesia:create_schema([node()]),
    mnesia:start(),
    
    mnesia:create_table(peer,
			[{attributes, record_info(fields, peer)},
			 {type, set},
			 {disc_copies, [node()]}
			]),
    mnesia:create_table(signed_prekey,
			[{attributes, record_info(fields, signed_prekey)},
			 {type, set},
			 {disc_copies, [node()]}
			]),
    mnesia:create_table(prekey,
			[{attributes, record_info(fields, prekey)},
			 {type, bag},
			 {disc_copies, [node()]}
			]).
