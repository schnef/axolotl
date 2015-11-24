-module(utils).

-include("../include/axolotl.hrl").
-include("../include/textsecure.hrl").
-include("../include/logger.hrl").

-export([get_prekeys/1, add_identity/3, tuple2pkb/1, pkb2tuple/1]).

%% =============================================================================
%% Following functions are helper functions for testing and creating a
%% rudimentary appliction. The libaxolotl-java implementation has no
%% function to add trusted identities or get a bunch of prekeys to be
%% uploaded to the TS server.
%% 
%% The code is not intended to be perfect but serves more as a
%% showcase.
%% =============================================================================

-spec add_identity(Remote, Type, Binary) -> Result when
      Remote :: axolotl:remote(),
      Type :: pkmsg | msg,
      Binary :: binary(),
      Result :: ok | {error, Reason :: term()}.
%% @doc Helper function to add a identity to the trusted identities
%% store. This function will process either a KeyExchange message or
%% PrekeyWhisper message, take out the required data and add the
%% identity to the trusted identity store. This is a helper function
%% that lacks lots of functionality and should be removed in the
%% fututure.
%%
%% TODO: REPLACE BY SOMETHING MORE APPROPRIATE.
add_identity(Remote, pkmsg, <<_Version:1/binary, Serialized/binary>>) ->
    Pkmsg = textsecure:decode_msg(Serialized, prekey_whisper_message),
    Remote_id = Pkmsg#prekey_whisper_message.registrationId,
    Remote_dhi_pub = Pkmsg#prekey_whisper_message.identityKey,
    identities:add(Remote, Remote_id, Remote_dhi_pub);
add_identity(Remote, kem, <<_Version:1/binary, Serialized/binary>>) ->
    Kem = textsecure:decode_msg(Serialized, key_exchange_message),
    Remote_id = Kem#key_exchange_message.id,
    Remote_dhi_pub = Kem#key_exchange_message.identityKey,
    identities:add(Remote, Remote_id, Remote_dhi_pub).

-spec get_prekeys(N) -> Result when
      N :: pos_integer(),
      Result :: tuple().
%% @doc Returns a list with fresh prekey bundles that can be used by remote
%% peers to establish new sessions.
get_prekeys(N) when N > 0 ->
    {Id, Device_id, Dhi_pub, 
     Signed_prekey, 
     Last_resort_prekey, 
     Prekeys}  = prekeys:generate(N),
    #signed_prekey{signed_prekey_id = Signed_prekey_id,
		   signed_prekey = {_priv, Signed_prekey_pub},
		   signed_prekey_sign = Signed_prekey_sign,
		   ttl = Ttl} = Signed_prekey,
    Signed_pk = {Signed_prekey_id, Signed_prekey_pub, Signed_prekey_sign, Ttl},
    #prekey{prekey_id = LRPrekey_id,
	    prekey = {_, LRPrekey_pub}} = Last_resort_prekey,
    Last_resort_pk = {LRPrekey_id, LRPrekey_pub},
    Pks = [ {Prekey_id, Prekey_pub} 
	    || #prekey{prekey_id = Prekey_id, 
		       prekey = {_, Prekey_pub}} <- Prekeys],
    {Id, Device_id, Dhi_pub, Signed_pk, Last_resort_pk, Pks}.

-spec tuple2pkb({Registration_id :: axolotl:registration_id(),
		 Device_id :: axolotl:device_id(),
		 Identity_key_pub :: axolotl:key(),
		 Prekey_id :: axolotl:prekey_id(),
		 Prekey_pub :: axolotl:key(),
		 Signed_prekey_id :: axolotl:prekey_id(),
		 Signed_prekey_pub :: axolotl:key(),
		 Signed_prekey_sign :: axolotl:sign(),
		 Ttl :: axolotl:ttl()}) ->
		       #prekey_bundle{}.
%% @doc HELPER FUNCTION: Convert a tuple to the internal record used for prekey bundles.
tuple2pkb({Registration_id,
	   Device_id,
	   Identity_key_pub,
	   Prekey_id,
	   Prekey_pub,
	   Signed_prekey_id,
	   Signed_prekey_pub,
	   Signed_prekey_sign,
	   Ttl}) ->
    #prekey_bundle{registration_id = Registration_id,
		   device_id = Device_id,
		   identity_key_pub = Identity_key_pub,
		   prekey_id = Prekey_id,
		   prekey_pub = Prekey_pub,
		   signed_prekey_id = Signed_prekey_id,
		   signed_prekey_pub = Signed_prekey_pub,
		   signed_prekey_sign = Signed_prekey_sign,
		   ttl = Ttl}.

-spec pkb2tuple(#prekey_bundle{}) -> 
		       {Registration_id :: axolotl:registration_id(),
			Device_id :: axolotl:device_id(),
			Identity_key_pub :: axolotl:key(),
			Prekey_id :: axolotl:prekey_id(),
			Prekey_pub :: axolotl:key(),
			Signed_prekey_id :: axolotl:prekey_id(),
			Signed_prekey_pub :: axolotl:key(),
			Signed_prekey_sign :: axolotl:sign(),
			Ttl :: axolotl:ttl()}.
%% @doc HELPER FUNCTION: Convert a the internally record used for prekey bundles to a tuple.
pkb2tuple(#prekey_bundle{registration_id = Registration_id,
			 device_id = Device_id,
			 identity_key_pub = Identity_key_pub,
			 prekey_id = Prekey_id,
			 prekey_pub = Prekey_pub,
			 signed_prekey_id = Signed_prekey_id,
			 signed_prekey_pub = Signed_prekey_pub,
			 signed_prekey_sign = Signed_prekey_sign,
			 ttl = Ttl}) ->
    {Registration_id,
	   Device_id,
	   Identity_key_pub,
	   Prekey_id,
	   Prekey_pub,
	   Signed_prekey_id,
	   Signed_prekey_pub,
	   Signed_prekey_sign,
	   Ttl}.
    
