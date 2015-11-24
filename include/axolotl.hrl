-ifndef(axolotl_hrl).
-define(axolotl_hrl, true).

-define(VERSION, 3).  % Protocol version 2 | 3.

-define(EXTENDED_RANGE, true).
-ifdef(EXTENDED_RANGE).
-define(MAX_REGISTRATION_ID, 16#7fffffff).
-else.
-define(MAX_REGISTRATION_ID, 16#3ffd).
-endif.
-define(MIN_REGISTRATION_ID, 1).

-define(MAX_DEVICE_ID, 16#7fffffff). 
-define(MIN_DEVICE_ID, 1).

%% Number of signed prekeys to keep in storage.
-define(NUMBER_OF_SIGNED_PREKEYS, 2).
%% NOT USED: Number of signed prekeys to keep in storage.
-define(NUMBER_OF_PREKEYS, 100).

-define(MAX_PREKEY_ID, 16#fffffe).
-define(MIN_PREKEY_ID, 1).
-define(PREKEY_TTL, 86400). % secs = prekey time to live = 1 day

-define(MAX_KEM_ID, 16#ffff).
-define(MIN_KEM_ID, 0). 
-define(KEM_TTL, 60). % secs = Key exchange time to live = 1 minute

%% TODO: The `kem' and `prekey' records currently are used both for
%% passing around data within the program and for storing
%% data. However, parts of the data and in particular the public parts
%% of the keys, aren't used anymore after being published or sent and
%% there is no need to keep them. Simplify storage.

%% Following records are also used for storing data.
-record(self, {node :: node(),
	       id :: axolotl:registration_id(),
	       device_id :: axolotl:device_id(),
	       dhi :: axolotl:key_pair()
	      }).

-record(identity, {dhi_pub = axolotl:key(),
		   remote = axolotl:remote(), 
		   registration_id = axolotl:registration_id()}). 
-record(kem, {remote :: axolotl:remote(),
	      kem_id :: kems:kem_id(),
	      dhb :: axolotl:key_pair(),
	      dhr :: axolotl:key_pair(),
	      ttl % Time to live as {MegaSecs, Secs, MicroSecs}
	     }).

-record(prekey, {prekey_id :: prekey:prekey_id(),
		 prekey :: axolotl:key_pair()
	    }).

-record(signed_prekey, {signed_prekey_id :: prekey:prekey_id(),
			signed_prekey :: axolotl:key_pair(),
			signed_prekey_sign :: axolotl:sign(),
			ttl :: erlang:timestamp()
		       }).

-record(prekey_bundle, {registration_id,
			device_id,
			identity_key_pub,
			prekey_id,
			prekey_pub,
			signed_prekey_id,
			signed_prekey_pub,
			signed_prekey_sign,
			ttl}).

-record(prekey_base, {key :: 'base',
		      last_prekey_id :: axolotl:prekey_id(), 
		      last_signed_prekey_id :: axolotl:prekey_id(), 
		      last_resort_prekey :: #prekey_bundle{}}).

-record(session, {remote :: axolotl:remote(),
		  state_name,
		  state
		 }).


%% The prekey_bundle record is used to pass information to and from
%% the axolotl program to external parties. An appliction should pack
%% the data from this record somehow and pass it on to / from the
%% remote peer. There is no protocol buffer definition for this.
%% -record(prekey_bundle, {peer :: node(), 
%% 			registration_id :: axolotl:registration_id(),
%% 			device_id :: axolotl:device_id(),
%% 			identity_key_pub :: axolotl:key(),
%% 			prekey_id :: prekey:prekey_id(),
%% 			prekey_pub :: axolotl:key(),
%% 			signed_prekey_id :: prekey:prekey_id(),
%% 			signed_prekey_pub :: axolotl:key(),
%% 			signed_prekey_sign :: axolotl:sign(),
%% 			ttl :: erlang:timestamp()}).

-endif.
