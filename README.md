# Overview

This is an Erlang implementation of the ratcheting secure Axolotl
protocol. For details on the ratcheting algorithm see [Axolotl
Ratchet](https://github.com/trevp/axolotl/wiki) and the for the
messages description see [TextSecure Protocol
V2](https://github.com/WhisperSystems/Signal-Android/wiki/ProtocolV2).

In contrast to the other implementations I know, you don't have to
build your own storage back-end. Except for a recent Erlang/OTP,
rebar3, git and C compiler, there are no dependencies you will have to
resolve to use the software. The dependencies are trivial to install.

Currently there are several implementations of the Axolotl protocol as
libraries from [Open Whisper
Systems](https://github.com/WhisperSystems), all closely following the
[libaxolotl-java](https://github.com/WhisperSystems/libaxolotl-java)
implementation which serves more or less as the reference
implementation of the protocol. Except for the previously mentioned
two documents which describe the ratcheting algorithm and the messages
format, there are no further specs detailing the requirements. Lack of
specifications properly are the reason all implementations follow the
reference implementation very closely. In this project, the reference
implementation was consulted to see what the system is supposed to do
but it does not follow its design. Since Erlang is a functional
language while the other implementations are all in object oriented
programming languages, a new approach was mandatory.

To keep things simple, the code does not rely heavily on third party
libraries. The code uses two pieces of code from sister projects
[curve25519](https://github.com/schnef/curve25519) and
[hkdf](https://github.com/schnef/hkdf), implementing curve25519-donna,
curve25519 signing / verifying and HMAC-based Extract-and-Expand Key
Derivation Function respectively. You will need the Erlang
implementation of Google's Protocol Buffers compiler
[gpb](https://github.com/tomas-abrahamsson/gpb), a C compiler and
[Rebar](https://github.com/rebar/rebar). The dependencies on
`curve25519`, `hkdf`, `gdb` and `reloader` are automatically resolved
during installation.

The program was implemented and tested on ErlangOTP version 18 on a
Debian Jessie AMD64 system and tested on 22. Installing the project on
OS/X, Windows or some other OS should be not to hard if you have a C
compiler and know how to make rebar make use of it.

# Installation

Install ErlangOTP from either [Erlang.org](http://www.erlang.org/) or,
as I mostly do, get it from [Erlang
Solutions](https://www.erlang-solutions.com/resources/download.html). Get
the 'standard' distribution from Erlang Solutions if in doubt and not
the 'enterprise' edition with rebar and other goodies.

Next install 
[rebar3](https://www.rebar3.org/) and follow the instructions
from the site to install. Mostly, I put the rebar3 executable
somewhere in my PATH, e.g. $(HOME)/bin.

To compile the C code for the curve25519 implementation, you will need
a C compiler such as gcc, MingW etc.

```
~$ git clone https://github.com/schnef/axolotl.git
...

~$ cd axolotl

~/axolotl$ rebar3 compile
...
```

# Try it out

The code comes with two scripts to run the code. The `peer` script is
used by each party and the `pks` script is a very simple `prekey
server` used by the peers to upload their prekeys to and to fetch
prekey bundles from. Both scripts are unsuitable for real use but can
be used to see how API calls are made.

> The Erlang Port Mapper Daemon `epmd' must be running to run the
> examples. Start `epmd' by issuing the command `epmd -daemon'.
>
> Depending on your system configuration and Erlang version used, you
> may or may not get log messages.

We will start by starting two peers and building a secure session
between the two. Open two terminal windows, one for each peer, and
enter the following commands:

Terminal 1:
```
~/axolotl$ ./peer juliet romeo
=INFO REPORT==== 28-Oct-2015::14:56:16 ===
    application: mnesia
         exited: stopped
           type: temporary
juliet>
```
In terminal 2:
```
~/axolotl$ ./peer romeo juliet

=INFO REPORT==== 28-Oct-2015::14:58:07 ===
    application: mnesia
         exited: stopped
           type: temporary
romeo> Peer juliet@debian connected
romeo> 
```

In terminal one you will notice that it will display (the host name will be different):

```
juliet> Peer romeo@debian connected
juliet>
```

In terminal one, the peer named `juliet` is started which should
contact remote peer `romeo` and in terminal 2 we start the peer `romeo`
which should connect to `juliet`. The `INFO REPORT` says that the
database system Mnesia is restarted while building the initial
database. The lines `Peer romeo@debian connected` and `juliet@debian
connected` indicate that the two peers are connected and can
communicate with each other. At this point, communication is insecure.

## Synchronous connect

Axolotl supports asynchronous and synchronize secure session
initiation. In the first case, the other peer can be offline or
otherwise unavailable to get the secure connection established. First
we will show how to get a session established when both peers are up
and able to communicate. At one of the terminal windows type the
command `:c` and make sure to follow the next few steps within one
minute since pairing times out after one minute and you will end up
with some weird error message.:

NB: If something goes wrong, you can always start-out fresh by
removing the databases `Mnesia.*`.

```
juliet> :c
juliet> Initiate session for romeo@debian
juliet>  Msg sent     : {kem,<<51,8,161,215,18,18,32,136,56,101,207,40,206,152,207,49,
                       160,2,117,52,103,44,101,145,216,143,55,23,59,109,125,
		       ...
                       195,48,174,78,157,3>>}
juliet>
```

In the other terminal window you will notice how romeo responses

```
romeo> Untrusted remote peer juliet@debian
romeo> Do you trust that party (y/n*)?
```

Type `y` and also in the other terminal confirm trusting the remote
peer by typing `y`.

```
romeo> Pairing response with juliet@debian
romeo>  Msg sent     : {kem,<<51,8,162,215,18,18,32,251,207,31,200,92,138,199,163,46,
                       234,211,115,131,64,128,142,25,33,99,35,153,41,37,151,
		       ...
		       211,143,94,139>>}
romeo>
```

Juliet wants to know if it should trust romeo and the two peers will be paired.

```
juliet> Untrusted remote peer romeo@debian
juliet> Do you trust that party? (y/n*) y
juliet> Paired with romeo@debian
juliet>
```

Juliet starts out initializing the session by sending Romeo a Key
Exchange Message (kem) which shows as `{kem,<<51,8,161,215,18,18,
... 157,3>>}`.  Romeo receives this message as indicated by `"Recieved
kem"` and returns a matching Key Exchange Message to Juliet:
`{kem,<<51,8,162,215,18 ... 94,139>>}`. Juliet and Romeo now have all
data available to get their side of the secure session up and
running. NB: In a real-world situation there should be a "out of band"
check on the public identity keys used by Juliet and Romeo.

Now, Juliet and Romeo can speak in private:

```
juliet> Hello Romeo!
juliet>  Msg sent     : {msg,<<51,10,32,93,15,121,251,182,85,128,131,49,179,217,26,
	     	      ...
	     	      252,221,130>>}
juliet>
```

```
romeo> Received msg: msg: "Hello Romeo!"
romeo>
```

Juliette's message gets encrypted and is sent as a `whipser` message to
Romeo.

## Re-establishing a session

Once a secure session is established, the session will remain valid
even after peers get disconnected, messages are entered offline and
the connection gets established some time later. Let's demonstrate
this by terminating one peer by entering control-D at the prompt:

```
romeo> ^D
Done
~/axolotl$
```

```
juliet> Peer romeo@debian disconnected
juliet>
```

Juliet continues sending messages to Romeo which will be encrypted and
queued for delivery later. NB: in a real-world application, Juliet
would have sent the encrypted message off to some external system for
delivery to Romeo, but we just queue messages here and deliver them
when the connection is re-established.

```
juliet> Where are you Romeo??
juliet>  Msg queued   : {msg,<<51,10,32,93,15,121,251,182,85,128,131,49,179,217,26,
	     	      ...
		      49,165,211,173,236>>}
juliet>
```

Romeo now gets back on line:

```
~/axolotl$ ./peer romeo juliet
romeo> Peer juliet@debian connected
romeo> Resume session for juliet@debian
romeo> Received msg: msg: "Where are you Romeo??"
romeo>
```

## Asynchronous connect

Terminate juliet and romeo and remove the databases with `rm -r Mnesia.*`.
In a third window start the prekey server.

```
~/axolotl$ ./pks

=INFO REPORT==== 24-Nov-2015::12:57:26 ===
    application: mnesia
         exited: stopped
           type: temporary
pks>
```

Now start juliet and romeo again but don't use `:c` to connect. You
will notice that pks finds there are no prekeys available yet for
juliet and romeo and instructs both to upload a bunch of fresh
prekeys.

```
romeo> I must generate!!
romeo> I must generate!!
romeo> Peer juliet@debian connected
romeo>
```

```
juliet> Peer romeo@debian connected
juliet> I must generate!!
juliet> I must generate!!
juliet>
```

```
pks> Peer romeo@debian uploads prekeys
pks> Review client {1976208028,448741545} prekeys
pks> Peer romeo@debian uploads prekeys
pks> Review client {1976208028,448741545} prekeys
pks> Peer juliet@debian uploads prekeys
pks> Review client {138906529,1747365075} prekeys
pks> Peer juliet@debian uploads prekeys
pks> Review client {138906529,1747365075} prekeys
pks>
```

Now, send a message from one peer to the other without first
connecting the two.

> You may notice a crash report which is precisely according to
> plan. The sending party finds out that there is no session running
> for the remote peer, which results in a crash, and will start a new
> session.

```
juliet> Hello Romeo, are you there?
juliet> Get prekey bundle and retry sending
juliet> Make prekey msg from prekey bundle {1976208028,448741545,
	     	    	     	    	   ...
juliet>  Msg sent     : {pkmsg,<<51,40,161,151,158,66,
	     	      ...
juliet>
```

Now at Romeo's end, you first have to tell Romeo that Juliet is to be
trusted, after which the message will be delivered.

```
romeo> Untrusted remote peer juliet@debian
romeo> Do you trust that party? (y/n*) y
romeo> Received msg: pkmsg: "Hello Romeo, are you there?"
romeo>
```

A session now is established and messages can be passed between the
two peers.

# Remarks

With `:o` you can start the Erlang observer from the scripts and `:d`
will start the debugger.

Axolotl is superseded by [Signal](https://signal.org/docs/), which is
a lot better documented. Maybe, one day, I will implement Signal just
for fun.
