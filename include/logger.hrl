%%% -*- mode: erlang -*-
-ifndef(logger_hrl).
-define(logger_hrl, true).

-define(PRINT(Format, Args), io:format(Format, Args)).

-ifdef(LAGER).
-compile([{parse_transform, lager_transform}]).

-define(DEBUG(Format, Args),
	lager:debug(Format, Args)).

-define(INFO_MSG(Format, Args),
	lager:info(Format, Args)).

-define(WARNING_MSG(Format, Args),
	lager:warning(Format, Args)).

-define(ERROR_MSG(Format, Args),
	lager:error(Format, Args)).

-define(CRITICAL_MSG(Format, Args),
	lager:critical(Format, Args)).

-else.

-define(DEBUG(Text), error_logger:info_msg(string:concat("~p, ~p, ", Text), [?MODULE, ?LINE])).
-define(DEBUG(Format, Args),
	error_logger:info_msg(string:concat("~p, ~p, ", Format), [?MODULE, ?LINE | Args])).

-define(INFO_MSG(Text), error_logger:info_msg(string:concat("~p, ~p, ", Text), [?MODULE, ?LINE])).
-define(INFO_MSG(Format, Args),
	error_logger:info_msg(string:concat("~p, ~p, ", Format), [?MODULE, ?LINE | Args])).

-define(WARNING_MSG(Text), error_logger:warning_msg(string:concat("~p, ~p, ", Text), [?MODULE, ?LINE])).
-define(WARNING_MSG(Format, Args),
	error_logger:warning_msg(string:concat("~p, ~p, ", Format), [?MODULE, ?LINE | Args])).

-define(ERROR_MSG(Text), error_logger:error_msg(string:concat("~p, ~p, ", Text), [?MODULE, ?LINE])).
-define(ERROR_MSG(Format, Args),
	error_logger:error_msg(string:concat("~p, ~p, ", Format), [?MODULE, ?LINE | Args])).

-define(CRITICAL_MSG(Text), error_logger:error_msg(string:concat("~p, ~p, ", Text), [?MODULE, ?LINE])).
-define(CRITICAL_MSG(Format, Args),
	error_logger:error_msg(string:concat("~p, ~p, ", Format), [?MODULE, ?LINE | Args])).

-endif.

-endif.
