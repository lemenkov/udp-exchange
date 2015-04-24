%%  This Source Code Form is subject to the terms of the Mozilla Public
%%  License, v. 2.0. If a copy of the MPL was not distributed with this
%%  file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%
%% udp-exchange HEP module
%% Contributed by Peter Lemenkov.
%%

-module(udp_exchange_hep_packet).
-include_lib("rabbit_common/include/rabbit.hrl").

-include_lib("hep/include/hep.hrl").
-include_lib("nksip/include/nksip.hrl").

-export([configure/1, parse/4, format/6]).

-record(hep_params, {ets, prefix}).

configure(#exchange{}) ->
	Ets = ets:new(hep_counter, [public, named_table]),
	ets:insert_new(hep_counter, {id, 0}),
	{A,B,C} = os:timestamp(),
	random:seed(A,B,C),
	Prefix = [ random:uniform(26) + 96 || X <- lists:seq(0,15) ],
	#hep_params{ets = Ets, prefix = Prefix}.

parse(_IpAddr, _Port, Packet, #hep_params{prefix = Prefix}) ->
	case hep_multi_decoder:decode(Packet) of
		{ok, Hep} ->
			{ok, Class, Headers, _Rest} = nksip_parse_sipmsg:parse(Hep#hep.payload),

			% SIP_REQUEST 1, SIP_REPLY 2, SIP_INVALID 0
			{SipType, _Code, Reason, Method, Uri} = case Class of
				{req, M0, U0} -> {1, <<"">>, <<"">>, M0, U0};
				{resp, C0, R0} -> {2, C0, R0, C0, <<"">>}
			end,

			RuriUser = case Uri of
				<<"">> -> <<"">>;
				_ ->
					{_, {R, _}} = nksip_parse_header:parse(<<"from">>, Uri),
					R#uri.user
			end,

			F = fun(N) ->
				case proplists:get_value(N, Headers) of
					undefined -> {<<"">>, <<"">>};
					V ->
						{N, {U, T}} = nksip_parse_header:parse(N, V),
						{U#uri.user, T}
				end
			end,

			{FromUser, FromTag} = F(<<"from">>),
			{ToUser, ToTag} = F(<<"to">>),

			Vias = proplists:get_value(<<"via">>, Headers, <<"">>),
			Via = case Vias of
				<<"">> -> <<"">>;
				_ -> {_, [V | _ ]} = nksip_parse_header:parse(<<"via">>, Vias), V
			end,

			Contact = proplists:get_value(<<"contact">>, Headers, <<"">>),
			{ContactIp, ContactPort, ContactUser} = case Contact of
				<<"">> -> {<<"">>, <<"0">>, <<"">>};
				_ ->
					{<<"contact">>, [C | _] } = nksip_parse_header:parse(<<"contact">>, Contact),
					{C#uri.domain, C#uri.port, C#uri.user}
			end,

			PAssetedId = proplists:get_value(<<"p-asserted-identity">>, Headers, <<"">>),
			PIdUser = case PAssetedId of
				<<"">> -> <<"">>;
				_ -> {<<"contact">>, [P | _] } = nksip_parse_header:parse(<<"contact">>, Contact), P#uri.user
			end,

			% P-RTP-Stat or X-RTP-Stat (vise versa of that from OpenSIPS)
			RtpStat = case proplists:get_value(<<"p-rtp-stat">>, Headers, <<"">>) of
				<<"">> ->
					case proplists:get_value(<<"x-rtp-stat">>, Headers, <<"">>) of
						<<"">> -> <<"">>;
						Something -> Something
					end;
				Something2 ->
					Something2
			end,

			{Auth, AuthUser} = case proplists:get_value(<<"proxy-authorization">>, Headers, <<"">>) of
				<<"">> ->
					case proplists:get_value(<<"authorization">>, Headers, <<"">>) of
						<<"">> -> {<<"">>, <<"">>};
						A -> {A, <<"">>} % FIXME no username for now
					end;
				PA ->
					{PA, <<"">>} % FIXME no username for now
			end,

			MkDate = fun() ->
				{{YYYY,MM,DD},{Hour,Min,Sec}} = erlang:localtime(),
				iolist_to_binary(io_lib:format("~4.4.0w-~2.2.0w-~2.2.0w ~2.2.0w:~2.2.0w:~2.2.0w", [YYYY, MM, DD, Hour,Min,Sec]))
			end,

			CallId = proplists:get_value(<<"call-id">>, Headers, <<"">>),

			Counter = ets:update_counter(hep_counter, id, 1),

			Json = [
				{id, iolist_to_binary(io_lib:format("~s-~16..0lb", [Prefix, Counter]))},
				{date, MkDate()},
				{micro_ts, fun({Mega, Secs, Micro}) -> Mega*1000*1000*1000*1000 + Secs * 1000 * 1000 + Micro end (Hep#hep.timestamp)},
				{method, Method},
				{reply_reason, Reason},
				{ruri, Uri},
				{ruri_user, RuriUser},
				{from_user, FromUser},
				{from_tag, FromTag},
				{to_user, ToUser},
				{to_tag, ToTag},
				{pid_user, PIdUser},
				{callid, CallId},
				{callid_aleg, <<"">>}, % FIXME X-CID, https://github.com/OpenSIPS/opensips/issues/459
				{via_1, proplists:get_value(<<"via">>, Headers, <<"">>)},
				{via_1_branch, proplists:get_value(<<"branch">>, Via#via.opts, <<"">>)},
				{cseq, proplists:get_value(<<"cseq">>, Headers, <<"">>)},
				{diversion, proplists:get_value(<<"diversion">>, Headers, <<"">>)},
				{reason, Reason},
				{content_type, proplists:get_value(<<"content-type">>, Headers, <<"">>)},
				{authorization, Auth},
				{auth_user, AuthUser},
				{user_agent, proplists:get_value(<<"user-agent">>, Headers, <<"">>)}, % FIXME server-agent as well
				{source_ip, << <<S>> || S <- inet_parse:ntoa(Hep#hep.src_ip) >>},
				{source_port, Hep#hep.src_port},
				{destination_ip, << <<S>> || S <- inet_parse:ntoa(Hep#hep.dst_ip) >>},
				{destination_port, Hep#hep.dst_port},
				{contact_ip, ContactIp},
				{contact_port, ContactPort},
				{contact_user, ContactUser},
				{originator_ip, <<"">>}, % FIXME X-OIP
				{originator_port, <<"0">>}, % FIXME X-OIP
				{proto, Hep#hep.protocol}, % https://github.com/OpenSIPS/opensips/blob/7903f2c/ip_addr.h#L52
				{family, Hep#hep.protocol_family}, % AF_INET (2),AF_INET6 (10)
				{rtp_stat, RtpStat},
				{type, SipType},
				{node, node()},
				{msg, Hep#hep.payload}
			],
			{ok,
				{
					CallId,
					[
						{content_type, <<"text/json">>},
						{content_encoding, <<"utf8">>}
					],
					iolist_to_binary(mochijson2:encode(Json))
				}
			};
		{error, _HepError, _Rest} ->
			{error, {hep_parsing_error, udp_exchange:truncate_bin(255, Packet)}}
	end.

format(_IpAddr, _Port, _RoutingKeySuffixes, _Body, #delivery{}, _Config) ->
	% Cannot send packets back
	ignore.
