%%  This Source Code Form is subject to the terms of the Mozilla Public
%%  License, v. 2.0. If a copy of the MPL was not distributed with this
%%  file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%
%% udp-exchange HEP module
%% Contributed by Peter Lemenkov.
%%

-module(udp_exchange_hep_packet).

-include_lib("rabbit_common/include/rabbit.hrl").
-include_lib("rabbit_common/include/rabbit_framing.hrl").

-include_lib("hep/include/hep.hrl").
-include_lib("nksip/include/nksip.hrl").

-export([configure/1, parse/4, format/6]).

-record(hep_params, {prefix, node}).

configure(#exchange{}) ->
	{A,B,C} = os:timestamp(),
	random:seed(A,B,C),
	Prefix = << << (random:uniform(26) + 96):8 >> || _ <- lists:seq(0,15) >>,
	#hep_params{prefix = Prefix, node = atom_to_binary(node(), utf8)}.

parse(_IpAddr, _Port, Packet, #hep_params{prefix = Prefix, node = Node}) ->
	case hep_multi_decoder:decode(Packet) of
		{ok, Hep} ->
			{CallId, JsonSip} = case nksip_parse_sipmsg:parse(Hep#hep.payload) of
				{ok, Class, Headers, _Rest} -> parse_sip(Class, Headers);
				_ ->
					{<<"">>,  [
						{method, <<"">>},
						{reply_reason, <<"">>},
						{ruri, <<"">>},
						{ruri_user, <<"">>},
						{from_user, <<"">>},
						{from_tag, <<"">>},
						{to_user, <<"">>},
						{to_tag, <<"">>},
						{pid_user, <<"">>},
						{callid, <<"">>},
						{callid_aleg, <<"">>},
						{via_1, <<"">>},
						{via_1_branch, <<"">>},
						{cseq, <<"">>},
						{diversion, <<"">>},
						{reason, <<"">>},
						{content_type, <<"">>},
						{authorization, <<"">>},
						{auth_user, <<"">>},
						{user_agent, <<"">>},
						{contact_ip, <<"">>},
						{contact_port, <<"">>},
						{contact_user, <<"">>},
						{originator_ip, <<"">>},
						{originator_port, <<"">>},
						{rtp_stat, <<"">>},
						{type, <<"">>}
				]}
			end,


			{{YYYY,MM,DD},{Hour,Min,Sec}} = calendar:now_to_local_time(Hep#hep.timestamp),
			{Mega, Secs, Micro} = Hep#hep.timestamp,
			Date = 	iolist_to_binary(io_lib:format("~4.4.0w-~2.2.0w-~2.2.0w ~2.2.0w:~2.2.0w:~2.2.0w", [YYYY, MM, DD, Hour,Min,Sec])),
			MicroTs = Mega*1000*1000*1000*1000 + Secs * 1000 * 1000 + Micro,

			JsonDate = [
				{date, Date},
				{micro_ts, MicroTs},
				{source_ip, << <<S>> || S <- inet_parse:ntoa(Hep#hep.src_ip) >>},
				{source_port, Hep#hep.src_port},
				{destination_ip, << <<S>> || S <- inet_parse:ntoa(Hep#hep.dst_ip) >>},
				{destination_port, Hep#hep.dst_port},
				{proto, Hep#hep.protocol}, % https://github.com/OpenSIPS/opensips/blob/7903f2c/ip_addr.h#L52
				{family, Hep#hep.protocol_family}, % AF_INET (2),AF_INET6 (10)
				{node, Node},
				{msg, Hep#hep.payload}
			],

			{ok,
				{
					CallId,
					#'P_basic'{content_type = <<"text/json">>, content_encoding = <<"utf8">>},
					iolist_to_binary(mochijson2:encode(lists:append([JsonDate, JsonSip])))
				}
			};
		{error, _HepError, _Rest} ->
			{error, {hep_parsing_error, udp_exchange:truncate_bin(255, Packet)}}
	end.

format(_IpAddr, _Port, _RoutingKeySuffixes, _Body, #delivery{}, _Config) ->
	% Cannot send packets back
	ignore.

%%
%% Private API
%%

parse_sip(Class, Headers) ->
	% SIP_REQUEST 1, SIP_REPLY 2, SIP_INVALID 0
	{SipType, _Code, Reason, Method, Uri} = case Class of
		{req, M0, U0} -> {1, <<"">>, <<"">>, M0, U0};
		{resp, C0, R0} -> {2, list_to_binary(C0), R0, list_to_binary(C0), <<"">>}
	end,

	RuriUser = case Uri of
		<<"">> -> <<"">>;
		_ ->
			case catch nksip_parse_header:parse(<<"from">>, Uri) of
				{_, {R, _}} -> R#uri.user;
				{invalid, <<"from">>} -> <<"invalid_ruri">>
			end
	end,

	F = fun(N) ->
		case proplists:get_value(N, Headers) of
			undefined -> {<<"">>, <<"">>};
			V ->
				case catch nksip_parse_header:parse(N, V) of
					{N, {U, T}} ->
						{U#uri.user, T};
					{invalid, N} ->
						{iolist_to_binary([<<"invalid_">>, N]), iolist_to_binary([<<"invalid_">>, N])}
				end
		end
	end,

	{FromUser, FromTag} = F(<<"from">>),
	{ToUser, ToTag} = F(<<"to">>),

	Vias = proplists:get_value(<<"via">>, Headers, <<"">>),
	Via = case Vias of
		<<"">> -> <<"">>;
		_ ->
			case catch nksip_parse_header:parse(<<"via">>, Vias) of
				{_, [V | _ ]} -> V;
				_ -> <<"invalid_via">>
			end
	end,

	Contact = proplists:get_value(<<"contact">>, Headers, <<"">>),
	{ContactIp, ContactPort, ContactUser} = case Contact of
		<<"">> -> {<<"">>, <<"0">>, <<"">>};
		_ ->
			case catch nksip_parse_header:parse(<<"contact">>, Contact) of
				{<<"contact">>, [C | _] } -> {C#uri.domain, C#uri.port, C#uri.user};
				_ -> {<<"invalid_contact">>, <<"0">>, <<"invalid_contact">>}
			end
	end,

	PAssetedId = proplists:get_value(<<"p-asserted-identity">>, Headers, <<"">>),
	PIdUser = case PAssetedId of
		<<"">> -> <<"">>;
		_ ->
			case catch nksip_parse_header:parse(<<"contact">>, Contact) of
				{<<"contact">>, [P | _] } -> P#uri.user;
				_ -> <<"invalid_p_asserted_identity">>
			end
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

	CallId = proplists:get_value(<<"call-id">>, Headers, <<"">>),

	{CallId, [
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
		{contact_ip, ContactIp},
		{contact_port, ContactPort},
		{contact_user, ContactUser},
		{originator_ip, <<"">>}, % FIXME X-OIP
		{originator_port, <<"0">>}, % FIXME X-OIP
		{rtp_stat, RtpStat},
		{type, SipType}
	]}.