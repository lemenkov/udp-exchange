%%  This Source Code Form is subject to the terms of the Mozilla Public
%%  License, v. 2.0. If a copy of the MPL was not distributed with this
%%  file, You can obtain one at http://mozilla.org/MPL/2.0/.
%%
-module(udp_exchange_relay).

-include_lib("rabbit_common/include/rabbit.hrl").
-include("udp_exchange.hrl").

-behaviour(gen_server).

-export([start_link/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         code_change/3, terminate/2]).

-record(state, {params, socket}).

start_link(Params = #params{process_name = ProcessName}) ->
    gen_server:start_link({local, ProcessName}, ?MODULE, [Params], []).

%%----------------------------------------------------------------------------

init([#params{ip_addr = IpAddr, port = Port} = Params]) ->
    Opts = [{recbuf, 65536}, binary],
    {ok, Socket} = case IpAddr of
                       {0,0,0,0} -> gen_udp:open(Port, Opts);
                       _ -> gen_udp:open(Port, [{ip, IpAddr} | Opts])
                   end,
    {ok, #state{params = Params, socket = Socket}}.

handle_call(Msg, _From, State) ->
    {stop, {unhandled_call, Msg}, State}.

handle_cast(Msg, State) ->
    {stop, {unhandled_cast, Msg}, State}.

handle_info(#delivery{}, State) ->
    {noreply, State};

handle_info({udp, _Socket, SourceIp, SourcePort, Packet},
            State = #state{params = Params}) ->
    {message_queue_len, MessageQueueLen} = process_info(self(), message_queue_len),
    (MessageQueueLen < 255) andalso begin
        case udp_delivery(SourceIp, SourcePort, Packet, Params) of
            ignore ->
                ok;
            {ok, Delivery} ->
                ok = udp_exchange:deliver(Params#params.exchange_def, Delivery)
        end
    end,
    {noreply, State};

handle_info(Msg, State) ->
    {stop, {unhandled_info, Msg}, State}.

terminate(_Reason, #state{socket = Socket}) ->
    ok = gen_udp:close(Socket),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%----------------------------------------------------------------------------

udp_delivery(IpAddr,
             Port,
             Packet,
             #params{exchange_def = #exchange{name = XName},
                     packet_module = PacketModule,
                     packet_config = PacketConfig}) ->
    case PacketModule:parse(IpAddr, Port, Packet, PacketConfig) of
        {ok, {RoutingKeySuffix, Properties, Body}} ->
            IpStr = list_to_binary(inet_parse:ntoa(IpAddr)),
            RoutingKey = udp_exchange:truncate_bin(
                           255, list_to_binary(["ipv4",
                                                ".", IpStr,
                                                ".", integer_to_list(Port),
                                                ".", RoutingKeySuffix])),
            {ok, rabbit_basic:delivery(false, %% mandatory?
                                       false, %% should confirm message?
                                       rabbit_basic:message(XName, RoutingKey, Properties, Body),
                                       undefined)};
        ignore ->
            ignore;
        {error, Error} ->
            error_logger:error_report({?MODULE, PacketModule, parse, Error}),
            ignore
    end.
