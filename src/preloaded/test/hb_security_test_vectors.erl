%%% @doc Test vectors for the `security@1.0' preloaded package.
-module(hb_security_test_vectors).
-include_lib("eunit/include/eunit.hrl").
-include_lib("hb/include/hb.hrl").

opts() ->
    hb:init(),
    #{
        <<"load-remote-devices">> => false,
        <<"priv-wallet">> => ar_wallet:new(),
        <<"store">> => [hb_test_utils:test_store()]
    }.

base(Policy) ->
    Policy#{ <<"device">> => <<"security@1.0">> }.

validate(Key, Policy, From, Opts) ->
    hb_ao:resolve(
        base(Policy),
        #{
            <<"path">> => <<"validate">>,
            <<"key">> => Key,
            <<"from">> => From,
            <<"subject">> => #{}
        },
        Opts
    ).

duplicate_authority_match_rejected_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Too few acceptable committers present.">>},
        validate(
            <<"authority">>,
            #{
                <<"authority">> => [<<"alice">>, <<"bob">>],
                <<"authority-match">> => 2
            },
            [<<"alice">>, <<"alice">>],
            Opts
        )
    ).

comma_separated_authority_config_supported_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {ok, true},
        validate(
            <<"authority">>,
            #{
                <<"authority">> => <<"\"alice\",\"bob\"">>
            },
            [<<"alice">>, <<"bob">>],
            Opts
        )
    ).

validate_route_uses_explicit_from_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {ok, true},
        validate(
            <<"set-authority">>,
            #{
                <<"set-authority">> => [<<"alice">>],
                <<"set-authority-required">> => [<<"alice">>]
            },
            <<"alice">>,
            Opts
        )
    ).

raw_set_authority_static_policy_allows_exact_from_vector_test() ->
    Opts = opts(),
    Authority = <<1:256>>,
    ?assertEqual(
        {ok, true},
        validate(
            <<"set-authority">>,
            #{ <<"set-authority">> => Authority },
            Authority,
            Opts
        )
    ).

raw_set_authority_static_policy_rejects_non_matching_from_vector_test() ->
    Opts = opts(),
    Authority = <<1:256>>,
    Other = <<2:256>>,
    ?assertEqual(
        {error, <<"Too few acceptable committers present.">>},
        validate(
            <<"set-authority">>,
            #{ <<"set-authority">> => Authority },
            Other,
            Opts
        )
    ).

set_authority_requires_policy_even_in_dev_mode_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Security policy not configured.">>},
        validate(<<"set-authority">>, #{}, <<"alice">>, Opts)
    ).

prod_mode_requires_explicit_policy_vector_test() ->
    Opts = (opts())#{ dev_security_mode => prod },
    ?assertEqual(
        {error, <<"Security policy not configured.">>},
        validate(<<"authority">>, #{}, [<<"alice">>], Opts)
    ).

prod_mode_allows_explicit_single_signer_policy_vector_test() ->
    Opts = (opts())#{ dev_security_mode => prod },
    ?assertEqual(
        {ok, true},
        validate(
            <<"authority">>,
            #{
                <<"authority">> => <<"alice">>
            },
            [<<"alice">>],
            Opts
        )
    ).
