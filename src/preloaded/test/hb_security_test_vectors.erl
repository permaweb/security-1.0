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

token_policy(Balances, TotalSupply, Opts) ->
    token_policy(Balances, TotalSupply, #{}, Opts).
token_policy(Balances, TotalSupply, Extra, Opts) ->
    {ok, BalanceTrie} =
        hb_ao:resolve(
            #{ <<"device">> => <<"trie@1.0">> },
            (canonical_balances(Balances))#{ <<"path">> => <<"set">> },
            Opts
        ),
    Extra#{
        <<"balances">> => BalanceTrie,
        <<"total-supply">> => TotalSupply
    }.

canonical_balances(Balances) ->
    maps:fold(
        fun(Account, Amount, Acc) ->
            Key = account_key(Account),
            Acc#{ Key => maps:get(Key, Acc, 0) + Amount }
        end,
        #{},
        Balances
    ).

account_key(Account) ->
    hb_util:to_lower(Account).

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

empty_set_authority_static_policy_rejected_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Security policy not configured.">>},
        validate(
            <<"set-authority">>,
            #{ <<"set-authority">> => [] },
            <<"alice">>,
            Opts
        )
    ).

empty_binary_set_authority_static_policy_rejected_vector_test() ->
    Opts = opts(),
    ?assertMatch(
        {error, _},
        validate(
            <<"set-authority">>,
            #{ <<"set-authority">> => <<>> },
            <<"alice">>,
            Opts
        )
    ).

set_authority_required_only_static_policy_allowed_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {ok, true},
        validate(
            <<"set-authority">>,
            #{ <<"set-authority-required">> => [<<"alice">>] },
            <<"alice">>,
            Opts
        )
    ),
    ?assertEqual(
        {error, <<"Required committers not present in message.">>},
        validate(
            <<"set-authority">>,
            #{ <<"set-authority-required">> => [<<"alice">>] },
            <<"bob">>,
            Opts
        )
    ).

set_authority_default_supply_owner_requires_token_state_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Balances not configured.">>},
        validate(<<"set-authority">>, #{}, <<"alice">>, Opts)
    ).

set_authority_default_supply_owner_allows_full_owner_vector_test() ->
    Opts = opts(),
    Owner = <<"alice">>,
    ?assertEqual(
        {ok, true},
        validate(
            <<"set-authority">>,
            token_policy(#{ Owner => 10 }, 10, Opts),
            Owner,
            Opts
        )
    ).

set_authority_default_supply_owner_rejects_non_owner_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Supply-threshold owner requirement not satisfied.">>},
        validate(
            <<"set-authority">>,
            token_policy(#{ <<"alice">> => 10 }, 10, Opts),
            <<"bob">>,
            Opts
        )
    ).

set_authority_default_supply_owner_rejects_split_supply_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Supply-threshold owner requirement not satisfied.">>},
        validate(
            <<"set-authority">>,
            token_policy(#{ <<"alice">> => 5, <<"bob">> => 5 }, 10, Opts),
            <<"alice">>,
            Opts
        )
    ).

set_authority_supply_threshold_bps_allows_half_owner_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {ok, true},
        validate(
            <<"set-authority">>,
            token_policy(
                #{ <<"alice">> => 5, <<"bob">> => 5 },
                10,
                #{
                    <<"set-authority-template">> => <<"supply-threshold-owner">>,
                    <<"set-authority-threshold-bps">> => 5000
                },
                Opts
            ),
            <<"alice">>,
            Opts
        )
    ).

set_authority_supply_owner_uses_canonical_account_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {ok, true},
        validate(
            <<"set-authority">>,
            token_policy(#{ <<"alice">> => 10 }, 10, Opts),
            <<"ALICE">>,
            Opts
        )
    ).

set_authority_static_policy_takes_precedence_vector_test() ->
    Opts = opts(),
    Admin = <<"admin">>,
    Owner = <<"owner">>,
    Policy =
        token_policy(
            #{ Owner => 10 },
            10,
            #{ <<"set-authority">> => Admin },
            Opts
        ),
    ?assertEqual({ok, true}, validate(<<"set-authority">>, Policy, Admin, Opts)),
    ?assertEqual(
        {error, <<"Too few acceptable committers present.">>},
        validate(<<"set-authority">>, Policy, Owner, Opts)
    ).

explicit_supply_owner_template_rejects_non_set_authority_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Supply-threshold owner template only supports set-authority.">>},
        validate(
            <<"authority">>,
            token_policy(
                #{ <<"alice">> => 10 },
                10,
                #{ <<"authority-template">> => <<"supply-threshold-owner">> },
                Opts
            ),
            <<"alice">>,
            Opts
        )
    ).

explicit_supply_owner_template_rejects_static_keys_vector_test() ->
    Opts = opts(),
    Authority = <<"alice">>,
    ?assertEqual(
        {error, <<"Ambiguous security policy configuration.">>},
        validate(
            <<"set-authority">>,
            token_policy(
                #{ Authority => 10 },
                10,
                #{
                    <<"set-authority-template">> => <<"supply-threshold-owner">>,
                    <<"set-authority">> => Authority
                },
                Opts
            ),
            Authority,
            Opts
        )
    ).

unknown_set_authority_template_rejected_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Unknown security template.">>},
        validate(
            <<"set-authority">>,
            token_policy(
                #{ <<"alice">> => 10 },
                10,
                #{ <<"set-authority-template">> => <<"unknown-template">> },
                Opts
            ),
            <<"alice">>,
            Opts
        )
    ).

set_authority_match_only_static_policy_rejected_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Security policy not configured.">>},
        validate(
            <<"set-authority">>,
            #{ <<"set-authority-match">> => 0 },
            <<"alice">>,
            Opts
        )
    ).

set_authority_supply_owner_rejects_path_candidate_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Address cannot contain path separators or whitespaces">>},
        validate(
            <<"set-authority">>,
            token_policy(#{ <<"alice">> => 10 }, 10, Opts),
            <<"alice/bob">>,
            Opts
        )
    ).

set_authority_supply_owner_rejects_invalid_threshold_vector_test() ->
    Opts = opts(),
    ?assertEqual(
        {error, <<"Threshold basis points out of range.">>},
        validate(
            <<"set-authority">>,
            token_policy(
                #{ <<"alice">> => 10 },
                10,
                #{
                    <<"set-authority-template">> => <<"supply-threshold-owner">>,
                    <<"set-authority-threshold-bps">> => 0
                },
                Opts
            ),
            <<"alice">>,
            Opts
        )
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
