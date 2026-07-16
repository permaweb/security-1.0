%%% @doc Security parameter enforcement for AO `~process@1.0' devices. Calling
%%% `compute' upon this device results in a modified version of the `Request'
%%% being returned, containing security-normalized keys (`from', etc). In the
%%% event that the request does not pass the security requirements of the 
%%% base process state a `{skip, State}' tuple is returned. Upon receipt, the
%%% caller is expected to disregard the request and return the orginal `Base'
%%% for the interaction in an unmodified form.
-module(dev_security).
-include_lib("hb/include/hb.hrl").
-implements(<<"security@1.0">>).
-device_libraries([lib_token]).
-define(MAX_EXACT_COMMITMENT_CANDIDATES, 12).
%%% Device API.
-export([info/0, compute/3, validate/3]).
%%% Public helpers.
-export([validate_address/2]).

%% @doc Return the public security device API.
info() ->
    #{
        exports => [<<"compute">>, <<"validate">>]
    }.

%% @doc Compute the security-normalized request.
compute(Base, Req, Opts) ->
    ?event(security_debug, {compute_called, {base, Base}, {req, Req}}, Opts),
    maybe
        {ok, HydratedReq} ?= hydrate_assignment_body(Req, Opts),
        {ok, SecureReq1} ?= validate_assignment(Base, HydratedReq, Opts),
        {ok, _SecureReq2} ?= validate_authority(Base, SecureReq1, Opts)
    else
        {error, Reason} ->
            ?event(
                security_error,
                {security_error,
                    {slot, hb_maps:get(<<"slot">>, Req, no_slot, Opts)},
                    {reason, Reason}
                },
                Opts
            ),
            {skip, Reason}
    end.

%% @doc Restore a cache-linked body's commitment set before verifying the
%% scheduler's commitment over the Assignment. A raw map update is intentional:
%% `hb_ao:set' would invalidate the outer commitment we are reconstructing.
hydrate_assignment_body(Assignment, Opts) when is_map(Assignment) ->
    BodyTargetID = assignment_body_target_id(Assignment, Opts),
    case hb_ao:get(<<"body">>, Assignment, not_found, Opts) of
        Body when is_map(Body) ->
            case hydrate_subject(Body, BodyTargetID, Opts) of
                {ok, HydratedBody} ->
                    {ok, Assignment#{ <<"body">> => HydratedBody }};
                {error, _} = Error ->
                    Error
            end;
        _ ->
            {error, <<"Security subject must be a message.">>}
    end;
hydrate_assignment_body(_Assignment, _Opts) ->
    {error, <<"Security subject must be a message.">>}.

%% @doc Validate a caller-controlled security intent through the device API.
%% Expected request keys:
%% - `key`: the base security policy prefix to validate, such as
%%   `set-authority`.
%% - `from`: optional identity or identities to validate. If omitted, the
%%   subject message signers are used.
%% - `subject`: optional message used for signer extraction and event context.
validate(Base, Req, Opts) ->
    maybe
        Key = hb_ao:get(<<"key">>, Req, not_found, Opts),
        true ?= (Key =/= not_found) orelse {error, <<"Security key not found.">>},
        SubjectMsg = hb_ao:get(<<"subject">>, Req, Req, Opts),
        Res =
            case hb_ao:get(<<"from">>, Req, not_found, Opts) of
                not_found -> validate(Key, Base, SubjectMsg, Opts);
                From -> validate(Key, Base, SubjectMsg, From, Opts)
            end,
        true ?= Res,
        {ok, true}
    else
        {error, Reason} -> {error, Reason}
    end.

%% @doc Validate that an assignment is trusted based on scheduler constraints.
validate_assignment(Base, Assignment, Opts) ->
    maybe
        {ok, Signers} ?= verified_signers(Assignment, Opts),
        true ?= validate(<<"scheduler">>, Base, Assignment, Signers, Opts),
        {ok, Assignment}
    else
        {error, Reason} -> {error, Reason}
    end.

%% @doc Validate that a request has proper authority, adding a `from' key to the
%% assigned message such that downstream callers can refer to a verified sender
%% (for replies, etc) -- whether an end-user wallet or another process.
validate_authority(Base, Assignment, Opts) ->
    Msg = hb_ao:get(<<"body">>, Assignment, undefined, Opts),
    maybe
        {ok, Signers} ?= verified_signers(Msg, Opts),
        case hb_ao:get(<<"from-process">>, Msg, undefined, Opts) of
            undefined ->
                {
                    ok,
                    hb_ao:set(
                        Assignment,
                        <<"body/from">>,
                        maybe_single(Signers, Opts),
                        Opts
                    )
                };
            Sender ->
                maybe
                    true ?= (length(Signers) =:= 1) orelse
                        {error, <<"Delegated messages require exactly one signer.">>},
                    true ?= validate(<<"authority">>, Base, Msg, Signers, Opts),
                    true ?= validate_authority_action(Base, Msg, Opts),
                    {
                        ok,
                        hb_ao:set(
                            Assignment,
                            <<"body/from">>,
                            Sender,
                            Opts
                        )
                    }
                end
        end
    end.

%% @doc Restrict process-delegated identities to explicitly configured actions.
%% Wallet-signed messages do not carry `from-process' and do not enter this path.
validate_authority_action(Base, Msg, Opts) ->
    try
        Action = hb_ao:get(<<"action">>, Msg, not_found, Opts),
        Allowed = hb_ao:get(<<"authority-actions">>, Base, [], Opts),
        Valid =
            is_binary(Action) andalso byte_size(Action) > 0 andalso
                is_list(Allowed) andalso Allowed =/= [] andalso
                lists:all(
                    fun(Item) -> is_binary(Item) andalso byte_size(Item) > 0 end,
                    Allowed
                ),
        case Valid andalso lists:member(
            hb_util:to_lower(Action),
            [hb_util:to_lower(Item) || Item <- Allowed]
        ) of
            true -> true;
            false -> {error, <<"Delegated action not allowed.">>}
        end
    catch
        _:_ -> {error, <<"Delegated action not allowed.">>}
    end.

%% @doc If a message purporting to be from a process satisfies the compute
%% authority constraints, return true, otherwise return false.
validate(Key, Base, SubjectMsg, Opts) ->
    validate(Key, Base, SubjectMsg, hb_message:signers(SubjectMsg, Opts), Opts).
validate(Key, Base, SubjectMsg, RawFrom, Opts) ->
    Template = security_template(Key, Base, Opts),
    validate_with_template(Template, Key, Base, SubjectMsg, RawFrom, Opts).

%% @doc Return only signer identities whose commitments verify against the
%% subject. Signer metadata alone is not authentication and an empty signer set
%% must never satisfy a security policy.
verified_signers(SubjectMsg, Opts) when is_map(SubjectMsg) ->
    try
        Signers = lists:uniq(hb_message:signers(SubjectMsg, Opts)),
        case Signers of
            [] ->
                {error, <<"Security subject has no signers.">>};
            _ ->
                case hb_message:verify(SubjectMsg, Signers, Opts) of
                    true -> {ok, Signers};
                    false ->
                        {error, <<"Security subject signature verification failed.">>}
                end
        end
    catch
        _:_ -> {error, <<"Security subject signature verification failed.">>}
    end;
verified_signers(_SubjectMsg, _Opts) ->
    {error, <<"Security subject must be a message.">>}.

%% @doc Ensure an Assignment body has the exact signer commitments needed for
%% security validation.
%%
%% Scheduler-loaded Assignment bodies can arrive as unsigned content plus a link
%% target that identifies the signed body the scheduler committed to. If the body
%% already contains signer commitments, keep it unchanged. If it does not, hydrate
%% only the commitment set for `BodyTargetID'. This is deliberately narrower than
%% `hb_cache:read_all_commitments/2', which would load every cached commitment for
%% the same unsigned body and could change the signer set of an older Assignment.
hydrate_subject(SubjectMsg, BodyTargetID, Opts) ->
    try
        case hb_message:signers(SubjectMsg, Opts) of
            [] -> hydrate_exact_subject(SubjectMsg, BodyTargetID, Opts);
            _ -> {ok, SubjectMsg}
        end
    catch
        _:_ -> {error, <<"Security subject signature verification failed.">>}
    end.

%% @doc Attach the exact commitments for `BodyTargetID' to an unsigned subject.
%% Without a body target from the Assignment there is no signed identity to
%% recover, so failing closed is safer than falling back to all cached signatures.
hydrate_exact_subject(_SubjectMsg, not_found, _Opts) ->
    {error, <<"Security subject commitment target not found.">>};
hydrate_exact_subject(SubjectMsg, BodyTargetID, Opts) ->
    case exact_commitments(SubjectMsg, BodyTargetID, Opts) of
        {ok, Commitments} ->
            {ok, SubjectMsg#{ <<"commitments">> => Commitments }};
        {error, _} = Error ->
            Error
    end.

%% @doc Find the signed body target that the Assignment points at.
%% Prefer link metadata already present on the Assignment. If the body has been
%% materialized and the link metadata was lost, reread the raw Assignment by its
%% signed/all ID and inspect that cached raw form for the original body link.
assignment_body_target_id(Assignment, Opts) ->
    case body_target_id(Assignment, Opts) of
        {ok, BodyTargetID} ->
            BodyTargetID;
        not_found ->
            assignment_body_target_id_from_cache(Assignment, Opts)
    end.

%% @doc Recover body link metadata by rereading the raw Assignment from cache.
%% This fallback exists because normal reads may materialize `body' as a map,
%% while the raw cached Assignment can still expose `body+link' or lazy link
%% structure that identifies the exact body commitment target.
assignment_body_target_id_from_cache(Assignment, Opts) ->
    try
        AssignmentID =
            hb_message:id(Assignment, all, Opts#{ <<"linkify-mode">> => discard }),
        case hb_cache:read(AssignmentID, Opts#{ cache_read_mode => raw }) of
            {ok, RawAssignment} ->
                case body_target_id(RawAssignment, Opts) of
                    {ok, BodyTargetID} -> BodyTargetID;
                    not_found -> not_found
                end;
            _ ->
                not_found
        end
    catch
        _:_ -> not_found
    end.

%% @doc Extract the Assignment body's target ID from inline link metadata.
%% The target ID may appear as a `body+link' sidecar, as a lazy `{link, ...}'
%% tuple, or as a direct binary body value in raw cache-read mode.
body_target_id(Assignment, Opts) ->
    case maps:get(<<"body+link">>, Assignment, not_found) of
        BodyTargetID when is_binary(BodyTargetID) ->
            {ok, BodyTargetID};
        _ ->
            case maps:get(<<"body">>, Assignment, not_found) of
                {link, ID, LinkOpts} ->
                    link_target_id(ID, LinkOpts, Opts);
                BodyTargetID when is_binary(BodyTargetID) ->
                    {ok, BodyTargetID};
                _ ->
                    not_found
            end
    end.

%% @doc Resolve a body link to the binary target ID it names.
%% Lazy links may point to another link, so this follows that chain until it
%% reaches the real target. Non-lazy binary links already carry the target ID.
link_target_id(ID, #{ <<"type">> := <<"link">>, <<"lazy">> := true } = LinkOpts, Opts) ->
    case hb_cache:read(ID, hb_util:deep_merge(Opts, LinkOpts, Opts)) of
        {ok, BodyTargetID} when is_binary(BodyTargetID) ->
            {ok, BodyTargetID};
        {ok, {link, NextID, NextOpts}} ->
            link_target_id(NextID, NextOpts, Opts);
        _ ->
            not_found
    end;
link_target_id(ID, #{ <<"type">> := <<"link">> }, _Opts) when is_binary(ID) ->
    {ok, ID};
link_target_id(ID, _LinkOpts, _Opts) when is_binary(ID) ->
    {ok, ID};
link_target_id(_ID, _LinkOpts, _Opts) ->
    not_found.

%% @doc Read only the commitments that recreate `BodyTargetID'.
%% Commitments are stored under the unsigned body root, but the Assignment points
%% at a signed/all body target. This helper bridges those identities: locate the
%% unsigned commitment group, choose the commitment IDs that correspond to the
%% target, then read exactly those commitments.
exact_commitments(SubjectMsg, BodyTargetID, Opts) ->
    LocalOpts = hb_store:scope(Opts, local),
    UncommittedID = commitment_root_id(SubjectMsg, BodyTargetID, Opts),
    CommitmentsPath = hb_path:to_binary([UncommittedID, <<"commitments">>]),
    case exact_commitment_ids(
        CommitmentsPath,
        BodyTargetID,
        UncommittedID,
        LocalOpts,
        Opts
    ) of
        {ok, CommitmentIDs} ->
            read_commitments(CommitmentsPath, CommitmentIDs, LocalOpts, Opts);
        {error, _} = Error ->
            Error
    end.

%% @doc Determine the unsigned root where the target body's commitments live.
%% If the target ID can be read directly, derive the unsigned ID from that cached
%% target. Otherwise fall back to the subject map we already have.
commitment_root_id(SubjectMsg, BodyTargetID, Opts) ->
    case hb_cache:read(BodyTargetID, Opts#{ cache_read_mode => raw }) of
        {ok, TargetSubject} when is_map(TargetSubject) ->
            hb_message:id(
                TargetSubject,
                none,
                Opts#{ <<"linkify-mode">> => discard }
            );
        _ ->
            hb_message:id(
                SubjectMsg,
                none,
                Opts#{ <<"linkify-mode">> => discard }
            )
    end.

%% @doc List candidate commitment IDs and choose the exact subset for the target.
%% The commitment group can contain signatures from older or newer writes of the
%% same unsigned body. We keep signer-bearing commitments separate from automatic
%% non-signer commitments so signed/all matching is based on actual authorities.
exact_commitment_ids(CommitmentsPath, BodyTargetID, RootID, LocalOpts, Opts) ->
    case hb_store:list(CommitmentsPath, LocalOpts) of
        {ok, RawCommitmentIDs} ->
            CommitmentIDs =
                lists:sort([
                    hb_util:bin(commitment_child_name(RawCommitmentID))
                ||
                    RawCommitmentID <- RawCommitmentIDs
                ]),
            SignerCommitmentIDs =
                signer_commitment_ids(
                    CommitmentsPath,
                    CommitmentIDs,
                    LocalOpts,
                    Opts
                ),
            find_commitment_ids(
                BodyTargetID,
                RootID,
                CommitmentIDs,
                SignerCommitmentIDs,
                LocalOpts,
                Opts
            );
        _ ->
            {error, <<"Security subject commitments not found.">>}
    end.

%% @doc Filter commitment IDs down to commitments that carry a real signer.
%% Automatic commitments, such as the constant AO HMAC commitment, are useful
%% cache artifacts but are not security authorities.
signer_commitment_ids(CommitmentsPath, CommitmentIDs, LocalOpts, Opts) ->
    [
        CommitmentID
    ||
        CommitmentID <- CommitmentIDs,
        signer_commitment(CommitmentsPath, CommitmentID, LocalOpts, Opts)
    ].

%% @doc Return true when a stored commitment has a `committer' field.
signer_commitment(CommitmentsPath, CommitmentID, LocalOpts, Opts) ->
    CommitmentPath = hb_path:to_binary([CommitmentsPath, CommitmentID]),
    case hb_cache:read(CommitmentPath, LocalOpts) of
        {ok, Commitment} ->
            LoadedCommitment =
                hb_cache:ensure_all_loaded(
                    Commitment,
                    Opts#{ <<"commitment">> => true }
                ),
            is_binary(
                hb_maps:get(<<"committer">>, LoadedCommitment, not_found, Opts)
            );
        _ ->
            false
    end.

%% @doc Select the commitment IDs that correspond to the Assignment body target.
%% First try to match the target ID by accumulating signer commitment IDs. If that
%% cannot be proven, fall back to checking which accumulated signer subset is
%% actually linked in cache to the same unsigned root.
find_commitment_ids(
    BodyTargetID,
    RootID,
    CommitmentIDs,
    SignerCommitmentIDs,
    LocalOpts,
    Opts
) ->
    case length(CommitmentIDs) =< ?MAX_EXACT_COMMITMENT_CANDIDATES of
        true ->
            case find_aggregate_commitment_ids(BodyTargetID, SignerCommitmentIDs) of
                {ok, _} = Ok ->
                    Ok;
                {error, _} = Error ->
                    find_written_aggregate_commitment_ids(
                        RootID,
                        SignerCommitmentIDs,
                        LocalOpts,
                        Opts
                    )
            end;
        false ->
            {error, <<"Too many cached commitments for exact security hydration.">>}
    end.

%% @doc Find a signer subset whose accumulated ID equals `BodyTargetID'.
%% This handles the normal case where the body target is the signed/all ID for
%% one or more signer commitments.
find_aggregate_commitment_ids(_BodyTargetID, []) ->
    {error, <<"Exact security commitment set not found.">>};
find_aggregate_commitment_ids(BodyTargetID, CommitmentIDs) ->
    find_aggregate_commitment_ids(BodyTargetID, CommitmentIDs, 1, length(CommitmentIDs)).
find_aggregate_commitment_ids(_BodyTargetID, _CommitmentIDs, Size, Max)
        when Size > Max ->
    {error, <<"Exact security commitment set not found.">>};
find_aggregate_commitment_ids(BodyTargetID, CommitmentIDs, Size, Max) ->
    case find_commitment_combination(BodyTargetID, Size, CommitmentIDs, []) of
        {ok, Match} ->
            {ok, Match};
        not_found ->
            find_aggregate_commitment_ids(BodyTargetID, CommitmentIDs, Size + 1, Max)
    end.

%% @doc Find a signer subset whose accumulated ID was written as an alt-ID link.
%% This is a compatibility fallback for cases where the body target itself is not
%% exactly the accumulated signer ID but the accumulated ID resolves to the same
%% unsigned body root in cache.
find_written_aggregate_commitment_ids(_RootID, [], _LocalOpts, _Opts) ->
    {error, <<"Exact security commitment set not found.">>};
find_written_aggregate_commitment_ids(RootID, SignerCommitmentIDs, LocalOpts, Opts) ->
    Max = length(SignerCommitmentIDs),
    case find_written_aggregate_commitment_ids(
        RootID,
        SignerCommitmentIDs,
        2,
        Max,
        LocalOpts,
        Opts
    ) of
        {ok, _} = Ok ->
            Ok;
        {error, _} ->
            find_written_aggregate_commitment_ids(
                RootID,
                SignerCommitmentIDs,
                1,
                1,
                LocalOpts,
                Opts
            )
    end.
find_written_aggregate_commitment_ids(
    _RootID,
    _SignerCommitmentIDs,
    Size,
    Max,
    _LocalOpts,
    _Opts
) when Size > Max ->
    {error, <<"Exact security commitment set not found.">>};
find_written_aggregate_commitment_ids(
    RootID,
    SignerCommitmentIDs,
    Size,
    Max,
    LocalOpts,
    Opts
) ->
    case find_written_commitment_combination(
        RootID,
        Size,
        SignerCommitmentIDs,
        [],
        LocalOpts,
        Opts
    ) of
        {ok, Match} ->
            {ok, Match};
        not_found ->
            find_written_aggregate_commitment_ids(
                RootID,
                SignerCommitmentIDs,
                Size + 1,
                Max,
                LocalOpts,
                Opts
            )
    end.

%% @doc Search combinations until one accumulates to `BodyTargetID'.
find_commitment_combination(BodyTargetID, 0, _CommitmentIDs, Acc) ->
    CommitmentIDs = lists:sort(Acc),
    case aggregate_commitment_id(CommitmentIDs) of
        BodyTargetID -> {ok, CommitmentIDs};
        _ -> not_found
    end;
find_commitment_combination(_BodyTargetID, _Size, [], _Acc) ->
    not_found;
find_commitment_combination(BodyTargetID, Size, [CommitmentID | Rest], Acc)
        when Size > 0 ->
    case find_commitment_combination(BodyTargetID, Size - 1, Rest, [CommitmentID | Acc]) of
        {ok, _} = Ok -> Ok;
        not_found -> find_commitment_combination(BodyTargetID, Size, Rest, Acc)
    end.

%% @doc Search combinations until one resolves back to the unsigned root.
find_written_commitment_combination(
    RootID,
    0,
    _CommitmentIDs,
    Acc,
    LocalOpts,
    Opts
) ->
    CommitmentIDs = lists:sort(Acc),
    AggregateID = aggregate_commitment_id(CommitmentIDs),
    case aggregate_resolves_to_root(AggregateID, RootID, LocalOpts, Opts) of
        true -> {ok, CommitmentIDs};
        false -> not_found
    end;
find_written_commitment_combination(
    _RootID,
    _Size,
    [],
    _Acc,
    _LocalOpts,
    _Opts
) ->
    not_found;
find_written_commitment_combination(
    RootID,
    Size,
    [CommitmentID | Rest],
    Acc,
    LocalOpts,
    Opts
) when Size > 0 ->
    case find_written_commitment_combination(
        RootID,
        Size - 1,
        Rest,
        [CommitmentID | Acc],
        LocalOpts,
        Opts
    ) of
        {ok, _} = Ok ->
            Ok;
        not_found ->
            find_written_commitment_combination(
                RootID,
                Size,
                Rest,
                Acc,
                LocalOpts,
                Opts
            )
    end.

%% @doc Return true when a written accumulated ID links to the expected root.
aggregate_resolves_to_root(AggregateID, RootID, LocalOpts, Opts) ->
    case hb_cache:read(AggregateID, LocalOpts#{ cache_read_mode => raw }) of
        {ok, TargetSubject} when is_map(TargetSubject) ->
            hb_message:id(
                TargetSubject,
                none,
                Opts#{ <<"linkify-mode">> => discard }
            ) =:= RootID;
        _ ->
            false
    end.

%% @doc Derive the combined signed/all ID from a set of commitment IDs.
aggregate_commitment_id(CommitmentIDs) ->
    hb_util:human_id(
        hb_crypto:accumulate(
            [hb_util:native_id(CommitmentID) || CommitmentID <- lists:sort(CommitmentIDs)]
        )
    ).

%% @doc Load the selected commitments from the unsigned commitment group.
%% Unlike `read_all_commitments/2', this reads only the IDs selected by
%% `exact_commitment_ids/5', preserving the Assignment's intended signer set.
read_commitments(CommitmentsPath, CommitmentIDs, LocalOpts, Opts) ->
    read_commitments(CommitmentsPath, CommitmentIDs, LocalOpts, Opts, []).
read_commitments(_CommitmentsPath, [], _LocalOpts, _Opts, Acc) ->
    {ok, maps:from_list(lists:reverse(Acc))};
read_commitments(CommitmentsPath, [CommitmentID | Rest], LocalOpts, Opts, Acc) ->
    CommitmentPath = hb_path:to_binary([CommitmentsPath, CommitmentID]),
    case hb_cache:read(CommitmentPath, LocalOpts) of
        {ok, Commitment} ->
            LoadedCommitment =
                hb_cache:ensure_all_loaded(
                    Commitment,
                    Opts#{ <<"commitment">> => true }
                ),
            read_commitments(
                CommitmentsPath,
                Rest,
                LocalOpts,
                Opts,
                [{CommitmentID, LoadedCommitment} | Acc]
            );
        _ ->
            {error, <<"Security subject commitment not found.">>}
    end.

%% @doc Normalize store-list entries to the actual child path name.
commitment_child_name({Subpath, _Value}) -> Subpath;
commitment_child_name(Subpath) -> Subpath.

validate_with_template(<<"static-signer-set">>, Key, Base, SubjectMsg, RawFrom, Opts) ->
    maybe
        true ?=
            case requires_static_policy(Key, Opts) of
                true ->
                    has_static_signer_policy(Key, Base, Opts)
                        orelse {error, <<"Security policy not configured.">>};
                false ->
                    true
            end,
        %% Dedup identities so duplicate committers cannot satisfy min-N thresholds.
        From = lists:uniq(as_list(RawFrom, Opts)),
        ValidOrError = as_signer_config_list(hb_ao:get(Key, Base, [], Opts), Opts),
        true ?= is_list(ValidOrError) orelse ValidOrError,
        Valid = lists:uniq(ValidOrError),
        RequiredListOrError =
            as_signer_config_list(
                hb_ao:get(<<Key/binary, "-required">>, Base, [], Opts),
                Opts
            ),
        true ?= is_list(RequiredListOrError) orelse RequiredListOrError,
        RequiredList = lists:uniq(RequiredListOrError),
        true ?= valid_static_signer_policy(Key, Base, Valid, RequiredList, Opts),
        DefaultThresholdN = case length(Valid) of
            0 -> 0;
            _ -> 1
        end,
        
        MatchRaw = hb_ao:get(<<Key/binary, "-match">>, Base, not_found, Opts),
        MatchOrError = safe_match(MatchRaw, DefaultThresholdN, length(Valid)),
        true ?= is_integer(MatchOrError) orelse MatchOrError,
        Match = MatchOrError,
        ?event(security_debug,
            {validate_authority,
                {subject_ids, From},
                {intent, compute},
                {valid_options, Valid},
                {required, RequiredList},
                {base, Base},
                {message, SubjectMsg}
            },
            Opts
        ),
        satisfies_constraints(Key, From, RequiredList, Valid, Match, Opts)
    end;
validate_with_template(<<"supply-threshold-owner">>, Key, _Base, _SubjectMsg, _RawFrom, _Opts)
        when Key =/= <<"set-authority">> ->
    {error, <<"Supply-threshold owner template only supports set-authority.">>};
validate_with_template(<<"supply-threshold-owner">>, Key, Base, _SubjectMsg, RawFrom, Opts) ->
    maybe
        true ?= (not has_static_policy(Key, Base, Opts))
            orelse {error, <<"Ambiguous security policy configuration.">>},
        {ok, Candidate} ?= single_authority_candidate(RawFrom, Opts),
        {ok, Balance} ?= candidate_balance(Candidate, Base, Opts),
        {ok, TotalSupply} ?= total_supply(Base, Opts),
        {ok, ThresholdBps} ?= threshold_bps(Key, Base, Opts),
        true ?= (Balance =< TotalSupply)
            orelse {error, <<"Balance exceeds total supply.">>},
        Res =
            (Balance * 10000 >= TotalSupply * ThresholdBps)
            orelse {error, <<"Supply-threshold owner requirement not satisfied.">>},
        ?event(
            security_short,
            {supply_threshold_owner_check,
                {intent, Key},
                {candidate, Candidate},
                {balance, Balance},
                {total_supply, TotalSupply},
                {threshold_bps, ThresholdBps},
                {result, Res}
            },
            Opts
        ),
        Res
    end;
validate_with_template(_Template, _Key, _Base, _SubjectMsg, _RawFrom, _Opts) ->
    {error, <<"Unknown security template.">>}.

security_template(Key, Base, Opts) ->
    case hb_ao:get(<<Key/binary, "-template">>, Base, not_found, Opts) of
        not_found ->
            default_template(Key, Base, Opts);
        Template ->
            Template
    end.

default_template(<<"set-authority">>, Base, Opts) ->
    case has_static_policy(<<"set-authority">>, Base, Opts) of
        true -> <<"static-signer-set">>;
        false -> <<"supply-threshold-owner">>
    end;
default_template(_Key, _Base, _Opts) ->
    <<"static-signer-set">>.

requires_static_policy(<<"set-authority">>, _Opts) ->
    true;
requires_static_policy(_Key, Opts) ->
    is_prod_mode(Opts).

is_prod_mode(Opts) ->
    case maps:get(dev_security_mode, Opts, maps:get(<<"dev-security-mode">>, Opts, dev)) of
        prod -> true;
        <<"prod">> -> true;
        _ -> false
    end.

has_static_policy(Key, Base, Opts) ->
    hb_ao:get(Key, Base, not_found, Opts) =/= not_found orelse
    hb_ao:get(<<Key/binary, "-required">>, Base, not_found, Opts) =/= not_found orelse
    hb_ao:get(<<Key/binary, "-match">>, Base, not_found, Opts) =/= not_found.

has_static_signer_policy(Key, Base, Opts) ->
    hb_ao:get(Key, Base, not_found, Opts) =/= not_found orelse
    hb_ao:get(<<Key/binary, "-required">>, Base, not_found, Opts) =/= not_found.

valid_static_signer_policy(Key, Base, Valid, Required, Opts) ->
    case requires_static_policy(Key, Opts) orelse has_static_policy(Key, Base, Opts) of
        false ->
            true;
        true ->
            case Valid ++ Required of
                [] ->
                    {error, <<"Security policy not configured.">>};
                Signers ->
                    lists:all(fun valid_static_signer/1, Signers)
                        orelse {error, <<"Security signer cannot be empty.">>}
            end
    end.

valid_static_signer(Signer) when is_binary(Signer) ->
    byte_size(Signer) > 0;
valid_static_signer(_Signer) ->
    true.

single_authority_candidate(RawFrom, Opts) ->
    case lists:uniq(as_list(RawFrom, Opts)) of
        [Candidate] ->
            maybe
                true ?= validate_address(Candidate, [], Opts),
                {ok, Candidate}
            end;
        [] ->
            {error, <<"Authority candidate not found.">>};
        _ ->
            {error, <<"Supply-threshold owner requires exactly one candidate.">>}
    end.

candidate_balance(Candidate, Base, Opts) ->
    case hb_ao:get(<<"balances">>, Base, not_found, Opts) of
        not_found ->
            {error, <<"Balances not configured.">>};
        Balances ->
            Account = account_key(Candidate),
            case hb_ao:resolve(Balances, Account, Opts) of
                {ok, Balance} when is_integer(Balance), Balance >= 0 ->
                    {ok, Balance};
                {ok, Balance} when is_integer(Balance) ->
                    {error, <<"Balance cannot be negative.">>};
                {ok, _Balance} ->
                    {error, <<"Balance must be an integer.">>};
                {error, not_found} ->
                    {ok, 0};
                {error, Reason} ->
                    {error, Reason}
            end
    end.

total_supply(Base, Opts) ->
    case hb_ao:get(<<"total-supply">>, Base, not_found, Opts) of
        TotalSupply when is_integer(TotalSupply), TotalSupply > 0 ->
            {ok, TotalSupply};
        TotalSupply when is_integer(TotalSupply) ->
            {error, <<"Total supply must be positive.">>};
        not_found ->
            {error, <<"Total supply not configured.">>};
        _ ->
            {error, <<"Total supply must be an integer.">>}
    end.

threshold_bps(Key, Base, Opts) ->
    ThresholdRaw = hb_ao:get(<<Key/binary, "-threshold-bps">>, Base, 10000, Opts),
    case parse_integer(ThresholdRaw) of
        ThresholdBps when
                is_integer(ThresholdBps),
                ThresholdBps >= 1,
                ThresholdBps =< 10000 ->
            {ok, ThresholdBps};
        ThresholdBps when is_integer(ThresholdBps) ->
            {error, <<"Threshold basis points out of range.">>};
        Error ->
            Error
    end.

parse_integer(Value) when is_integer(Value) ->
    Value;
parse_integer(Value) when is_binary(Value) ->
    try binary_to_integer(Value) of
        Int -> Int
    catch
        _:_ -> {error, <<"Integer value is invalid.">>}
    end;
parse_integer(_Value) ->
    {error, <<"Integer value is invalid.">>}.

account_key(Account) when is_binary(Account) ->
    lib_token:account_key(Account).

validate_address(Address, CustomList) ->
    lib_token:validate_address(Address, CustomList).

validate_address(Address, CustomList, Opts) ->
    lib_token:validate_address(Address, CustomList, Opts).

%% @doc Validate that the request satisfies the given constraints.
%% Returns true if:
%% 1. At least `Match` elements from `Subject` are in `All`
%% 2. All elements in `Required` are in Subject
satisfies_constraints(Intent, MsgCommitters, Required, Valid, ValidCount, Opts) ->
    % Normalize inputs to lists
    MsgCommitterList = as_list(MsgCommitters, Opts),
    ValidList = as_list(Valid, Opts),
    RequiredList = as_list(Required, Opts),
    % Are there at least `ValidCount' valid committers present in the message?
    PresentAcceptableCommitters = count_common(MsgCommitterList, ValidList),
    SatisfiesAcceptable =
        (PresentAcceptableCommitters >= ValidCount) orelse
            {error, <<"Too few acceptable committers present.">>},
    % Are all required committers present in the message?
    PresentRequiredCommitters = count_common(MsgCommitterList, RequiredList),
    SatisfiesRequired =
        (PresentRequiredCommitters == length(RequiredList)) orelse
            {error, <<"Required committers not present in message.">>},
    % Must have at least `Match' common elements AND all `Required' elements
    Res =
        case SatisfiesAcceptable of
            true -> SatisfiesRequired;
            Error -> Error
        end,
    ?event(
        security_short,
        {constraint_check,
            {intent, Intent},
            {message_committers, length(MsgCommitterList)},
            {acceptable_committers, length(ValidList)},
            {present_acceptable_committers, PresentAcceptableCommitters},
            {satisfies_acceptable, SatisfiesAcceptable},
            {required_committers, length(RequiredList)},
            {all_required_are_present, SatisfiesRequired},
            {result, Res}
        },
        Opts
    ),
    Res.

%% @doc Count elements that appear in both lists.
count_common(ListA, ListB) -> length([X || X <- ListA, lists:member(X, ListB)]).

%% @doc Normalize value to a list.
as_list(Value, _Opts) when is_list(Value) -> Value;
as_list(Value, _Opts) -> [Value].

%% @doc Normalize signer config values. Supports true lists and comma-separated
%% binary encodings used in process security configuration.
as_signer_config_list(Value, _Opts) when is_list(Value) -> Value;
as_signer_config_list(Value, _Opts) when is_binary(Value) ->
    hb_util:binary_to_strings(Value);
as_signer_config_list(_Value, _Opts) -> 
    {error, <<"Signer config must be a binary or a list.">>}.
%% @doc Normalize and validate a `*-match` threshold against the acceptable
%% signer set `Valid`. Let `ValidLen = |Valid|`. If no explicit threshold is
%% provided, the default threshold is `0` when `ValidLen = 0` and `1` when
%% `ValidLen > 0`. Explicit thresholds must be integer-like and satisfy:
%% `Match = 0` iff `ValidLen = 0`; otherwise `1 =< Match =< ValidLen`.
safe_match(_Match, _Default, ValidLen) when not is_integer(ValidLen) ->
    {error, <<"Invalid Valid list length type.">>};
safe_match(_Match, _Default, ValidLen) when is_integer(ValidLen), ValidLen < 0 ->
    {error, <<"Valid list length must be a non-negative integer.">>};
safe_match(_Match, Default, _ValidLen) when not is_integer(Default) ->
    {error, <<"Invalid Default type.">>};
safe_match(_Match, Default, _ValidLen) when Default < 0 ->
    {error, <<"Default must be a non-negative integer.">>};
safe_match(_Match, Default, ValidLen) when Default > ValidLen ->
    {error, <<"Default must be integer less than or equal to ValidLen.">>};
safe_match(not_found, Default, _ValidLen) when is_integer(Default), Default >= 0 ->
    Default;
safe_match(Match, _Default, ValidLen) when is_integer(Match) ->
    case {Match, ValidLen} of
        {0, 0} -> 0;
        {M, V} when M > 0 andalso M =< V -> M;
        _ -> {error, <<"Invalid Match threshold.">>}
    end;
safe_match(Match, _Default, ValidLen) when is_binary(Match)->
    try binary_to_integer(Match) of
        IntMatch -> safe_match(IntMatch, _Default, ValidLen)
    catch
        _:_ -> {error, <<"Invalid Match threshold.">>}
    end;
safe_match(_, _, _) ->
    {error, <<"Invalid Match threshold.">>}.

%% @doc Return the single element of a list if there is only one, else return
%% the list.
maybe_single([SingleElement], _Opts) -> SingleElement;
maybe_single(List, _Opts) -> List.
