"""Resolve proxy hostnames through the same ordered DNS policy as DNS queries.

FakeIP rules deliberately leave resolution to the selected remote proxy. Their
effective match includes precedence: an earlier DNS-only rule can override them.
"""
import copy
from policy_modes import ACTION_FIELDS
from rule_compiler import conjunction


def disjunction(parts):
    return parts[0] if len(parts) == 1 else {'type': 'logical', 'mode': 'or', 'rules': parts}


def inverted(match):
    result = copy.deepcopy(match)
    result['invert'] = not result.get('invert', False)
    return result


def has_query_type(match):
    return 'query_type' in match or any(has_query_type(child) for child in match.get('rules', []))


def required_mode(match):
    """Only recognize a positive mode guard guaranteed by this conjunction."""
    if match.get('invert'):
        return None
    if isinstance(match.get('clash_mode'), str):
        return match['clash_mode']
    if match.get('type') == 'logical' and match.get('mode') == 'and':
        for child in match['rules']:
            mode = required_mode(child)
            if mode is not None:
                return mode
    return None


def connection_resolve_rule(dns_rules, servers):
    fake_tags = {server['tag'] for server in servers if server['type'] == 'fakeip'}
    all_earlier, unguarded, by_mode, remote_names = [], [], {}, []
    for rule in dns_rules:
        match = {key: copy.deepcopy(value) for key, value in rule.items() if key not in ACTION_FIELDS}
        # A/AAAA suppression must stay in DNS routing; query_type is not a
        # connection matcher. Every compiled profile has a whole-query tail.
        if has_query_type(match):
            continue
        mode = required_mode(match)
        # Other modes cannot match this rule. Excluding their history avoids
        # quadratic growth across independent precompiled mode combinations.
        earlier = all_earlier if mode is None else [*unguarded, *by_mode.get(mode, [])]
        if rule.get('action') == 'route' and rule.get('server') in fake_tags:
            effective = conjunction(match, inverted(disjunction(earlier))) if earlier else match
            remote_names.append(effective)
        if not match:  # unconditional terminal rule
            break
        all_earlier.append(match)
        (unguarded if mode is None else by_mode.setdefault(mode, [])).append(match)
    condition = inverted(disjunction(remote_names)) if remote_names else {}
    # No explicit server: sing-box must evaluate dns.rules with the connection
    # metadata, including source and current mode, and preserve DNS-only rules.
    return {**condition, 'action': 'resolve'}
