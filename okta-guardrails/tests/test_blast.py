from okta_guardrails.blast import Population, analyze

from conftest import make_plan


def by_group(result):
    return {i.group: i for i in result.impacts}


def test_demo_numbers(risky, population):
    r = by_group(analyze(risky, population))
    sf = r["Salesforce-Admin"]
    assert (sf.before, sf.after, len(sf.gained), len(sf.lost)) == (5, 352, 347, 0)
    assert sf.apps == ["Salesforce"]
    aws = r["AWS-Prod"]
    assert len(aws.gained) == 0 and len(aws.lost) == aws.before - aws.after > 0
    assert r["Okta-Helpdesk-Admins"].admin_roles == ["HELP_DESK_ADMIN", "SUPER_ADMIN"]
    assert len(r["Sales-Leadership"].gained) == 5  # resolved through config references


def test_clean_plan_has_no_impact(clean, population):
    result = analyze(clean, population)
    assert result.impacts == [] and result.findings == []


def _pop():
    return Population(users=[
        {"id": "u1", "login": "a", "profile": {"department": "Sales"}, "groups": []},
        {"id": "u2", "login": "b", "profile": {"department": "Sales"}, "groups": []},
        {"id": "u3", "login": "c", "profile": {"department": "IT"}, "groups": ["G"]},
    ])


PRIOR_GROUP = ("okta_group.g", {"id": "00gG", "name": "G"})


def test_overlapping_rules_do_not_count_as_loss():
    # Rule A and rule B both feed G; narrowing A does not remove users B still matches.
    prior = [PRIOR_GROUP,
             ("okta_group_rule.b", {"id": "rB", "status": "ACTIVE", "expression_value": 'user.department == "Sales"',
                                    "group_assignments": ["00gG"]})]
    a_before = {"id": "rA", "status": "ACTIVE", "expression_value": 'user.department == "Sales"', "group_assignments": ["00gG"]}
    a_after = {**a_before, "expression_value": 'user.department == "Nobody"'}
    plan = make_plan([("okta_group_rule.a", ["update"], a_before, a_after)], prior=prior + [("okta_group_rule.a", a_before)])
    imp = by_group(analyze(plan, _pop()))["G"]
    assert imp.lost == [] and imp.gained == []


def test_direct_members_are_never_lost():
    before = {"id": "r", "status": "ACTIVE", "expression_value": 'user.department == "IT"', "group_assignments": ["00gG"]}
    after = {**before, "expression_value": 'user.department == "Sales"'}
    plan = make_plan([("okta_group_rule.r", ["update"], before, after)], prior=[PRIOR_GROUP, ("okta_group_rule.r", before)])
    imp = by_group(analyze(plan, _pop()))["G"]
    assert [u["id"] for u in imp.gained] == ["u1", "u2"] and imp.lost == []  # u3 is a direct member


def test_deleted_rule_leaves_members_behind_unless_removed():
    before = {"id": "r", "status": "ACTIVE", "expression_value": 'user.department == "Sales"',
              "group_assignments": ["00gG"], "remove_assigned_users": False}
    plan = make_plan([("okta_group_rule.r", ["delete"], before, None)], prior=[PRIOR_GROUP, ("okta_group_rule.r", before)])
    res = analyze(plan, _pop())
    imp = by_group(res)["G"]
    assert imp.lost == [] and len(imp.retained) == 2
    assert "BR004" in {f.rule_id for f in res.findings}

    before2 = {**before, "remove_assigned_users": True}
    plan2 = make_plan([("okta_group_rule.r", ["delete"], before2, None)], prior=[PRIOR_GROUP, ("okta_group_rule.r", before2)])
    imp2 = by_group(analyze(plan2, _pop()))["G"]
    assert len(imp2.lost) == 2 and imp2.retained == []


def test_unsupported_expression_is_reported():
    before = {"id": "r", "status": "ACTIVE", "expression_value": 'user.department == "IT"', "group_assignments": ["00gG"]}
    after = {**before, "expression_value": 'Convert.toInt(user.level) > 3'}
    plan = make_plan([("okta_group_rule.r", ["update"], before, after)], prior=[PRIOR_GROUP, ("okta_group_rule.r", before)])
    res = analyze(plan, _pop())
    assert any(f.rule_id == "BR003" for f in res.findings)
