import pytest

from okta_guardrails.oel import Context, Expression, OELError, UnsupportedExpression, evaluate


def ctx(**profile):
    return Context(profile=profile, group_names=set(), group_ids=set())


@pytest.mark.parametrize("expr,expected", [
    ('user.department == "Sales"', True),
    ("user.department == 'Sales'", True),
    ('user.department != "Sales"', False),
    ('user.department == "sales"', False),  # case-sensitive
    ('user.department == "Sales" && user.employeeType == "Contractor"', False),
    ('user.department == "Sales" AND user.employeeType == "Employee"', True),
    ('user.department == "IT" || user.title == "VP Sales"', True),
    ('!(user.department == "Sales")', False),
    ('String.stringContains(user.department, "Sal")', True),
    ('String.toLowerCase(user.department) == "sales"', True),
    ('user.missing == null', True),
    ('String.stringContains(user.missing, "x")', False),
    ('user.level >= 5', True),
    ('user.level > "x"', False),
    ('user.department == "Sales" ? true : false', True),
    ('Arrays.contains(user.tags, "vip")', True),
])
def test_expressions(expr, expected):
    c = ctx(department="Sales", employeeType="Employee", title="VP Sales", level=7, tags=["vip"])
    assert Expression(expr).matches(c) is expected


def test_operator_precedence():
    c = ctx(a="1", b="2", c="3")
    # && binds tighter than ||
    assert Expression('user.a == "x" && user.b == "2" || user.c == "3"').matches(c)
    assert not Expression('user.a == "x" && (user.b == "2" || user.c == "3")').matches(c)


def test_group_functions():
    c = Context(profile={}, group_names={"Engineering", "Everyone"}, group_ids={"00gENG"})
    assert evaluate('isMemberOfGroupName("Engineering")', c) is True
    assert evaluate('isMemberOfGroup("00gENG")', c) is True
    assert evaluate('isMemberOfAnyGroup("00gX", "00gENG")', c) is True
    assert evaluate('isMemberOfGroupNameStartsWith("Eng")', c) is True
    assert evaluate('isMemberOfGroupNameContains("ryo")', c) is True
    assert evaluate('isMemberOfGroupNameRegex("Every.*")', c) is True
    assert evaluate('isMemberOfGroupName("Sales")', c) is False


def test_unsupported_function_is_reported_not_guessed():
    with pytest.raises(UnsupportedExpression):
        Expression('Convert.toInt(user.level) > 3').matches(ctx(level="4"))


def test_unsupported_reference():
    with pytest.raises(UnsupportedExpression):
        Expression('app.department == "x"').matches(ctx())


def test_syntax_error():
    with pytest.raises(OELError):
        Expression('user.department == ')
