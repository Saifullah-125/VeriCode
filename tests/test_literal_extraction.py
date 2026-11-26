from security.secrets.literal_extractor import extract_literals


def test_extracts_python_assignment_and_dict_literals():
    code = """
api_key = "sk-live-1234567890abcdef"
config = {"db_password": "s3cr3t_db_password"}
env_val = os.getenv("OPENAI_API_KEY")
"""
    lits = extract_literals(code, "Python")
    by_val = {item.value: item for item in lits}

    assert "sk-live-1234567890abcdef" in by_val
    assert by_val["sk-live-1234567890abcdef"].context_name == "api_key"
    assert by_val["sk-live-1234567890abcdef"].line == 2

    assert "s3cr3t_db_password" in by_val
    assert by_val["s3cr3t_db_password"].context_name == "db_password"
    assert by_val["s3cr3t_db_password"].context_kind == "dict_key"

    assert by_val["OPENAI_API_KEY"].is_env_lookup is True


def test_extracts_c_cpp_and_java_literals():
    c_code = 'int main() { char password[32] = "super_secret_123"; return 0; }'
    c_lits = extract_literals(c_code, "C")
    assert len(c_lits) == 1
    assert c_lits[0].value == "super_secret_123"
    assert c_lits[0].context_name == "password"

    java_code = 'public class A { String apiKey = "AIzaSyD-1234567890Secret"; }'
    j_lits = extract_literals(java_code, "Java")
    assert len(j_lits) == 1
    assert j_lits[0].value == "AIzaSyD-1234567890Secret"
    assert j_lits[0].context_name == "apiKey"
