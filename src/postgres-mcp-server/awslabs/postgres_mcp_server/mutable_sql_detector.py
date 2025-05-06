import re

MUTATING_KEYWORDS = {
    # DML
    "INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE",

    # DDL
    "CREATE", "DROP", "ALTER", "RENAME",

    # Permissions
    "GRANT", "REVOKE",

    # Metadata changes
    "COMMENT ON", "SECURITY LABEL",

    # Extensions and functions
    "CREATE EXTENSION", "CREATE FUNCTION", "INSTALL",

    # Storage-level
    "CLUSTER", "REINDEX", "VACUUM", "ANALYZE",
}

# Compile regex pattern
MUTATING_PATTERN = re.compile(
    r"(?i)\b(" + "|".join(re.escape(k) for k in MUTATING_KEYWORDS) + r")\b"
)

def remove_comments(sql: str) -> str:
    sql = re.sub(r'--.*?$', '', sql, flags=re.MULTILINE)
    sql = re.sub(r'/\*.*?\*/', '', sql, flags=re.DOTALL)
    return sql

def remove_strings(sql: str) -> str:
    # Remove single-quoted and double-quoted string literals
    return re.sub(r"('([^']|'')*')|(\"([^\"]|\"\")*\")", '', sql)

def detect_mutating_keywords(sql_text: str) -> list[str]:
    """
    Return a list of mutating keywords found in the SQL (excluding comments).
    """
    cleaned_sql = remove_comments(sql_text)
    cleaned_sql = remove_strings(cleaned_sql)
    matches = MUTATING_PATTERN.findall(cleaned_sql)
    return list(set(m.upper() for m in matches))  # Deduplicated and normalized to uppercase