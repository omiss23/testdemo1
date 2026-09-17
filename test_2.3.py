"""
FT IR-1 keyword screening driven by the mapping workbook.

Mapping workbook
  P1                 RT Type, Countries
  P2                 RT Type, Keyword, Message, Rules, Status
  Intelligence_Lists List (TOPONYM, SECULAR, RELIGIOUS), Value, Status

How the sheets combine
  Each ACTIVE row in P2 is one screening rule:
    - search its Keyword in every column listed in its Message cell
    - only in transactions where an FI country code is in the Countries
      that P1 gives for the row's RT Type
    - check each hit against the row's Rules (comma separated, or blank)
  Keywords are searched exactly as written, ignoring only upper/lower case and
  spaces at either end: ON-SURYA matches ON-SURYA, not ONSURYA or ON SURYA.
  Look-alike characters count as their plain versions in the mapping and in the
  transactions: non-breaking space = space, en dash = hyphen, curly apostrophe =
  straight apostrophe.
  Listing ORIGINATOR_NAME or ORIGINATOR_NAME_1 in a Message cell searches both.

Hit-level decision: FLAG, unless any one of the row's rules clears the hit
  no rules            FLAG
  EXCL_INDIV          Clears a hit in a party name when that party's entity
                      type is INDIV. CORP doesn't clear it, and blank means the
                      rule isn't applied. Each name uses its own party's column:
                        ORIGINATOR_NAME, ORIGINATOR_NAME_1 -> ENTITY_TYPE_ORG
                        BENEFICIARY_NAME                   -> ENTITY_TYPE_BENE
  EXCL_ON_TOPONYM     Clear a hit when every occurrence of the keyword in that
  EXCL_IN_SECULAR     field sits inside an ACTIVE value from the TOPONYM,
  EXCL_IN_RELIGIOUS   SECULAR or RELIGIOUS list. Values from all of the row's
                      list rules count together. A value that is just the
                      keyword itself never clears it.

Output: each transaction with at least one keyword hit, with all its own columns, then
  KEYWORD, RT TYPE, MATCHED_ISO   from the hits behind the disposition: for an
                                  ALERT the hits no rule cleared, for EXCLUDED all
  DISPOSITION                     ALERT if a hit is left after the EXCL_ rules;
                                  EXCLUDED if every hit was cleared or the BNPAFR
                                  filter applies (see EXCLUDE_WHEN)
  RULE_APPLIED                    what excluded it: the EXCL_ rules and/or BNPAFR
  FLAGGED                         Y for ALERT, N for EXCLUDED
  The DISPOSITION and FLAGGED values are set in OUTPUT_LABELS. Each FI code is its
  4-character FI_ORG_KEY plus its 2-character FI_COUNTRY_CD.

Usage
  1. Set INPUT_FILE, MAPPING_FILE and OUTPUT_FILE in the "File paths" section below
  2. Run:  python ft_ir1_name_rules.py          (or press Run in your editor)
     Test: python ft_ir1_name_rules.py --demo   (runs the built-in test cases)
"""
import difflib
import os
import re
import sys

import pandas as pd

# ---------------------------------------------------------------------------
# File paths: edit these three lines
# Keep the r before each opening quote so Windows backslashes are read as-is.
# ---------------------------------------------------------------------------
INPUT_FILE = r"C:\FT_IR_1\input\transactions.csv"            # transaction extract (CSV)
MAPPING_FILE = r"C:\FT_IR_1\mapping\FT_IR_1_mapping.xlsx"    # sheets P1, P2, Intelligence_Lists
OUTPUT_FILE = r"C:\FT_IR_1\output\final_threat_report.csv"   # overwritten on each run

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KEY = "MESSAGE_KEY"

# Entity type columns in the extract (INDIV, CORP or blank)
ORIGINATOR_ENTITY_TYPE = "ENTITY_TYPE_ORG"
BENEFICIARY_ENTITY_TYPE = "ENTITY_TYPE_BENE"

# Party name columns (exact extract names), each with its party's entity type column
ENTITY_TYPE_FOR = {
    "ORIGINATOR_NAME": ORIGINATOR_ENTITY_TYPE,
    "ORIGINATOR_NAME_1": ORIGINATOR_ENTITY_TYPE,
    "BENEFICIARY_NAME": BENEFICIARY_ENTITY_TYPE,
}
NAME_COLUMNS = list(ENTITY_TYPE_FOR)

# Columns searched together: listing any one of them in a Message cell searches all
SEARCH_TOGETHER = [["ORIGINATOR_NAME", "ORIGINATOR_NAME_1"]]
ISO_COLUMNS = ["ORIGINATOR_FI_COUNTRY_CD", "BENEFICIARY_FI_COUNTRY_CD"]

INDIV_RULE = "EXCL_INDIV"
LIST_RULES = {                       # rule -> Intelligence_List list it uses
    "EXCL_ON_TOPONYM": "TOPONYM",
    "EXCL_IN_SECULAR": "SECULAR",
    "EXCL_IN_RELIGIOUS": "RELIGIOUS",
}
KNOWN_RULES = [INDIV_RULE] + list(LIST_RULES)

# FI code exclusion: 4-character org key + 2-character country code, e.g. BNPA + FR
FI_CODE_PARTS = {
    "ORIGINATOR_FI": ("ORIGINATOR_FI_ORG_KEY", "ORIGINATOR_FI_COUNTRY_CD"),
    "BENEFICIARY_FI": ("BENEFICIARY_FI_ORG_KEY", "BENEFICIARY_FI_COUNTRY_CD"),
}
EXCLUDED_FI_CODES = ["BNPAFR"]
EXCLUDE_WHEN = "either"   # "either": the originator or the beneficiary FI code matches
                          # "both":   the originator and beneficiary FI codes both match

# Output columns, added after all of the transaction's own columns
OUTPUT_COLUMNS = ["KEYWORD", "RT TYPE", "MATCHED_ISO", "DISPOSITION", "RULE_APPLIED", "FLAGGED"]

# How each outcome is written in DISPOSITION and FLAGGED
OUTPUT_LABELS = {
    "SUSPICIOUS": ("ALERT", "Y"),      # at least one keyword hit that no EXCL_ rule cleared
    "CLEARED":    ("EXCLUDED", "N"),   # every keyword hit cleared by an EXCL_ rule
    "EXCLUDED":   ("EXCLUDED", "N"),   # excluded by the BNPAFR filter
}

SHEET_P1, SHEET_P2, SHEET_LISTS = "P1", "P2", "Intelligence_Lists"
COUNTRY_CODE_RE = r"^[A-Z]{2}$"
SPLIT_RE = r"[,;|\n]+"    # separators allowed inside Message, Countries and Rules cells

# Look-alike characters are read as their plain versions, in the mapping and in the
# transactions, so values match the way they look: odd spaces such as the non-breaking
# space become a normal space, dashes a hyphen, curly apostrophes a straight one, and
# invisible characters are dropped.
PLAIN = str.maketrans({
    **dict.fromkeys("\u00A0\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009"
                    "\u200A\u202F\u205F\u3000", " "),
    **dict.fromkeys("\u2010\u2011\u2012\u2013\u2014\u2015\u2212\uFE63\uFF0D", "-"),
    **dict.fromkeys("\u2018\u2019\u201B\u02BB\u02BC\u02BD\u02BE\u02BF\u2032\u00B4\u0060", "'"),
    **dict.fromkeys("\u00AD\u200B\u200C\u200D\u2060\uFEFF", ""),
})


def _upper(s):
    return s.fillna("").astype(str).str.translate(PLAIN).str.strip().str.upper()


def _plain(value):
    return str(value).translate(PLAIN).strip().upper()


def _split(cell):
    return [p.strip() for p in re.split(SPLIT_RE, str(cell).translate(PLAIN)) if p.strip()]


def _closest(names, pool):
    """Each missing name, with the most similar names from the pool."""
    out = []
    for name in names:
        close = difflib.get_close_matches(_plain(name), [str(p) for p in pool], n=2, cutoff=0.6)
        out.append(f"{name} (closest in the extract: {', '.join(close)})" if close else name)
    return out


def _columns(df, sheet, required):
    """Find the required headers, ignoring case and stray spaces, and drop
    completely blank rows."""
    lookup = {_plain(c): c for c in df.columns}
    missing = [r for r in required if r.upper() not in lookup]
    if missing:
        raise ValueError(f"Sheet {sheet} is missing columns: {missing}")
    df = df.rename(columns={lookup[r.upper()]: r for r in required})[required].fillna("")
    filled = df.astype(str).apply(lambda c: c.str.strip().ne(""))
    return df[filled.any(axis=1)]


def _active_rows(df, sheet, problems):
    status = _upper(df["Status"])
    odd = sorted(set(status) - {"ACTIVE", "INACTIVE"})
    if odd:
        problems.append(f"{sheet}: Status must be ACTIVE or INACTIVE, found: "
                        f"{[v or '(blank)' for v in odd]}")
    return df[status == "ACTIVE"]


def _search_together(columns, by_upper, missing):
    """Add the other columns of any SEARCH_TOGETHER group a listed column is in."""
    out = []
    for col in columns:
        group = next((g for g in SEARCH_TOGETHER
                      if col.upper() in [c.upper() for c in g]), [col])
        for member in group:
            actual = by_upper.get(member.upper())
            if actual is None:
                missing.add(member)
            elif actual not in out:
                out.append(actual)
    return out


# ---------------------------------------------------------------------------
# 1. Read and check the mapping
# ---------------------------------------------------------------------------
def load_mapping(p1, p2, intel, extract_columns):
    """Return (rules, lists): one screening rule per ACTIVE P2 row, and the
    ACTIVE values of each Intelligence_List list. Every problem found in the
    three sheets is reported together in one error."""
    p1 = _columns(p1, SHEET_P1, ["RT Type", "Countries"])
    p2 = _columns(p2, SHEET_P2, ["RT Type", "Keyword", "Message", "Rules", "Status"])
    intel = _columns(intel, SHEET_LISTS, ["List", "Value", "Status"])
    problems = []

    needed = list(dict.fromkeys([KEY] + ISO_COLUMNS + list(ENTITY_TYPE_FOR.values())
                                + [col for parts in FI_CODE_PARTS.values() for col in parts]))
    missing = [c for c in needed if c not in extract_columns]
    if missing:
        unused = [c for c in extract_columns if c not in needed]
        problems.append(f"Extract is missing columns: {'; '.join(_closest(missing, unused))}")
    clash = [c for c in OUTPUT_COLUMNS if c in extract_columns]
    if clash:
        problems.append(f"Extract already has columns named like output columns: {clash}")
    if EXCLUDE_WHEN not in ("either", "both"):
        problems.append(f"EXCLUDE_WHEN must be 'either' or 'both', not '{EXCLUDE_WHEN}'")

    # Intelligence_List: list name -> ACTIVE values
    lists = {name: set() for name in LIST_RULES.values()}
    for i, row in _active_rows(intel, SHEET_LISTS, problems).iterrows():
        name = _plain(row["List"])
        value = _plain(row["Value"])
        if name not in lists:
            problems.append(f"{SHEET_LISTS} row {i + 2}: List '{name}' is not one of {list(lists)}")
        elif not value:
            problems.append(f"{SHEET_LISTS} row {i + 2}: Value is blank")
        else:
            lists[name].add(value)

    # P1: RT Type -> country codes (one code per row, or several in a cell)
    countries = {}
    for i, row in p1.iterrows():
        rt = _plain(row["RT Type"])
        codes = [c.upper() for c in _split(row["Countries"])]
        if not rt:
            problems.append(f"P1 row {i + 2}: Countries {codes} have no RT Type")
            continue
        if not codes:
            problems.append(f"P1 row {i + 2}: RT Type {rt} has no Countries")
        bad = [c for c in codes if not re.match(COUNTRY_CODE_RE, c)]
        if bad:
            problems.append(f"P1 row {i + 2}: not two-letter country codes: {bad}")
        countries.setdefault(rt, set()).update(codes)

    # P2: one screening rule per ACTIVE row
    by_upper = {_plain(c): c for c in extract_columns}
    rules, missing_together = [], set()
    for i, row in _active_rows(p2, SHEET_P2, problems).iterrows():
        where = f"P2 row {i + 2}"
        rt = _plain(row["RT Type"])
        keyword = _plain(row["Keyword"])   # hyphens and all other characters kept
        row_rules = list(dict.fromkeys(r.upper() for r in _split(row["Rules"])))
        listed = _split(row["Message"])
        found = [by_upper.get(c.upper()) for c in listed]

        if not keyword:
            problems.append(f"{where}: Keyword is blank")
        if not countries.get(rt):
            problems.append(f"{where}: RT Type '{rt}' has no countries in P1")
        if not listed:
            problems.append(f"{where}: Message lists no columns")
        unknown = [c for c, f in zip(listed, found) if f is None]
        if unknown:
            problems.append(f"{where}: Message columns not in the extract: "
                            f"{'; '.join(_closest(unknown, by_upper))}")
        columns = _search_together([f for f in found if f], by_upper, missing_together)
        bad = [r for r in row_rules if r not in KNOWN_RULES]
        if bad:
            problems.append(f"{where}: Rules not recognised: {bad}")
        for r in row_rules:
            name = LIST_RULES.get(r)
            if name and not lists[name]:
                problems.append(f"{where}: {r} needs {name} values, but "
                                f"{SHEET_LISTS} has no ACTIVE {name} rows")

        rules.append({"row": i + 2, "rt_type": rt, "keyword": keyword, "rules": row_rules,
                      "columns": columns,
                      "countries": sorted(countries.get(rt, ()))})

    if missing_together:
        problems.append(f"Extract is missing {sorted(missing_together)}, which must be "
                        f"searched together with {SEARCH_TOGETHER}")
    indiv_rows = [r for r in rules if INDIV_RULE in r["rules"]]
    if indiv_rows and not any(c in NAME_COLUMNS for r in indiv_rows for c in r["columns"]):
        problems.append(f"P2 uses {INDIV_RULE}, but no Message cell on those rows lists the "
                        f"name columns {NAME_COLUMNS}. Set ENTITY_TYPE_FOR to the names "
                        f"used in Message.")

    if problems:
        raise ValueError("Mapping problems:\n  - " + "\n  - ".join(problems))
    if not rules:
        raise ValueError("P2 has no ACTIVE rows, so nothing would be screened")
    return rules, {name: sorted(values) for name, values in lists.items()}


# ---------------------------------------------------------------------------
# 2. Keyword hits: one row per P2 rule per column the keyword was found in
# ---------------------------------------------------------------------------
def build_hits(txns, rules):
    if txns[KEY].duplicated().any():
        raise ValueError(f"{KEY} is not unique in the extract")
    iso = txns[ISO_COLUMNS].apply(_upper)
    scope, upper_cols, parts = {}, {}, []

    def col_upper(col):
        if col not in upper_cols:
            upper_cols[col] = _upper(txns[col])
        return upper_cols[col]

    for r in rules:
        if r["rt_type"] not in scope:
            scope[r["rt_type"]] = iso.isin(r["countries"]).any(axis=1)
        in_scope = scope[r["rt_type"]]
        if not in_scope.any():
            continue

        for col in r["columns"]:
            text = col_upper(col)
            # Exact search: the keyword is used as written, so a hyphen in the
            # keyword must also be in the text (ON-SURYA never matches ONSURYA).
            found = text[in_scope].str.contains(r["keyword"], regex=False)
            idx = found[found].index
            if idx.empty:
                continue
            codes = iso.loc[idx]
            matched = codes.where(codes.isin(r["countries"]), "").apply(
                lambda v: ",".join(sorted({c for c in v if c})), axis=1)
            type_col = ENTITY_TYPE_FOR.get(col)
            parts.append(pd.DataFrame({
                KEY: txns.loc[idx, KEY],
                "p2_row": r["row"],
                "rt_type": r["rt_type"],
                "keyword": r["keyword"],
                "matched_column": col,
                "rules": ",".join(r["rules"]),
                "countries": matched,
                "text": text.loc[idx],
                "entity_type": col_upper(type_col).loc[idx] if type_col else "",
            }))

    columns = [KEY, "p2_row", "rt_type", "keyword", "matched_column", "rules",
               "countries", "text", "entity_type"]
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=columns)


# ---------------------------------------------------------------------------
# 3. Decide each hit
# ---------------------------------------------------------------------------
def _starts(text, word):
    """Start position of every occurrence of word in text, overlaps included."""
    starts, i = [], text.find(word)
    while i != -1:
        starts.append(i)
        i = text.find(word, i + 1)
    return starts


def _inside_listed_values(text, keyword, values):
    """For the given (rule, value) pairs: how many times the keyword occurs in the
    text, how many of those sit inside an occurrence of a value, and which rules'
    values did the covering."""
    starts = _starts(text, keyword)
    inside, used = set(), []
    for rule, value in values:
        for v in _starts(text, value):
            covered = {s for s in starts if v <= s and s + len(keyword) <= v + len(value)}
            if covered:
                inside |= covered
                if rule not in used:
                    used.append(rule)
    return len(starts), len(inside), used


def decide(hit, candidates):
    """("CLEAR", the rules that cleared the hit) if any of its P2 row's rules clears
    it, otherwise ("FLAG", [])."""
    rules = [r for r in hit["rules"].split(",") if r]
    keyword = hit["keyword"]
    cleared_by = []

    # EXCL_INDIV: a party name whose own party's entity type column says INDIV
    if (INDIV_RULE in rules and hit["matched_column"] in ENTITY_TYPE_FOR
            and hit["entity_type"] == "INDIV"):
        cleared_by.append(INDIV_RULE)

    # List rules: every occurrence of the keyword sits inside a longer listed value
    list_rules = [r for r in rules if r in LIST_RULES]
    if list_rules:
        values = [(r, v) for r in list_rules for v in candidates[(keyword, LIST_RULES[r])]]
        total, inside, used = _inside_listed_values(hit["text"], keyword, values)
        if total and inside == total:
            cleared_by += used

    return ("CLEAR", cleared_by) if cleared_by else ("FLAG", [])


def apply_rules(hits, lists):
    h = hits.copy()
    # Only a list value that contains the keyword and is longer than it can clear it.
    # A value that is just the keyword (TOPONYM 'FALCON' for keyword FALCON) can't
    # show that a hit is really part of a place name or phrase.
    candidates = {(kw, name): [v for v in values if kw in v and v != kw]
                  for kw in h["keyword"].unique() for name, values in lists.items()}
    results = [decide(hit, candidates) for hit in h.to_dict("records")]
    h["hit_decision"] = [d for d, _ in results]
    h["cleared_by"] = [",".join(c) for _, c in results]
    return h


# ---------------------------------------------------------------------------
# 4. One row per transaction, with the output columns
# ---------------------------------------------------------------------------
def _unique(values):
    return ", ".join(sorted({v for v in values if v}))


def _unique_parts(values):
    return ", ".join(sorted({p for v in values for p in v.split(",") if p}))


def _fi_excluded(df):
    """Per row: the excluded FI code, e.g. "BNPAFR", or "" (see EXCLUDE_WHEN)."""
    codes, matches = [], []
    for org_col, country_col in FI_CODE_PARTS.values():
        org, country = _upper(df[org_col]), _upper(df[country_col])
        code = (org + country).where(org.str.len().eq(4) & country.str.len().eq(2), "")
        match = code.isin(EXCLUDED_FI_CODES)
        codes.append(code.where(match, ""))
        matches.append(match)
    matches = pd.concat(matches, axis=1)
    excluded = matches.all(axis=1) if EXCLUDE_WHEN == "both" else matches.any(axis=1)
    return pd.concat(codes, axis=1).apply(_unique, axis=1).where(excluded, "")


def transaction_outcomes(h, txns):
    """One row per transaction with hits (index MESSAGE_KEY): its outcome, and the
    KEYWORD, RT TYPE, MATCHED_ISO and RULE_APPLIED values behind it.
      SUSPICIOUS  at least one hit that no EXCL_ rule cleared
      CLEARED     every hit cleared by an EXCL_ rule
      EXCLUDED    the BNPAFR filter applies
    A SUSPICIOUS transaction is described by the hits no rule cleared; the others
    by all of their hits."""
    hit_txns = txns[txns[KEY].isin(h[KEY])]
    fi_code = pd.Series(_fi_excluded(hit_txns).to_numpy(), index=hit_txns[KEY].to_numpy())

    is_flag = h["hit_decision"].eq("FLAG")
    outcome = is_flag.groupby(h[KEY]).any().map({True: "SUSPICIOUS", False: "CLEARED"})
    outcome[fi_code.reindex(outcome.index).ne("")] = "EXCLUDED"

    described = h[is_flag | h[KEY].map(outcome).ne("SUSPICIOUS")].groupby(KEY)
    report = pd.DataFrame({
        "outcome": outcome,
        "KEYWORD": described["keyword"].agg(_unique),
        "RT TYPE": described["rt_type"].agg(_unique),
        "MATCHED_ISO": described["countries"].agg(_unique_parts),
        "RULE_APPLIED": described["cleared_by"].agg(_unique_parts),
    })
    excluded = report["outcome"].eq("EXCLUDED")
    report.loc[excluded, "RULE_APPLIED"] = (
        report.loc[excluded, "RULE_APPLIED"] + ", " + fi_code.reindex(report.index)[excluded]
    ).str.strip(", ")
    report.index.name = KEY
    return report


def summarise(h, txns):
    """All transaction columns plus OUTPUT_COLUMNS, for each transaction with hits."""
    if h.empty:
        return txns.iloc[0:0].assign(**{c: "" for c in OUTPUT_COLUMNS})
    report = transaction_outcomes(h, txns)
    labels = report.pop("outcome").map(OUTPUT_LABELS)
    report["DISPOSITION"] = labels.str[0]
    report["FLAGGED"] = labels.str[1]
    out = txns.merge(report.reset_index(), on=KEY, how="inner")
    return out[list(txns.columns) + OUTPUT_COLUMNS]


# ---------------------------------------------------------------------------
# Run on real files
# ---------------------------------------------------------------------------
def run(input_file=INPUT_FILE, mapping_file=MAPPING_FILE, output_file=OUTPUT_FILE):
    problems = [f"{label} not found: {path}" for label, path in
                [("INPUT_FILE", input_file), ("MAPPING_FILE", mapping_file)]
                if not os.path.isfile(path)]
    out_folder = os.path.dirname(os.path.abspath(output_file))
    if not os.path.isdir(out_folder):
        problems.append(f"OUTPUT_FILE folder doesn't exist: {out_folder}")
    if problems:
        raise FileNotFoundError("File path problems:\n  - " + "\n  - ".join(problems))

    # keep_default_na=False: by default pandas turns the country code "NA"
    # (Namibia) into a missing value, which silently drops those matches.
    read = dict(dtype=str, keep_default_na=False)
    txns = pd.read_csv(input_file, **read)
    txns.columns = [_plain(c) for c in txns.columns]   # ignore stray spaces and case in headers
    if txns.columns.duplicated().any():
        raise ValueError("Extract has duplicate column names: "
                         f"{sorted(set(txns.columns[txns.columns.duplicated()]))}")
    sheets = pd.read_excel(mapping_file, sheet_name=[SHEET_P1, SHEET_P2, SHEET_LISTS], **read)

    rules, lists = load_mapping(sheets[SHEET_P1], sheets[SHEET_P2], sheets[SHEET_LISTS],
                                txns.columns)
    report = summarise(apply_rules(build_hits(txns, rules), lists), txns)
    try:
        report.to_csv(output_file, index=False)
    except PermissionError:
        raise PermissionError(f"Can't write {output_file}. If it's open in Excel, "
                              "close it and run again.") from None

    counts = report["DISPOSITION"].value_counts()
    summary = ", ".join(f"{label} {n}" for label, n in counts.items())
    print(f"Saved {len(report)} transactions with keyword hits to {output_file}"
          + (f" ({summary})" if summary else ""))
    return report


# ---------------------------------------------------------------------------
# Built-in test cases
# ---------------------------------------------------------------------------
def _demo():
    p1 = pd.DataFrame({
        "RT Type": ["RT1", "RT1", "RT2"],
        "Countries": ["ZZ", "QQ", "QQ, QM"],   # one code per row, or several in a cell
    })
    p2 = pd.DataFrame({                         # Excel rows 2 to 8
        "RT Type": ["RT1", "RT1", "RT2", "RT1", "RT1", "RT1", "RT1"],
        "Keyword": ["FALCON", "FALCON", "FALCON", "ZEPHYR", "ORCHID", "LOTUS", "ON-SURYA"],
        "Message": ["ORIGINATOR_NAME, BENEFICIARY_NAME", "BENEFICIARY_ADDRESS",
                    "BENEFICIARY_NAME", "ORIGINATOR_NAME", "BENEFICIARY_NAME",
                    "BENEFICIARY_NAME", "BENEFICIARY_NAME"],
        "Rules": ["EXCL_INDIV, EXCL_IN_RELIGIOUS", "EXCL_ON_TOPONYM", "", "",
                  "EXCL_IN_SECULAR", "", ""],
        "Status": ["ACTIVE", "ACTIVE", "ACTIVE", "ACTIVE", "ACTIVE", "INACTIVE", "ACTIVE"],
    })
    intel = pd.DataFrame({
        "List": ["TOPONYM", "TOPONYM", "TOPONYM", "TOPONYM", "RELIGIOUS", "SECULAR"],
        # the third value has a non-breaking space, the fourth is the keyword itself
        "Value": ["FALCONVILLE", "FALCON RIDGE", "FALCON\u00A0HEIGHTS", "FALCON",
                  "FALCON ABBEY", "ORCHIDEA"],
        "Status": ["ACTIVE", "INACTIVE", "ACTIVE", "ACTIVE", "ACTIVE", "ACTIVE"],
    })

    base = {"ORIGINATOR_NAME": "ACME LTD", "ORIGINATOR_NAME_1": "", "ENTITY_TYPE_ORG": "CORP",
            "BENEFICIARY_NAME": "BETA SARL", "BENEFICIARY_ADDRESS": "5 PARK RD",
            "ENTITY_TYPE_BENE": "CORP",
            "ORIGINATOR_FI_ORG_KEY": "ABCD", "ORIGINATOR_FI_COUNTRY_CD": "ZZ",
            "BENEFICIARY_FI_ORG_KEY": "WXYZ", "BENEFICIARY_FI_COUNTRY_CD": "XX"}
    one_side = "EXCLUDED" if EXCLUDE_WHEN == "either" else "SUSPICIOUS"
    cases = [
        # key, how it differs from base, expected decision (None: no hit, not in report)
        # EXCL_INDIV
        ("T1", {"BENEFICIARY_NAME": "JOHN FALCON", "ENTITY_TYPE_BENE": "INDIV"}, "CLEARED"),
        ("T2", {"BENEFICIARY_NAME": "FALCON TRADING LLC"}, "SUSPICIOUS"),          # CORP
        ("T3", {"BENEFICIARY_NAME": "JOHN FALCON", "ENTITY_TYPE_BENE": ""}, "SUSPICIOUS"),
        ("T4", {"ORIGINATOR_NAME": "JOHN FALCON", "ENTITY_TYPE_ORG": "",
                "ENTITY_TYPE_BENE": "INDIV"}, "SUSPICIOUS"),   # the beneficiary's INDIV doesn't count
        # Intelligence_List rules
        ("T5", {"BENEFICIARY_ADDRESS": "12 MAIN ST, FALCONVILLE"}, "CLEARED"),
        ("T6", {"BENEFICIARY_ADDRESS": "FALCON HOUSE, FALCONVILLE"}, "SUSPICIOUS"),  # 1 of 2 inside
        ("T7", {"BENEFICIARY_ADDRESS": "5 FALCON RIDGE"}, "SUSPICIOUS"),        # toponym INACTIVE
        ("T8", {"BENEFICIARY_NAME": "FALCON ABBEY TRUST"}, "CLEARED"),           # religious value
        ("T9", {"BENEFICIARY_NAME": "ORCHIDEA FLOWERS LTD"}, "CLEARED"),         # secular value
        # P1 countries and P2 rows
        ("T10", {"BENEFICIARY_NAME": "JOHN FALCON", "ENTITY_TYPE_BENE": "INDIV",
                 "ORIGINATOR_FI_COUNTRY_CD": "QQ"}, "SUSPICIOUS"),  # RT2 row has no rule
        ("T11", {"ORIGINATOR_NAME": "ZEPHYR KAHN"}, "SUSPICIOUS"),  # no rule
        ("T12", {"BENEFICIARY_NAME": "LOTUS LTD"}, None),           # P2 row INACTIVE
        ("T13", {"BENEFICIARY_NAME": "FALCON TRADING LLC",
                 "ORIGINATOR_FI_COUNTRY_CD": "XQ"}, None),          # country not in P1
        # keyword searched exactly as written
        ("T14", {"BENEFICIARY_NAME": "ON-SURYA TRADING"}, "SUSPICIOUS"),
        ("T15", {"BENEFICIARY_NAME": "ON SURYA TRADING"}, None),
        ("T16", {"BENEFICIARY_NAME": "ONSURYA TRADING"}, None),
        # BNPAFR exclusion
        ("T17", {"BENEFICIARY_NAME": "FALCON TRADING LLC", "ORIGINATOR_FI_ORG_KEY": "BNPA",
                 "ORIGINATOR_FI_COUNTRY_CD": "FR", "BENEFICIARY_FI_COUNTRY_CD": "ZZ"}, one_side),
        ("T18", {"BENEFICIARY_NAME": "FALCON TRADING LLC", "ORIGINATOR_FI_ORG_KEY": "BNPA",
                 "ORIGINATOR_FI_COUNTRY_CD": "DE", "BENEFICIARY_FI_COUNTRY_CD": "ZZ"},
         "SUSPICIOUS"),                                             # BNPADE isn't excluded
        ("T19", {"BENEFICIARY_NAME": "FALCON TRADING LLC", "BENEFICIARY_FI_ORG_KEY": "BNPA",
                 "BENEFICIARY_FI_COUNTRY_CD": "FR"}, one_side),
        # ORIGINATOR_NAME_1: searched whenever ORIGINATOR_NAME is listed, uses ENTITY_TYPE_ORG
        ("T20", {"ORIGINATOR_NAME": "JOHN", "ORIGINATOR_NAME_1": "FALCON",
                 "ENTITY_TYPE_ORG": "INDIV"}, "CLEARED"),
        ("T21", {"ORIGINATOR_NAME": "GLOBAL", "ORIGINATOR_NAME_1": "FALCON TRADING LLC"},
         "SUSPICIOUS"),
        # look-alike characters, and a list value that is just the keyword
        ("T22", {"BENEFICIARY_ADDRESS": "7 FALCON HEIGHTS"}, "CLEARED"),  # value had a no-break space
        ("T23", {"BENEFICIARY_NAME": "ON\u2013SURYA TRADING"}, "SUSPICIOUS"),  # en dash = hyphen
        ("T24", {"BENEFICIARY_ADDRESS": "FALCON STREET"}, "SUSPICIOUS"),  # TOPONYM 'FALCON' can't clear
    ]
    txns = pd.DataFrame([{KEY: key, **base, **changes} for key, changes, _ in cases])
    expected = {key: decision for key, _, decision in cases if decision}

    rules, lists = load_mapping(p1, p2, intel, txns.columns)
    hits = apply_rules(build_hits(txns, rules), lists)
    report = summarise(hits, txns)
    pd.set_option("display.max_colwidth", None)
    pd.set_option("display.width", 400)
    print(report[[KEY] + OUTPUT_COLUMNS].to_string(index=False))

    got = transaction_outcomes(hits, txns)["outcome"].to_dict()
    assert got == expected, f"Unexpected outcomes: {got}"

    # Output columns: their order, and the values for a few typical cases
    assert list(report.columns) == list(txns.columns) + OUTPUT_COLUMNS
    rows = report.set_index(KEY)

    def check(key, keyword, rt_type, iso, outcome, rule_applied):
        disposition, flagged = OUTPUT_LABELS[outcome]
        actual = rows.loc[key, OUTPUT_COLUMNS].tolist()
        assert actual == [keyword, rt_type, iso, disposition, rule_applied, flagged], (key, actual)

    check("T1", "FALCON", "RT1", "ZZ", "CLEARED", "EXCL_INDIV")
    check("T2", "FALCON", "RT1", "ZZ", "SUSPICIOUS", "")
    check("T8", "FALCON", "RT1", "ZZ", "CLEARED", "EXCL_IN_RELIGIOUS")
    check("T10", "FALCON", "RT2", "QQ", "SUSPICIOUS", "")   # only the RT2 hit is left
    if EXCLUDE_WHEN == "either":
        check("T17", "FALCON", "RT1", "ZZ", "EXCLUDED", "BNPAFR")
    print(f"\nAll {len(cases)} demo cases behave as expected (EXCLUDE_WHEN = '{EXCLUDE_WHEN}').")


if __name__ == "__main__":
    if "--demo" in sys.argv[1:]:
        _demo()
    else:
        run()
