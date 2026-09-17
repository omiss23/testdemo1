"""
FT IR-1 keyword screening driven by the mapping workbook.

Mapping workbook
  P1                 RT Type, Countries
  P2                 RT Type, Keyword, Message, Rules, Status
  Intelligence_List  List (TOPONYM, SECULAR, RELIGIOUS), Value, Status

How the sheets combine
  Each ACTIVE row in P2 is one screening rule:
    - search its Keyword in every column listed in its Message cell
    - only in transactions where an FI country code is in the Countries
      that P1 gives for the row's RT Type
    - check each hit against the row's Rules (comma separated, or blank)
  Keywords are searched exactly as written, ignoring only upper/lower case and
  spaces at either end: ON-SURYA matches ON-SURYA, not ONSURYA or ON SURYA.
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
                      list rules count together.

Transaction-level decision
  EXCLUDED     an FI code is BNPAFR (see EXCLUDE_WHEN). Each FI code is its
               4-character FI_ORG_KEY plus its 2-character FI_COUNTRY_CD.
  SUSPICIOUS   otherwise, if any hit is FLAG
  CLEARED      otherwise

Usage
  1. Set INPUT_FILE, MAPPING_FILE and OUTPUT_FILE in the "File paths" section below
  2. Run:  python ft_ir1_name_rules.py          (or press Run in your editor)
     Test: python ft_ir1_name_rules.py --demo   (runs the built-in test cases)
"""
import os
import re
import sys
import unicodedata

import pandas as pd

# ---------------------------------------------------------------------------
# File paths: edit these three lines
# Keep the r before each opening quote so Windows backslashes are read as-is.
# ---------------------------------------------------------------------------
INPUT_FILE = r"C:\FT_IR_1\input\transactions.csv"            # transaction extract (CSV)
MAPPING_FILE = r"C:\FT_IR_1\mapping\FT_IR_1_mapping.xlsx"    # sheets P1, P2, Intelligence_List
OUTPUT_FILE = r"C:\FT_IR_1\output\final_threat_report.csv"   # overwritten on each run

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
KEY = "MESSAGE_KEY"

# Party name columns (exact extract names), each with its party's entity type column
ENTITY_TYPE_FOR = {
    "ORIGINATOR_NAME": "ENTITY_TYPE_ORG",
    "ORIGINATOR_NAME_1": "ENTITY_TYPE_ORG",
    "BENEFICIARY_NAME": "ENTITY_TYPE_BENE",
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

SHEET_P1, SHEET_P2, SHEET_LISTS = "P1", "P2", "Intelligence_List"
COUNTRY_CODE_RE = r"^[A-Z]{2}$"
SPLIT_RE = r"[,;|\n]+"    # separators allowed inside Message, Countries and Rules cells

# Characters that look like a hyphen or a space but aren't, such as the en dash
# Excel can swap in. A keyword or list value containing one would never match.
LOOKALIKE_RE = r"[\u00A0\u00AD\u200B-\u200D\u2010-\u2015\u2060\u2212\uFE63\uFEFF\uFF0D]"


def _upper(s):
    return s.fillna("").astype(str).str.strip().str.upper()


def _split(cell):
    return [p.strip() for p in re.split(SPLIT_RE, str(cell)) if p.strip()]


def _lookalikes(text):
    return [unicodedata.name(ch, f"U+{ord(ch):04X}")
            for ch in dict.fromkeys(re.findall(LOOKALIKE_RE, text))]


def _columns(df, sheet, required):
    """Find the required headers, ignoring case and stray spaces, and drop
    completely blank rows."""
    lookup = {str(c).strip().upper(): c for c in df.columns}
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

    needed = ([KEY] + ISO_COLUMNS + list(ENTITY_TYPE_FOR.values())
              + [col for parts in FI_CODE_PARTS.values() for col in parts])
    missing = [c for c in dict.fromkeys(needed) if c not in extract_columns]
    if missing:
        problems.append(f"Extract is missing columns: {missing}")
    if EXCLUDE_WHEN not in ("either", "both"):
        problems.append(f"EXCLUDE_WHEN must be 'either' or 'both', not '{EXCLUDE_WHEN}'")

    # Intelligence_List: list name -> ACTIVE values
    lists = {name: set() for name in LIST_RULES.values()}
    for i, row in _active_rows(intel, SHEET_LISTS, problems).iterrows():
        name = str(row["List"]).strip().upper()
        value = str(row["Value"]).strip().upper()
        odd_chars = _lookalikes(value)
        if name not in lists:
            problems.append(f"{SHEET_LISTS} row {i + 2}: List '{name}' is not one of {list(lists)}")
        elif not value:
            problems.append(f"{SHEET_LISTS} row {i + 2}: Value is blank")
        elif odd_chars:
            problems.append(f"{SHEET_LISTS} row {i + 2}: Value '{value}' contains {odd_chars}, "
                            "which only looks like a normal hyphen or space")
        else:
            lists[name].add(value)

    # P1: RT Type -> country codes (one code per row, or several in a cell)
    countries = {}
    for i, row in p1.iterrows():
        rt = str(row["RT Type"]).strip().upper()
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
    by_upper = {str(c).strip().upper(): c for c in extract_columns}
    rules, missing_together = [], set()
    for i, row in _active_rows(p2, SHEET_P2, problems).iterrows():
        where = f"P2 row {i + 2}"
        rt = str(row["RT Type"]).strip().upper()
        keyword = str(row["Keyword"]).strip().upper()   # hyphens and all other characters kept
        row_rules = list(dict.fromkeys(r.upper() for r in _split(row["Rules"])))
        listed = _split(row["Message"])
        found = [by_upper.get(c.upper()) for c in listed]

        odd_chars = _lookalikes(keyword)
        if not keyword:
            problems.append(f"{where}: Keyword is blank")
        elif odd_chars:
            problems.append(f"{where}: Keyword '{keyword}' contains {odd_chars}, which only "
                            "looks like a normal hyphen or space, so it would never match")
        if not countries.get(rt):
            problems.append(f"{where}: RT Type '{rt}' has no countries in P1")
        if not listed:
            problems.append(f"{where}: Message lists no columns")
        unknown = [c for c, f in zip(listed, found) if f is None]
        if unknown:
            problems.append(f"{where}: Message columns not in the extract: {unknown}")
        columns = _search_together([f for f in found if f], by_upper, missing_together)
        bad = [r for r in row_rules if r not in KNOWN_RULES]
        if bad:
            problems.append(f"{where}: Rules not recognised: {bad}")
        for r in row_rules:
            name = LIST_RULES.get(r)
            if name and not lists[name]:
                problems.append(f"{where}: {r} needs {name} values, but "
                                f"{SHEET_LISTS} has no ACTIVE {name} rows")
            elif name and keyword in lists[name]:
                problems.append(f"{where}: {name} value '{keyword}' is the keyword itself, "
                                f"so {r} would clear every {keyword} hit")

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
    """Count the keyword's occurrences in the text, and how many of them sit
    inside an occurrence of one of the given (list, value) pairs."""
    starts = _starts(text, keyword)
    inside, used = set(), []
    for name, value in values:
        for v in _starts(text, value):
            covered = {s for s in starts if v <= s and s + len(keyword) <= v + len(value)}
            if covered:
                inside |= covered
                label = f"{name} '{value}'"
                if label not in used:
                    used.append(label)
    return len(starts), len(inside), used


def decide(hit, candidates):
    """CLEAR if any one of the hit's rules clears it, otherwise FLAG.
    Returns (decision, explanation)."""
    rules = [r for r in hit["rules"].split(",") if r]
    if not rules:
        return "FLAG", "no rule"
    keyword, col = hit["keyword"], hit["matched_column"]
    cleared, notes = False, []

    if INDIV_RULE in rules:
        type_col = ENTITY_TYPE_FOR.get(col)
        etype = hit["entity_type"]
        if type_col is None:
            notes.append(f"{INDIV_RULE} not applicable, not a name column")
        elif etype == "INDIV":
            cleared = True
            notes.append(f"{INDIV_RULE} cleared, {type_col}=INDIV")
        elif etype == "CORP":
            notes.append(f"{INDIV_RULE} not cleared, {type_col}=CORP")
        else:
            notes.append(f"{INDIV_RULE} not applied, {type_col}={etype or 'blank'}")

    list_rules = [r for r in rules if r in LIST_RULES]
    if list_rules:
        values = [(LIST_RULES[r], v) for r in list_rules
                  for v in candidates[(keyword, LIST_RULES[r])]]
        total, inside, used = _inside_listed_values(hit["text"], keyword, values)
        label = "+".join(list_rules)
        if total and inside == total:
            cleared = True
            notes.append(f"{label} cleared, every {keyword} inside {', '.join(used)}")
        elif inside:
            notes.append(f"{label} not cleared, only {inside} of {total} {keyword} "
                         f"inside {', '.join(used)}")
        else:
            notes.append(f"{label} not cleared, {keyword} not inside a listed value")

    return ("CLEAR" if cleared else "FLAG"), "; ".join(notes)


def apply_rules(hits, lists):
    h = hits.copy()
    # Only list values that contain the keyword can ever clear it
    candidates = {(kw, name): [v for v in values if kw in v]
                  for kw in h["keyword"].unique() for name, values in lists.items()}
    results = [decide(hit, candidates) for hit in h.to_dict("records")]
    h["hit_decision"] = [d for d, _ in results]
    h["explanation"] = [e for _, e in results]
    return h


# ---------------------------------------------------------------------------
# 4. One row per transaction, with the reason for every hit
# ---------------------------------------------------------------------------
def _join_sorted(values):
    return "; ".join(sorted({v for v in values if v}))


def _join_codes(values):
    return ", ".join(sorted({c for v in values for c in v.split(",") if c}))


def _join_in_order(values):
    return "; ".join(dict.fromkeys(v for v in values if v))


def _fi_exclusion(df):
    """(excluded, reason) per transaction for the FI code exclusion (BNPAFR)."""
    matches, labels = [], []
    for side, (org_col, country_col) in FI_CODE_PARTS.items():
        org, country = _upper(df[org_col]), _upper(df[country_col])
        code = (org + country).where(org.str.len().eq(4) & country.str.len().eq(2), "")
        match = code.isin(EXCLUDED_FI_CODES)
        matches.append(match)
        labels.append((side + "=" + code).where(match, ""))
    matches = pd.concat(matches, axis=1)
    excluded = matches.all(axis=1) if EXCLUDE_WHEN == "both" else matches.any(axis=1)
    reason = pd.concat(labels, axis=1).apply(lambda r: "; ".join(v for v in r if v), axis=1)
    return excluded, reason.where(excluded, "")


def summarise(h, txns):
    extra = ["decision", "excluded_reason", "flagged_keywords", "flagged_rt_types",
             "flagged_countries", "hit_details"]
    if h.empty:
        return txns.iloc[0:0].assign(**{c: "" for c in extra})

    h = h.sort_values(["p2_row", "matched_column"], kind="stable")
    h = h.assign(detail="P2 row " + h["p2_row"].astype(str) + " (" + h["rt_type"] + "): "
                 + h["keyword"] + " in " + h["matched_column"] + ", "
                 + h["explanation"] + " -> " + h["hit_decision"])
    flagged = h[h["hit_decision"] == "FLAG"]

    report = pd.DataFrame({
        "decision": h["hit_decision"].eq("FLAG").groupby(h[KEY]).any()
                    .map({True: "SUSPICIOUS", False: "CLEARED"}),
        "flagged_keywords": flagged.groupby(KEY)["keyword"].agg(_join_sorted),
        "flagged_rt_types": flagged.groupby(KEY)["rt_type"].agg(_join_sorted),
        "flagged_countries": flagged.groupby(KEY)["countries"].agg(_join_codes),
        "hit_details": h.groupby(KEY, sort=False)["detail"].agg(_join_in_order),
    }).fillna("")
    report.index.name = KEY
    out = txns.merge(report.reset_index(), on=KEY, how="inner")

    excluded, reason = _fi_exclusion(out)
    out["decision"] = out["decision"].where(~excluded, "EXCLUDED")
    out.insert(out.columns.get_loc("decision") + 1, "excluded_reason", reason)
    return out


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
    sheets = pd.read_excel(mapping_file, sheet_name=[SHEET_P1, SHEET_P2, SHEET_LISTS], **read)

    rules, lists = load_mapping(sheets[SHEET_P1], sheets[SHEET_P2], sheets[SHEET_LISTS],
                                txns.columns)
    report = summarise(apply_rules(build_hits(txns, rules), lists), txns)
    try:
        report.to_csv(output_file, index=False)
    except PermissionError:
        raise PermissionError(f"Can't write {output_file}. If it's open in Excel, "
                              "close it and run again.") from None

    counts = report["decision"].value_counts()
    summary = ", ".join(f"{d} {counts.get(d, 0)}" for d in ["SUSPICIOUS", "CLEARED", "EXCLUDED"])
    print(f"Saved {len(report)} transactions with keyword hits to {output_file} ({summary})")
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
        "List": ["TOPONYM", "TOPONYM", "RELIGIOUS", "SECULAR"],
        "Value": ["FALCONVILLE", "FALCON RIDGE", "FALCON ABBEY", "ORCHIDEA"],
        "Status": ["ACTIVE", "INACTIVE", "ACTIVE", "ACTIVE"],
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
    ]
    txns = pd.DataFrame([{KEY: key, **base, **changes} for key, changes, _ in cases])
    expected = {key: decision for key, _, decision in cases if decision}

    rules, lists = load_mapping(p1, p2, intel, txns.columns)
    report = summarise(apply_rules(build_hits(txns, rules), lists), txns)
    pd.set_option("display.max_colwidth", None)
    pd.set_option("display.width", 400)
    print(report[[KEY, "decision", "excluded_reason", "hit_details"]].to_string(index=False))

    got = dict(zip(report[KEY], report["decision"]))
    assert got == expected, f"Unexpected decisions: {got}"
    print(f"\nAll {len(cases)} demo cases behave as expected (EXCLUDE_WHEN = '{EXCLUDE_WHEN}').")


if __name__ == "__main__":
    if "--demo" in sys.argv[1:]:
        _demo()
    else:
        run()
