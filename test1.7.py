#!/usr/bin/env python3
"""
Transaction monitoring - keyword screening with per-keyword, per-column rules.

    python tm_screening.py
    python tm_screening.py --transactions aug.csv --output output/aug.csv

FILES  (paths and sheet names are all declared in the CONFIG block below)
    mapping.xlsx            maintained by compliance - what to look for
        Sheet P1 : RT Type | Countries            codes that put a flow in scope
        Sheet P2 : RT Type | Keyword | Message | Rules
                     Message = columns to search, comma separated
                     Rules   = rules for that keyword, comma separated (may be blank)
                   An optional Status column (ACTIVE/INACTIVE) is honoured.

    intelligence_list.xlsx  maintained by compliance - what things mean
        One sheet, one row per value:
            List      | Value       | Status | Source
            TOPONYM   | ISLAMABAD   | ACTIVE | FP review Jul-26
            SECULAR   | GALA        | ACTIVE |
        List   = the list name, used in a rule as ON_<LIST> or IN_<LIST>
        Value  = the entry
        Status = optional, ACTIVE/INACTIVE
        Any other column (Source, Added By, Date) is ignored and is a good place
        to record where an entry came from.
        Type a new name in the List column and it is usable in a rule at once.

SCOPE
    A flow is screened only if a country code in COUNTRY_COLS matches the P1 list
    for that RT Type, AND neither side's financial institution is one of
    EXCLUDED_INSTITUTIONS. The institution filter runs before any keyword is
    searched, so no rule can bring those flows back - the count is printed in the
    run summary.

TWO DIFFERENT THINGS DECIDE WHICH COLUMNS MATTER
    Message in P2   which columns are SEARCHED for that keyword
    COLUMN_TAGS     which of the resulting hits a rule is allowed to act on

    A column that is tagged but never searched will never produce a hit, so a
    rule pointing at it can never fire. The script warns about both mismatches
    at startup.

RULE GRAMMAR
    ACTION _ TEST _ COLUMN : ARGS          every part after ACTION is optional

    ACTION   EXCL    do not flag this hit
             RETAIN  flag it, stop checking further rules
             REVIEW  send to an analyst instead of dropping

    COLUMN   the suffix that limits the rule to one side of the payment.
             PM = Originator, PP = Beneficiary, REF = reference/description,
             NAME = both party names.
             NO SUFFIX means every column the keyword was searched in. That is
             usually what you want for a rule written without a side, e.g.
             "exclude surnames containing ARYAN" -> EXCL_SURNAME.
             A tag can cover several columns - see COLUMN_TAGS below.

    TEST     (none)        the keyword is in that column, nothing else needed
             STRADDLE      the match spans two words    CRISTAL HOLDING -> "AL HOL"
             PART_OF_WORD  the match sits inside a word ISLAMABAD, GAZAN, AFGHANATAN
             SURNAME       the match is in the surname  MEHMET KURDOGLU
                           only ever fires on NAME_COLUMNS, so EXCL_SURNAME with
                           no suffix safely means "either party's surname"
             CONTAINS:A|B  the column contains any of these words
             ON_<LIST>     THE KEYWORD ITSELF is an entry on that list, or sits
                           inside one.   GAZA on TOPONYM, ISLAM inside ISLAMABAD
             IN_<LIST>     SOMETHING ELSE in the column is on that list.
                           EVENT in "MONACO CHARITY EVENT" is on SECULAR

             ON and IN are not interchangeable - see the note at the bottom.

    Rules are checked LEFT TO RIGHT and the first one that fires decides the hit,
    so put RETAIN rules first. If nothing fires, the hit is flagged.
    WORD_ONLY anywhere in the cell switches that keyword to whole-word matching.

    Examples
        EXCL_PP                        keyword in the beneficiary name -> do not flag
        EXCL_SURNAME_PP                only when it is the beneficiary's surname
        EXCL_STRADDLE_PM               only the CRISTAL HOLDING style noise, originator side
        EXCL_ON_TOPONYM                the keyword is a place name
        EXCL_IN_BANK_PP                the beneficiary is a banking institution
        EXCL_CONTAINS_PM:HOLDING|LLC   originator name contains either word
        RETAIN_REF                     always flag when it is in the reference

OUTPUT
    One CSV, one row per hit, with DISPOSITION (ALERT / REVIEW / EXCLUDED), the
    RULE_APPLIED, and FLAGGED. FLAGGED is decided per MESSAGE_KEY: N only when
    every hit on that message was excluded - a hit surviving in another column
    still flags the message. Filter on FLAGGED = Y for the report.

ON vs IN
    ON asks "is the keyword itself this kind of thing?"
    IN asks "is there something of this kind nearby?"
    Use ON for TOPONYM. "AL HOL TRADING, KARACHI" contains a place name, but the
    keyword is not the place - IN_TOPONYM would wrongly suppress it, ON_TOPONYM
    keeps it. Use IN for context lists like SECULAR, RELIGIOUS and BANK, where
    the point is what surrounds the keyword.
"""

import argparse
import re
import sys
import unicodedata
from pathlib import Path

import pandas as pd

# ----------------------------------------------------------------------------
# CONFIG - edit to match your files
# ----------------------------------------------------------------------------
TRANSACTIONS_FILE = "transactions.csv"
MAPPING_FILE = "mapping.xlsx"
INTELLIGENCE_FILE = "intelligence_list.xlsx"
OUTPUT_FILE = "screening_output.csv"

# --- sheet names -------------------------------------------------------------
SHEET_COUNTRIES = "P1"          # RT Type | Countries
SHEET_KEYWORDS = "P2"           # RT Type | Keyword | Message | Rules
SHEET_INTELLIGENCE = "Lists"    # List | Value | Status

# --- sheet headers -----------------------------------------------------------
COL_RT, COL_COUNTRIES = "RT Type", "Countries"
COL_KEYWORD, COL_MESSAGE, COL_RULES, COL_STATUS = "Keyword", "Message", "Rules", "Status"
COL_LIST, COL_VALUE = "List", "Value"

# --- transaction file columns ------------------------------------------------
ID_COL = "MESSAGE_KEY"

COUNTRY_COLS = ["ORIGINATOR_COUNTRY", "BENEFICIARY_COUNTRY",
                "ORIGINATOR_FI_COUNTRY_CD", "BENEFICIARY_FI_COUNTRY_CD"]

# Which columns each rule suffix covers. A tag may list SEVERAL columns - useful
# when the originator or beneficiary is spread over name + address lines:
#     "PM": ["ORIGINATOR_NAME", "ORIGINATOR_ADDRESS"],
# These only decide which hits a tagged rule acts on. What actually gets searched
# is the Message column in P2.
COLUMN_TAGS = {
    "PM": ["ORIGINATOR_NAME"],                      # Originator
    "PP": ["BENEFICIARY_NAME"],                     # Beneficiary
    "REF": ["REMITTANCE_INFO", "PAYMENT_DETAILS"],  # reference / description
    "NAME": ["ORIGINATOR_NAME", "BENEFICIARY_NAME"],  # both parties, for rules that
                                                    # do not care which side it is
}
# A column may appear under several tags. The FIRST tag listing it is the one
# shown in the TAG column of the output, so keep the specific tags above the
# group ones.

# Columns holding a person or entity name. The SURNAME test only runs on these.
NAME_COLUMNS = ["ORIGINATOR_NAME", "BENEFICIARY_NAME"]

# Output shape. Every column of the input row is written, then KEYWORD, then
# DISPOSITION, RULE_APPLIED and FLAGGED.
OUTPUT_ONLY_FLAGGED = False     # True = write only rows where FLAGGED is Y
INCLUDE_MATCH_DETAIL = False    # True = also write the diagnostic columns below
MATCH_DETAIL_COLUMNS = ["RT_TYPE", "MATCH", "COLUMN", "TAG", "SHAPE", "SCOPE_COUNTRY"]

# Flows to or from our own institution are out of scope and are dropped BEFORE
# any keyword is searched - no rule can bring them back.
# Each code is a 6-character BIC+ISO: a 4-character institution key followed by
# a 2-character country code, e.g. BNPA + FR = BNPAFR (BNP Paribas SA).
EXCLUDED_INSTITUTIONS = ["BNPAFR"]          # [] = do not filter on institution
FI_KEY_PAIRS = [                            # (institution key column, country code column)
    ("ORIGINATOR_FI_ORG_KEY", "ORIGINATOR_FI_COUNTRY_CD"),
    ("BENEFICIARY_FI_ORG_KEY", "BENEFICIARY_FI_COUNTRY_CD"),
]

PARTICLES = {"AL", "EL", "BEN", "BIN", "IBN", "ABU", "DE", "DA", "DI", "VAN", "VON", "DER", "LA"}
SPLIT_RE = re.compile(r"[,;/|\n]+")

ACTIONS = {"EXCL": "EXCLUDED", "RETAIN": "ALERT", "REVIEW": "REVIEW"}
BUILTIN_TESTS = {"", "STRADDLE", "PART_OF_WORD", "SURNAME", "CONTAINS"}

LISTS = {}     # list name -> compiled regex, loaded from the intelligence file
LIST_SIZE = {}


# ----------------------------------------------------------------------------
# text helpers
# ----------------------------------------------------------------------------
def norm(value):
    """Uppercase, strip accents and punctuation, collapse spaces."""
    if value is None:
        return ""
    text = str(value)
    if not text or text.lower() in ("nan", "none"):
        return ""
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c)).upper()
    return re.sub(r"\s+", " ", re.sub(r"[^0-9A-Z ]+", " ", text)).strip()


def build_pattern(keyword, word_only):
    core = r"\s*".join(re.escape(t) for t in keyword.split())
    if word_only:
        core = r"(?<![0-9A-Z])" + core + r"(?![0-9A-Z])"
    return re.compile(core)


def match_shape(text, start, end):
    """whole | part_of_word (inside one word) | straddle (across two words)."""
    left = start == 0 or text[start - 1] == " "
    right = end == len(text) or text[end] == " "
    if left and right:
        return "whole"
    return "straddle" if " " in text[start:end] else "part_of_word"


def best_match(text, pattern):
    """Best occurrence in the field: a real word beats a fragment beats a straddle."""
    rank = {"whole": 0, "part_of_word": 1, "straddle": 2}
    best = None
    for m in pattern.finditer(text):
        shape = match_shape(text, m.start(), m.end())
        if best is None or rank[shape] < rank[best[2]]:
            best = (m.start(), m.end(), shape, m.group(0))
    return best


def surname_span(name):
    """Char span of the surname: last token plus particles glued to it
    (EL KHOURY, BEN SALMAN, VAN DER BERG)."""
    spans = [(m.start(), m.end()) for m in re.finditer(r"\S+", name)]
    if not spans:
        return (0, 0)
    words = name.split()
    i = len(words) - 1
    while i - 1 >= 1 and words[i - 1] in PARTICLES:
        i -= 1
    return (spans[i][0], spans[-1][1])


def on_list(hit, name):
    """The matched keyword IS an entry on the list, or sits inside one."""
    pattern = LISTS.get(name)
    if not pattern:
        return False
    for m in pattern.finditer(hit["text"]):
        if m.start() <= hit["start"] and m.end() >= hit["end"]:
            return True
    return False


def in_list(hit, name):
    """Something in the column is on the list (it may or may not be the keyword)."""
    pattern = LISTS.get(name)
    return bool(pattern and pattern.search(hit["text"]))


# ----------------------------------------------------------------------------
# intelligence file
# ----------------------------------------------------------------------------
def load_intelligence(path):
    """One sheet, one row per value: List | Value | Status."""
    if not Path(path).exists():
        print(f"WARNING: no intelligence file at {path} - ON_/IN_ rules will not be available")
        return
    book = pd.ExcelFile(path)
    if SHEET_INTELLIGENCE not in book.sheet_names:
        sys.exit(f"ERROR: {path} has no sheet named '{SHEET_INTELLIGENCE}' "
                 f"(it has: {', '.join(book.sheet_names)})")

    frame = book.parse(SHEET_INTELLIGENCE, dtype=str).fillna("")
    absent = [c for c in (COL_LIST, COL_VALUE) if c not in frame.columns]
    if absent:
        sys.exit(f"ERROR: sheet '{SHEET_INTELLIGENCE}' of {path} is missing column(s): {absent}")

    if COL_STATUS in frame.columns:
        status = frame[COL_STATUS].str.strip().str.upper()
        frame = frame[status.eq("") | status.isin(["ACTIVE", "Y", "YES", "1", "TRUE"])]

    grouped = {}
    for list_name, value in zip(frame[COL_LIST], frame[COL_VALUE]):
        name = norm(list_name).replace(" ", "_")
        entry = norm(value)
        if not name or not entry:
            continue
        grouped.setdefault(name, set()).add(entry)

    for name, entries in grouped.items():
        for tag in COLUMN_TAGS:
            if name.endswith("_" + tag):
                sys.exit(f"ERROR: list '{name}' ends with the column tag '{tag}' - rename it, "
                         f"it would be unreadable in a rule name")
        ordered = sorted(entries, key=len, reverse=True)
        LISTS[name] = re.compile(
            r"(?<![0-9A-Z])(?:" + "|".join(re.escape(e) for e in ordered) + r")(?![0-9A-Z])")
        LIST_SIZE[name] = len(ordered)

    if not LISTS:
        print(f"WARNING: no values loaded from sheet '{SHEET_INTELLIGENCE}' of {path}")


def check_lists(keywords):
    """A list nobody references usually means a typo in the List column -
    the entries went to a new list instead of the one that was meant."""
    used = set()
    for spec in keywords:
        for _action, test, _tag, _args in spec["rules"]:
            if test.startswith(("ON_", "IN_")):
                used.add(test[3:])
    for name in sorted(set(LISTS) - used):
        print(f"WARNING: list '{name}' has {LIST_SIZE[name]} value(s) but no rule uses it - "
              f"check the {COL_LIST} column for a typo")


# ----------------------------------------------------------------------------
# rules
# ----------------------------------------------------------------------------
def parse_rule(token, where):
    """'EXCL_SURNAME_PP' -> ('EXCL', 'SURNAME', 'PP', []).
       'EXCL_ON_TOPONYM'  -> ('EXCL', 'ON_TOPONYM', '', [])"""
    name, _, arg = token.partition(":")
    name = name.strip().upper()
    args = [a.strip().upper() for a in arg.split("|") if a.strip()]

    tag = ""
    for candidate in sorted(COLUMN_TAGS, key=len, reverse=True):
        if name.endswith("_" + candidate):
            name, tag = name[: -(len(candidate) + 1)], candidate
            break

    action, _, test = name.partition("_")
    if action not in ACTIONS:
        raise ValueError(f"'{action}' is not a valid action - use EXCL, RETAIN or REVIEW")

    if test.startswith(("ON_", "IN_")):
        list_name = test[3:]
        if list_name not in LISTS:
            known = ", ".join(sorted(LISTS)) or "none loaded"
            raise ValueError(f"list '{list_name}' is not in the {COL_LIST} column of {where} "
                             f"(available: {known})")
    elif test in LISTS:
        raise ValueError(f"'{test}' is a list - write ON_{test} (the keyword is one) "
                         f"or IN_{test} (something else in the column is one)")
    elif test not in BUILTIN_TESTS:
        raise ValueError(f"'{test}' is not a valid test for {action}")

    if test == "CONTAINS" and not args:
        raise ValueError("CONTAINS needs arguments, e.g. EXCL_CONTAINS_PM:HOLDING|LLC")
    return action, test, tag, args


def parse_rules(cell, where):
    rules, word_only = [], False
    for token in str(cell or "").split(","):
        token = token.strip()
        if not token or token.lower() in ("nan", "none"):
            continue
        if token.upper() == "WORD_ONLY":
            word_only = True
            continue
        rules.append(parse_rule(token, where))
    return rules, word_only


def rule_fires(test, tag, args, hit):
    # the column suffix decides whether this rule looks at this hit at all
    if tag and hit["field"] not in COLUMN_TAGS[tag]:
        return False
    if test == "":
        return True
    if test == "STRADDLE":
        return hit["shape"] == "straddle"
    if test == "PART_OF_WORD":
        return hit["shape"] == "part_of_word"
    if test == "SURNAME":
        return hit["in_surname"]
    if test == "CONTAINS":
        return any(norm(a) in hit["text"] for a in args)
    if test.startswith("ON_"):
        return on_list(hit, test[3:])
    if test.startswith("IN_"):
        return in_list(hit, test[3:])
    return False


def decide(hit, rules):
    """First rule that fires wins. Nothing fires -> the hit is flagged."""
    for action, test, tag, args in rules:
        if rule_fires(test, tag, args, hit):
            return ACTIONS[action], "_".join(p for p in (action, test, tag) if p)
    return "ALERT", ""


# ----------------------------------------------------------------------------
# mapping
# ----------------------------------------------------------------------------
def load_mapping(path, intelligence_path):
    sheets = pd.read_excel(path, sheet_name=[SHEET_COUNTRIES, SHEET_KEYWORDS], dtype=str)
    p1, p2 = sheets[SHEET_COUNTRIES].fillna(""), sheets[SHEET_KEYWORDS].fillna("")

    for sheet, frame, required in ((SHEET_COUNTRIES, p1, [COL_RT, COL_COUNTRIES]),
                                   (SHEET_KEYWORDS, p2, [COL_RT, COL_KEYWORD, COL_MESSAGE])):
        absent = [c for c in required if c not in frame.columns]
        if absent:
            sys.exit(f"ERROR: sheet {sheet} of {path} is missing column(s): {absent}")

    countries = {}
    for _, row in p1.iterrows():
        rt = str(row[COL_RT]).strip()
        if rt:
            codes = {c.strip().upper() for c in SPLIT_RE.split(str(row[COL_COUNTRIES])) if c.strip()}
            countries.setdefault(rt, set()).update(codes)

    keywords = []
    for i, row in p2.iterrows():
        rt, keyword = str(row[COL_RT]).strip(), str(row[COL_KEYWORD]).strip()
        if not rt and keyword:
            print(f"WARNING: {SHEET_KEYWORDS} row {i + 2} ('{keyword}') has no {COL_RT} - row skipped")
        if not rt or not keyword:
            continue
        if COL_STATUS in p2.columns:
            status = str(row[COL_STATUS]).strip().upper()
            if status and status not in ("ACTIVE", "Y", "YES", "1", "TRUE"):
                continue
        try:
            rules, word_only = parse_rules(row[COL_RULES] if COL_RULES in p2.columns else "",
                                           intelligence_path)
        except ValueError as exc:
            sys.exit(f"ERROR in sheet {SHEET_KEYWORDS} row {i + 2} ({keyword}): {exc}")
        keywords.append({
            "rt": rt,
            "keyword": keyword,
            "keyword_norm": norm(keyword),
            "fields": [f.strip() for f in SPLIT_RE.split(str(row[COL_MESSAGE])) if f.strip()],
            "rules": rules,
            "word_only": word_only,
        })

    # an RT Type with no country list can never put a flow in scope, so its
    # keywords would silently never be screened
    orphans = sorted({k["rt"] for k in keywords} - set(countries))
    if orphans:
        sys.exit(f"ERROR: RT Type(s) {orphans} are used in {SHEET_KEYWORDS} but have no countries in "
                 f"{SHEET_COUNTRIES} - those keywords would never be screened. "
                 f"{SHEET_COUNTRIES} has: {', '.join(sorted(countries)) or 'nothing'}")
    for rt in sorted(set(countries) - {k["rt"] for k in keywords}):
        print(f"WARNING: RT Type '{rt}' is in {SHEET_COUNTRIES} but has no active keywords in {SHEET_KEYWORDS}")

    return countries, keywords


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def drop_own_institution(df, transactions_file):
    """Remove flows whose originating or beneficiary FI is one of ours.

    The institution key and the country code live in separate columns and are
    concatenated to a 6-character BIC+ISO: BNPA + FR = BNPAFR.
    """
    if not EXCLUDED_INSTITUTIONS:
        return df, 0

    codes = {re.sub(r"[^0-9A-Z]", "", str(c).upper()) for c in EXCLUDED_INSTITUTIONS}
    missing = sorted({c for pair in FI_KEY_PAIRS for c in pair if c not in df.columns})
    if missing:
        sys.exit(f"ERROR: EXCLUDED_INSTITUTIONS is set but these columns are not in "
                 f"{transactions_file}: {missing}")

    def clean(series):
        return series.map(lambda v: re.sub(r"[^0-9A-Z]", "", str(v).upper()))

    drop = pd.Series(False, index=df.index)
    for key_col, country_col in FI_KEY_PAIRS:
        key, country = clean(df[key_col]), clean(df[country_col])
        odd = key[key.str.len().ne(4) & key.ne("")]
        if len(odd):
            print(f"WARNING: {len(odd):,} value(s) in '{key_col}' are not 4 characters "
                  f"(e.g. {odd.iloc[0]!r}) - the first 4 are used to build the BIC")
        drop |= (key.str[:4] + country.str[:2]).isin(codes)

    return df[~drop].reset_index(drop=True), int(drop.sum())


def check_columns(df, keywords, transactions_file):
    tagged = {col for cols in COLUMN_TAGS.values() for col in cols}
    searched = {f for k in keywords for f in k["fields"]}
    required = {ID_COL, *COUNTRY_COLS, *NAME_COLUMNS, *tagged, *searched}

    missing = sorted(c for c in required if c and c not in df.columns)
    if missing:
        sys.exit(f"ERROR: these columns are not in {transactions_file}: {missing}\n"
                 f"       check ID_COL, COUNTRY_COLS, COLUMN_TAGS and the Message column in "
                 f"{SHEET_KEYWORDS}")

    for col in sorted(tagged - searched):
        tags = [t for t, cols in COLUMN_TAGS.items() if col in cols]
        print(f"WARNING: '{col}' is tagged {tags} but no keyword searches it - "
              f"rules using that tag can never fire on it")
    for col in sorted(searched - tagged):
        print(f"WARNING: '{col}' is searched but has no tag in COLUMN_TAGS - "
              f"only untagged rules will apply to its hits")


def screen(transactions_file, mapping_file, intelligence_file, output_file):
    load_intelligence(intelligence_file)
    countries, keywords = load_mapping(mapping_file, intelligence_file)
    check_lists(keywords)
    df = pd.read_csv(transactions_file, dtype=str, keep_default_na=False).fillna("")
    rows_read = len(df)
    df, dropped = drop_own_institution(df, transactions_file)
    check_columns(df, keywords, transactions_file)

    tag_of = {}
    for tag, cols in COLUMN_TAGS.items():
        for col in cols:
            tag_of.setdefault(col, tag)
    name_cols = set(NAME_COLUMNS)

    text_cols = sorted({f for k in keywords for f in k["fields"]})
    normed = {c: df[c].map(norm) for c in text_cols}

    upper = {c: df[c].str.strip().str.upper() for c in COUNTRY_COLS}
    scope, scope_country = {}, {}
    for rt, codes in countries.items():
        mask = pd.Series(False, index=df.index)
        code_hit = pd.Series("", index=df.index)
        for col in COUNTRY_COLS:
            m = upper[col].isin(codes)
            code_hit = code_hit.where(code_hit.ne("") | ~m, upper[col])
            mask |= m
        scope[rt], scope_country[rt] = mask, code_hit

    rows = []
    for spec in keywords:
        in_scope = scope.get(spec["rt"])
        if in_scope is None or not in_scope.any() or not spec["keyword_norm"]:
            continue
        pattern = build_pattern(spec["keyword_norm"], spec["word_only"])
        for field in spec["fields"]:
            series = normed[field]
            for i in df.index[series.str.contains(pattern.pattern, regex=True) & in_scope]:
                text = series[i]
                found = best_match(text, pattern)
                if not found:
                    continue
                start, end, shape, matched = found
                sur_start, sur_end = surname_span(text) if field in name_cols else (0, 0)
                hit = {
                    "field": field, "text": text, "start": start, "end": end, "shape": shape,
                    "in_surname": start < sur_end and end > sur_start,
                }
                disposition, rule = decide(hit, spec["rules"])
                rows.append({
                    "_row": i,
                    "KEYWORD": spec["keyword"],
                    "RT_TYPE": spec["rt"],
                    "MATCH": matched,
                    "COLUMN": field,
                    "TAG": tag_of.get(field, ""),
                    "SHAPE": shape,
                    "SCOPE_COUNTRY": scope_country[spec["rt"]][i],
                    "DISPOSITION": disposition,
                    "RULE_APPLIED": rule,
                })

    # output = the whole input row, then KEYWORD, then the three decision columns
    added = ["KEYWORD"] + (MATCH_DETAIL_COLUMNS if INCLUDE_MATCH_DETAIL else []) \
        + ["DISPOSITION", "RULE_APPLIED", "FLAGGED"]
    clash = [c for c in added if c in df.columns]
    if clash:
        print(f"WARNING: the input file already has column(s) {clash} - the screening "
              f"version is suffixed '_HIT'")
    rename = {c: f"{c}_HIT" for c in clash}
    DISP, RULE, FLAG = (rename.get(c, c) for c in ("DISPOSITION", "RULE_APPLIED", "FLAGGED"))

    if not rows:
        out = pd.DataFrame(columns=list(df.columns) + [rename.get(c, c) for c in added])
    else:
        hits = pd.DataFrame(rows)
        base = df.loc[hits["_row"]].reset_index(drop=True)
        detail = hits[[c for c in added if c != "FLAGGED"]].reset_index(drop=True)
        out = pd.concat([base, detail.rename(columns=rename)], axis=1)
        # a message survives if any one of its hits was not excluded
        kept = out.groupby(ID_COL)[DISP].transform(lambda s: (s != "EXCLUDED").any())
        out[FLAG] = kept.map({True: "Y", False: "N"})

    written = out[out[FLAG].eq("Y")] if (OUTPUT_ONLY_FLAGGED and len(out)) else out
    written.to_csv(output_file, index=False)

    lists_loaded = ", ".join(f"{n} ({LIST_SIZE[n]})" for n in sorted(LIST_SIZE)) or "none"
    print(f"\nIntelligence lists  : {lists_loaded}")
    print(f"Rows read           : {rows_read:,}")
    if dropped:
        print(f"  dropped as own FI : {dropped:,} ({', '.join(EXCLUDED_INSTITUTIONS)})")
    print(f"Rows screened       : {len(df):,}")
    print(f"Raw hits            : {len(out):,}")
    for disposition in ("ALERT", "REVIEW", "EXCLUDED"):
        print(f"  {disposition:<10}: {(out[DISP] == disposition).sum():,}")
    if len(out):
        flagged = out[out[FLAG] == "Y"][ID_COL].nunique()
        print(f"Messages flagged    : {flagged:,} of {out[ID_COL].nunique():,} with a hit")
        counts = out[out[RULE] != ""][RULE].value_counts()
        if len(counts):
            print("\nDecided by rule:")
            for rule, count in counts.items():
                print(f"  {rule:<24} {count:,}")
    if OUTPUT_ONLY_FLAGGED:
        print(f"\nOUTPUT_ONLY_FLAGGED is on - {len(out) - len(written):,} excluded hit row(s) "
              f"were not written")
    print(f"\nWritten to {output_file}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transactions", default=TRANSACTIONS_FILE)
    parser.add_argument("--mapping", default=MAPPING_FILE)
    parser.add_argument("--intelligence", default=INTELLIGENCE_FILE)
    parser.add_argument("--output", default=OUTPUT_FILE)
    args = parser.parse_args()

    screen(args.transactions, args.mapping, args.intelligence, args.output)
