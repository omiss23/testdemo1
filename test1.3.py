#!/usr/bin/env python3
"""
Transaction monitoring - keyword screening with per-keyword, per-column rules.

    python tm_screening.py
    python tm_screening.py --transactions aug.csv --output output/aug.csv

FILES
    mapping.xlsx            maintained by compliance - what to look for
        Sheet P1 : RT Type | Countries            codes that put a flow in scope
        Sheet P2 : RT Type | Keyword | Message | Rules
                     Message = columns to search, comma separated
                     Rules   = rules for that keyword, comma separated (may be blank)
                   An optional Status column (ACTIVE/INACTIVE) is honoured.

    intelligence_list.xlsx  maintained by compliance - what things mean
        One sheet per list. Sheet name = list name (TOPONYM, SECULAR, BANK...).
        First column = the values. An optional Status column (ACTIVE/INACTIVE)
        is honoured; any other column (Source, Added By, Date) is ignored and is
        a good place to record where an entry came from.
        Add a sheet, and its name is immediately usable in a rule. No code change.

RULE GRAMMAR
    ACTION _ TEST _ COLUMN : ARGS          every part after ACTION is optional

    ACTION   EXCL    do not flag this hit
             RETAIN  flag it, stop checking further rules
             REVIEW  send to an analyst instead of dropping

    COLUMN   the suffix that limits the rule to one side of the payment.
             PM = Originator, PP = Beneficiary, REF = reference/description.
             No suffix means "wherever the keyword was found".
             Tags are defined in COLUMN_TAGS below - add your own freely.

    TEST     (none)        the keyword is in that column, nothing else needed
             STRADDLE      the match spans two words    CRISTAL HOLDING -> "AL HOL"
             PART_OF_WORD  the match sits inside a word ISLAMABAD, GAZAN, AFGHANATAN
             SURNAME       the match is in the surname  MEHMET KURDOGLU
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
    RULE_APPLIED, and TXN_FLAGGED. A transaction is TXN_FLAGGED = N only when
    every one of its hits was excluded - a hit surviving in another column still
    flags the payment. Filter on TXN_FLAGGED = Y for the report.

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

SHEET_P1, SHEET_P2 = "P1", "P2"
COL_RT, COL_COUNTRIES = "RT Type", "Countries"
COL_KEYWORD, COL_MESSAGE, COL_RULES, COL_STATUS = "Keyword", "Message", "Rules", "Status"

ID_COL = "TXN_ID"
ORIG_NAME_COL, BENE_NAME_COL = "ORIGINATOR_NAME", "BENEFICIARY_NAME"
COUNTRY_COLS = ["ORIGINATOR_COUNTRY", "BENEFICIARY_COUNTRY",
                "ORIGINATOR_FI_COUNTRY_CD", "BENEFICIARY_FI_COUNTRY_CD"]

# the suffixes you can put on a rule name -> the columns they mean
COLUMN_TAGS = {
    "PM": [ORIG_NAME_COL],                          # Originator
    "PP": [BENE_NAME_COL],                          # Beneficiary
    "REF": ["REMITTANCE_INFO", "PAYMENT_DETAILS"],  # reference / description
}

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
    """One sheet per list. Sheet name = list name, first column = the values."""
    if not Path(path).exists():
        return
    book = pd.ExcelFile(path)
    for sheet in book.sheet_names:
        frame = book.parse(sheet, dtype=str).fillna("")
        if frame.empty:
            continue
        name = norm(sheet).replace(" ", "_")
        values = frame.iloc[:, 0]
        if COL_STATUS in frame.columns:
            status = frame[COL_STATUS].str.strip().str.upper()
            values = values[status.eq("") | status.isin(["ACTIVE", "Y", "YES", "1", "TRUE"])]
        entries = sorted({norm(v) for v in values if norm(v)}, key=len, reverse=True)
        if not entries:
            continue
        LISTS[name] = re.compile(
            r"(?<![0-9A-Z])(?:" + "|".join(re.escape(e) for e in entries) + r")(?![0-9A-Z])")
        LIST_SIZE[name] = len(entries)

    for name in LISTS:
        for tag in COLUMN_TAGS:
            if name.endswith("_" + tag):
                sys.exit(f"ERROR: list '{name}' ends with the column tag '{tag}' - rename the sheet, "
                         f"it would be unreadable in a rule name")


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
            raise ValueError(f"list '{list_name}' is not a sheet in {where} (available: {known})")
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
    sheets = pd.read_excel(path, sheet_name=[SHEET_P1, SHEET_P2], dtype=str)
    p1, p2 = sheets[SHEET_P1].fillna(""), sheets[SHEET_P2].fillna("")

    countries = {}
    for _, row in p1.iterrows():
        rt = str(row[COL_RT]).strip()
        if rt:
            codes = {c.strip().upper() for c in SPLIT_RE.split(str(row[COL_COUNTRIES])) if c.strip()}
            countries.setdefault(rt, set()).update(codes)

    keywords = []
    for i, row in p2.iterrows():
        rt, keyword = str(row[COL_RT]).strip(), str(row[COL_KEYWORD]).strip()
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
            sys.exit(f"ERROR in sheet {SHEET_P2} row {i + 2} ({keyword}): {exc}")
        keywords.append({
            "rt": rt,
            "keyword": keyword,
            "keyword_norm": norm(keyword),
            "fields": [f.strip() for f in SPLIT_RE.split(str(row[COL_MESSAGE])) if f.strip()],
            "rules": rules,
            "word_only": word_only,
        })
    return countries, keywords


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------
def screen(transactions_file, mapping_file, intelligence_file, output_file):
    load_intelligence(intelligence_file)
    countries, keywords = load_mapping(mapping_file, intelligence_file)
    df = pd.read_csv(transactions_file, dtype=str, keep_default_na=False).fillna("")

    tag_of = {col: tag for tag, cols in COLUMN_TAGS.items() for col in cols}
    name_cols = {ORIG_NAME_COL, BENE_NAME_COL}
    needed = {ID_COL, ORIG_NAME_COL, BENE_NAME_COL, *COUNTRY_COLS}
    needed |= {f for k in keywords for f in k["fields"]}
    missing = sorted(c for c in needed if c and c not in df.columns)
    if missing:
        sys.exit(f"ERROR: these columns are not in {transactions_file}: {missing}")

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
                    "TXN_ID": df.at[i, ID_COL],
                    "RT_TYPE": spec["rt"],
                    "KEYWORD": spec["keyword"],
                    "MATCH": matched,
                    "COLUMN": field,
                    "TAG": tag_of.get(field, ""),
                    "FIELD_VALUE": df.at[i, field],
                    "SHAPE": shape,
                    "SCOPE_COUNTRY": scope_country[spec["rt"]][i],
                    "ORIGINATOR": df.at[i, ORIG_NAME_COL],
                    "BENEFICIARY": df.at[i, BENE_NAME_COL],
                    "DISPOSITION": disposition,
                    "RULE_APPLIED": rule,
                })

    out = pd.DataFrame(rows, columns=[
        "TXN_ID", "RT_TYPE", "KEYWORD", "MATCH", "COLUMN", "TAG", "FIELD_VALUE", "SHAPE",
        "SCOPE_COUNTRY", "ORIGINATOR", "BENEFICIARY", "DISPOSITION", "RULE_APPLIED"])

    # a transaction survives if any one of its hits was not excluded
    if len(out):
        kept = out.groupby("TXN_ID")["DISPOSITION"].transform(lambda s: (s != "EXCLUDED").any())
        out["TXN_FLAGGED"] = kept.map({True: "Y", False: "N"})
    else:
        out["TXN_FLAGGED"] = []
    out.to_csv(output_file, index=False)

    lists_loaded = ", ".join(f"{n} ({LIST_SIZE[n]})" for n in sorted(LIST_SIZE)) or "none"
    print(f"\nIntelligence lists  : {lists_loaded}")
    print(f"Transactions read   : {len(df):,}")
    print(f"Raw hits            : {len(out):,}")
    for disposition in ("ALERT", "REVIEW", "EXCLUDED"):
        print(f"  {disposition:<10}: {(out['DISPOSITION'] == disposition).sum():,}")
    if len(out):
        flagged = out[out["TXN_FLAGGED"] == "Y"]["TXN_ID"].nunique()
        print(f"Transactions flagged: {flagged:,} of {out['TXN_ID'].nunique():,} with a hit")
        counts = out[out["RULE_APPLIED"] != ""]["RULE_APPLIED"].value_counts()
        if len(counts):
            print("\nDecided by rule:")
            for rule, count in counts.items():
                print(f"  {rule:<24} {count:,}")
    print(f"\nWritten to {output_file}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transactions", default=TRANSACTIONS_FILE)
    parser.add_argument("--mapping", default=MAPPING_FILE)
    parser.add_argument("--intelligence", default=INTELLIGENCE_FILE)
    parser.add_argument("--output", default=OUTPUT_FILE)
    args = parser.parse_args()

    screen(args.transactions, args.mapping, args.intelligence, args.output)
