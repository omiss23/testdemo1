"""
CTF Screening -- Master Rules Engine (corrected, v2)
====================================================

v2 changes
----------
  * EXCLUDE_<CATEGORY> is now first-class. Categories are resolved against the
    intelligence workbook at parse time, so EXCLUDE_SURNAME, EXCLUDE_BANK,
    EXCLUDE_TOPONYM and EXCLUDE_SECULAR_CONTEXT all work without editing the
    mapping. An optional trailing scope is still supported:
    EXCLUDE_SURNAME_BENEFICIARY_NAME.
  * EXCLUDE_CATEGORY_SCOPES lets you pin which columns each category searches.
    This matters -- see the note on that constant.
  * Rule errors are grouped by cause instead of printed one line per row, and
    every distinct unrecognised command is listed.

Architecture
------------
    load -> validate -> PASS 1 (exclusions) -> PASS 2 (matches)
         -> aggregate -> internal-FI filter -> CSV

Both passes complete independently, so mapping row order cannot change the
output. Exclusions are keyed (message_key, keyword), so an exclusion raised for
one keyword never suppresses a different keyword's hit on the same message.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict

import pandas as pd

# --------------------------------------------------------------------------
# CONFIG
# --------------------------------------------------------------------------

TRANSACTIONS_FILE = 'Sample1.csv'
MAPPING_FILE      = 'Mapping_CTF.xlsx'
INTEL_FILE        = 'Intelligence_Lists.xlsx'
INTEL_SHEET_NAME  = 'Sheet1'
OUTPUT_FILE       = 'final_threat_report.csv'

MAPPING_SHEETS    = ('P1', 'P2')
MAPPING_JOIN_KEY  = 'RT Type'

UNIQUE_ID_COLUMN = 'MESSAGE_KEY'

DEFAULT_TEXT_COLUMNS = [
    'ADDITIONAL_MESSAGE_INFO', 'ORIGINATOR_NAME', 'ORIGINATOR_NAME_1',
    'ORIGINATOR_ADDRESS_LINE_1', 'ORIGINATOR_ADDRESS_LINE_2', 'ORIGINATOR_ADDRESS_LINE_3',
    'BENEFICIARY_NAME', 'BENEFICIARY_ADDRESS_LINE_1', 'BENEFICIARY_ADDRESS_LINE_2',
    'BENEFICIARY_ADDRESS_LINE_3',
]

GEO_COLUMNS = ['ORIGINATOR_FI_COUNTRY_CD', 'BENEFICIARY_FI_COUNTRY_CD']

COLUMN_GROUPS = {
    'BENEFICIARY_NAME': ['BENEFICIARY_NAME', 'BENEFICIARY_NAME_1'],
    'ORIGINATOR_NAME':  ['ORIGINATOR_NAME',  'ORIGINATOR_NAME_1'],
    'NAMES':            ['ORIGINATOR_NAME', 'ORIGINATOR_NAME_1',
                         'BENEFICIARY_NAME', 'BENEFICIARY_NAME_1'],
    'ADDRESSES':        ['ORIGINATOR_ADDRESS_LINE_1', 'ORIGINATOR_ADDRESS_LINE_2',
                         'ORIGINATOR_ADDRESS_LINE_3', 'BENEFICIARY_ADDRESS_LINE_1',
                         'BENEFICIARY_ADDRESS_LINE_2', 'BENEFICIARY_ADDRESS_LINE_3'],
}

RELATION_COLUMNS = ('ORIGINATOR_FI_ORG_KEY', 'BENEFICIARY_FI_ORG_KEY')

INTERNAL_FI = [('BNPA', 'FR')]
INTERNAL_FI_COLUMNS = (
    'ORIGINATOR_FI_ORG_KEY', 'ORIGINATOR_FI_COUNTRY_CD',
    'BENEFICIARY_FI_ORG_KEY', 'BENEFICIARY_FI_COUNTRY_CD',
)
INTERNAL_FI_REQUIRE_BOTH_SIDES = False

WHOLE_WORD_MATCH = True
STRICT = True
VERBOSE = True

# Scope searched by EXCLUDE_<CATEGORY> when the command carries no explicit
# scope. An UNSCOPED exclusion searches every default text column, which for a
# broad category such as SURNAME will suppress a very large share of hits --
# pin the narrow scope per category once you have seen the pass-1 counts.
# Values may be a column-group name, a column name, or a list of either.
EXCLUDE_CATEGORY_SCOPES = {
    # 'SURNAME':         'NAMES',
    # 'BANK':            'NAMES',
    # 'TOPONYM':         'ADDRESSES',
    # 'SECULAR_CONTEXT': 'ADDITIONAL_MESSAGE_INFO',
}
EXCLUDE_IF_DEFAULT_SCOPE = DEFAULT_TEXT_COLUMNS

ACTIONS = (
    'EXCLUDE_PM_ONLY',
    'EXCLUDE_PP_ONLY',
    'EXCLUDE_PP_PP_RELATION',
    'EXCLUDE_IF',
    'MATCH_ONLY',
)


class RuleError(Exception):
    """A mapping row could not be interpreted. Carries ref and cause separately
    so identical failures across hundreds of rows can be grouped."""

    def __init__(self, ref: str, detail: str):
        self.ref = ref
        self.detail = detail
        super().__init__(f"{ref}: {detail}")


# --------------------------------------------------------------------------
# MATCHING PRIMITIVES
# --------------------------------------------------------------------------

def build_search_frame(df: pd.DataFrame) -> pd.DataFrame:
    """All-string view for matching. Null becomes '' not the string 'nan'."""
    out = pd.DataFrame(index=df.index)
    for col in df.columns:
        s = df[col]
        out[col] = s.astype(str).where(s.notna(), '').str.strip()
    return out


def keyword_pattern(kw: str) -> str:
    pat = re.escape(kw)
    if WHOLE_WORD_MATCH:
        pat = rf'(?<!\w){pat}(?!\w)'
    return pat


def text_mask_for(df_str: pd.DataFrame, kw: str, cols) -> pd.Series:
    pat = keyword_pattern(kw)
    mask = pd.Series(False, index=df_str.index)
    for col in cols:
        if col in df_str.columns:
            mask |= df_str[col].str.contains(pat, case=False, na=False, regex=True)
    return mask


def geo_mask_for(df_str: pd.DataFrame, target_iso: str, ref: str) -> pd.Series:
    target = (target_iso or '').strip().upper()
    if target in ('', 'NAN'):
        raise RuleError(ref, "'Countries' is blank. Use ALL to mean every country.")
    if target in ('ALL', '*'):
        return pd.Series(True, index=df_str.index)

    isos = [t.strip() for t in re.split(r'[|,;]', target) if t.strip()]
    present = [c for c in GEO_COLUMNS if c in df_str.columns]
    if not present:
        raise RuleError(ref, f"none of {GEO_COLUMNS} exist in the transactions file, "
                             f"so this rule could never match.")

    mask = pd.Series(False, index=df_str.index)
    for col in present:
        mask |= df_str[col].str.upper().isin(isos)
    return mask


# --------------------------------------------------------------------------
# COMMAND PARSING
# --------------------------------------------------------------------------

def parse_command(cmd: str, known_scopes, known_categories, ref: str):
    """Parse one Logic_Instruction command into (action, args).

    Accepted forms:
        MATCH_ONLY
        EXCLUDE_PM_ONLY_BENEFICIARY_NAME     /  EXCLUDE_PM_ONLY:BENEFICIARY_NAME
        EXCLUDE_PP_PP_RELATION
        EXCLUDE_SURNAME                      -> EXCLUDE_IF, category SURNAME
        EXCLUDE_SURNAME_BENEFICIARY_NAME     -> EXCLUDE_IF, SURNAME, scoped
        EXCLUDE_SECULAR_CONTEXT              -> EXCLUDE_IF, SECULAR_CONTEXT
        EXCLUDE_IF_CHARITY_BENEFICIARY_NAME  -> legacy long form
        EXCLUDE:SURNAME:BENEFICIARY_NAME     -> explicit separator form

    Never splits on '_' positionally. The original used rsplit('_', 1), which
    turned MATCH_ONLY into 'MATCH' and disabled every match in the engine.
    """
    cmd = (cmd or '').strip()
    if not cmd:
        raise RuleError(ref, "empty command in Logic_Instruction.")

    if ':' in cmd:
        parts = [p.strip() for p in cmd.split(':') if p.strip()]
        head, args = parts[0].upper(), parts[1:]
        if head == 'EXCLUDE' and args:
            return 'EXCLUDE_IF', args
        if head in ACTIONS:
            return head, args
        raise RuleError(ref, f"unknown action {head!r} in command {cmd!r}.")

    up = cmd.upper()

    # Named actions first, longest name wins, so EXCLUDE_PP_PP_RELATION is not
    # mistaken for a category called PP.
    for action in sorted(ACTIONS, key=len, reverse=True):
        if up == action:
            return action, []
        if up.startswith(action + '_'):
            rest = cmd[len(action) + 1:]
            if action == 'EXCLUDE_IF':
                category, scope = _split_trailing_scope(rest, known_scopes)
                return action, [category] if scope is None else [category, scope]
            return action, [rest]

    # Then EXCLUDE_<CATEGORY>[_<SCOPE>], resolved against the intel workbook.
    if up.startswith('EXCLUDE_'):
        rest = cmd[len('EXCLUDE_'):]
        category, scope = _split_leading_category(rest, known_categories)
        if category is not None:
            return 'EXCLUDE_IF', [category] if scope is None else [category, scope]
        raise RuleError(
            ref,
            f"unrecognised command {cmd!r}. It looks like an EXCLUDE_<CATEGORY> "
            f"command but {rest!r} does not start with a known intelligence "
            f"category. Categories in the intel sheet: "
            f"{', '.join(sorted(known_categories)) or '(none)'}."
        )

    raise RuleError(ref, f"unrecognised command {cmd!r}. Known actions: "
                         f"{', '.join(ACTIONS)}.")


def _split_trailing_scope(rest: str, known_scopes):
    """'CHARITY_BENEFICIARY_NAME' -> ('CHARITY', 'BENEFICIARY_NAME')."""
    for scope in sorted(known_scopes, key=len, reverse=True):
        if rest.upper().endswith('_' + scope.upper()):
            return rest[: -(len(scope) + 1)], scope
    return rest, None


def _split_leading_category(rest: str, known_categories):
    """'SURNAME_BENEFICIARY_NAME' -> ('SURNAME', 'BENEFICIARY_NAME').

    Longest category first, so SECULAR_CONTEXT is not read as a category
    'SECULAR' with scope 'CONTEXT'.
    """
    up = rest.upper()
    for cat in sorted(known_categories, key=len, reverse=True):
        cu = cat.upper()
        if up == cu:
            return cat, None
        if up.startswith(cu + '_'):
            return cat, rest[len(cat) + 1:]
    return None, None


def resolve_scope(scope, df_str: pd.DataFrame, ref: str):
    """Turn a scope (None, a column group, a column, or a list) into columns."""
    if scope is None:
        return [c for c in EXCLUDE_IF_DEFAULT_SCOPE if c in df_str.columns]
    if isinstance(scope, (list, tuple)):
        cols = []
        for s in scope:
            for c in resolve_scope(s, df_str, ref):
                if c not in cols:
                    cols.append(c)
        return cols
    if scope in COLUMN_GROUPS:
        return [c for c in COLUMN_GROUPS[scope] if c in df_str.columns]
    if scope in df_str.columns:
        return [scope]
    raise RuleError(ref, f"scope {scope!r} is neither a column group "
                         f"({', '.join(COLUMN_GROUPS)}) nor a column in the "
                         f"transactions file.")


# --------------------------------------------------------------------------
# LOADERS
# --------------------------------------------------------------------------

def load_transactions(path: str):
    df = pd.read_csv(path, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]
    df = df.drop_duplicates().reset_index(drop=True)

    if UNIQUE_ID_COLUMN not in df.columns:
        sys.exit(f"FATAL: transactions file has no {UNIQUE_ID_COLUMN} column.")

    dupes = int(df[UNIQUE_ID_COLUMN].duplicated().sum())
    if dupes:
        print(f"WARNING: {dupes:,} duplicate {UNIQUE_ID_COLUMN} values -- "
              f"distinct transactions will be merged in the report.")

    print(f"Transactions loaded: {len(df):,} rows, {len(df.columns)} columns.")
    return df, build_search_frame(df)


def load_mapping(path: str) -> pd.DataFrame:
    p1 = pd.read_excel(path, sheet_name=MAPPING_SHEETS[0])
    p2 = pd.read_excel(path, sheet_name=MAPPING_SHEETS[1])
    for frame in (p1, p2):
        frame.columns = [str(c).strip() for c in frame.columns]
        for col in frame.columns:
            s = frame[col]
            frame[col] = s.astype(str).where(s.notna(), '').str.strip()

    df_map = pd.merge(p2, p1, on=MAPPING_JOIN_KEY, how='inner')

    lost = set(p2[MAPPING_JOIN_KEY]) ^ set(p1[MAPPING_JOIN_KEY])
    if lost:
        print(f"WARNING: {len(lost)} {MAPPING_JOIN_KEY} value(s) in only one mapping "
              f"sheet, dropped by the inner join: {sorted(lost)[:10]}")

    status_cols = [c for c in df_map.columns if c.lower() == 'status']
    if status_cols:
        col = status_cols[0]
        before = len(df_map)
        df_map = df_map[df_map[col].str.upper() != 'INACTIVE']
        print(f"Status filter: {before - len(df_map)} INACTIVE rule(s) skipped.")

    missing = {'Keyword', 'Countries'} - set(df_map.columns)
    if missing:
        sys.exit(f"FATAL: mapping is missing required column(s): {sorted(missing)}")

    print(f"Mapping loaded: {len(df_map)} combined rules.")
    return df_map.reset_index(drop=True)


def load_intel(path: str, sheet: str) -> dict:
    try:
        df = pd.read_excel(path, sheet_name=sheet)
        df.columns = [str(c).strip() for c in df.columns]
        df = df.dropna(subset=['category', 'value'])
        intel = (
            df.assign(
                category=df['category'].astype(str).str.strip().str.upper(),
                value=df['value'].astype(str).str.strip(),
            )
            .groupby('category')['value']
            .apply(lambda s: sorted({v for v in s if v}))
            .to_dict()
        )
        sizes = ', '.join(f"{k} ({len(v)})" for k, v in sorted(intel.items()))
        print(f"Intelligence loaded. Categories: {sizes}")
        return intel
    except Exception as exc:
        sys.exit(f"FATAL: could not load intelligence file '{path}': {exc}")


# --------------------------------------------------------------------------
# RULE EVALUATION
# --------------------------------------------------------------------------

def rule_candidates(df_str, kw, target_iso, msg_val, ref):
    if msg_val and msg_val.lower() not in ('nan', '*'):
        cols = [c.strip() for c in msg_val.split(',') if c.strip()]
        unknown = [c for c in cols if c not in df_str.columns]
        if unknown and STRICT:
            raise RuleError(ref, f"'Message' names column(s) not in the "
                                 f"transactions file: {unknown}")
        cols = [c for c in cols if c in df_str.columns]
        if not cols:
            raise RuleError(ref, "no scannable columns resolved from 'Message'.")
    else:
        cols = [c for c in DEFAULT_TEXT_COLUMNS if c in df_str.columns]

    return df_str.index[text_mask_for(df_str, kw, cols)
                        & geo_mask_for(df_str, target_iso, ref)]


def apply_exclusion(action, args, df, df_str, candidates, kw, intel, ref):
    """Return the subset of `candidates` this exclusion removes."""
    sub = df_str.loc[candidates]

    if action in ('EXCLUDE_PM_ONLY', 'EXCLUDE_PP_ONLY'):
        # Identical in the original script; kept identical here. If PM and PP
        # are meant to differ, that logic still needs writing.
        if not args:
            raise RuleError(ref, f"{action} requires a column group, "
                                 f"e.g. {action}:BENEFICIARY_NAME")
        cols = resolve_scope(args[0], df_str, ref)
        return sub.index[text_mask_for(sub, kw, cols)]

    if action == 'EXCLUDE_PP_PP_RELATION':
        a, b = RELATION_COLUMNS
        missing = [c for c in RELATION_COLUMNS if c not in df_str.columns]
        if missing:
            raise RuleError(ref, f"EXCLUDE_PP_PP_RELATION needs {missing}.")
        return sub.index[sub[a].ne('') & sub[b].ne('') & sub[a].eq(sub[b])]

    if action == 'EXCLUDE_IF':
        if not args:
            raise RuleError(ref, "EXCLUDE_IF requires a category.")
        category = args[0].strip().upper()
        if category not in intel:
            raise RuleError(ref, f"intelligence category {category!r} not found. "
                                 f"Available: {', '.join(sorted(intel))}.")
        scope = args[1] if len(args) > 1 else EXCLUDE_CATEGORY_SCOPES.get(category)
        cols = resolve_scope(scope, df_str, ref)
        mask = pd.Series(False, index=sub.index)
        for term in intel[category]:
            mask |= text_mask_for(sub, term, cols)
        return sub.index[mask]

    raise RuleError(ref, f"{action} is not an exclusion action.")


# --------------------------------------------------------------------------
# PIPELINE
# --------------------------------------------------------------------------

def _report_errors(errors):
    """Group identical causes instead of one line per mapping row."""
    grouped = defaultdict(list)
    for err in errors:
        grouped[err.detail].append(err.ref)

    print(f"\n{len(errors)} unusable mapping row(s), {len(grouped)} distinct cause(s):\n")
    for detail, refs in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        sample = ', '.join(r.replace('mapping row ', '') for r in refs[:6])
        more = f" ... +{len(refs) - 6} more" if len(refs) > 6 else ''
        print(f"  [{len(refs)} row(s)] {detail}")
        print(f"      Excel rows: {sample}{more}\n")


def run_ctf_pipeline(trans_path, map_path, intel_path, intel_sheet, output_path):
    print('--- Starting Master Rules Engine ---')

    df, df_str = load_transactions(trans_path)
    df_map = load_mapping(map_path)
    intel = load_intel(intel_path, intel_sheet)

    known_scopes = list(COLUMN_GROUPS) + list(df_str.columns)
    known_categories = list(intel)
    ids = df_str[UNIQUE_ID_COLUMN]

    # ---- parse every rule before any scanning happens
    rules, errors = [], []
    for i, row in df_map.iterrows():
        ref = f"mapping row {i + 2}"
        try:
            kw = str(row['Keyword']).strip()
            if not kw or kw.lower() == 'nan':
                raise RuleError(ref, "blank Keyword.")

            instr = str(row.get('Logic_Instruction', '')).strip()
            if not instr or instr.lower() == 'nan':
                instr = 'MATCH_ONLY'

            commands = [parse_command(c, known_scopes, known_categories, ref)
                        for c in instr.split(',') if c.strip()]

            rules.append({
                'ref': ref,
                'keyword': kw,
                'iso': str(row['Countries']).strip(),
                'message': str(row.get('Message', '')).strip(),
                'rt_type': str(row.get(MAPPING_JOIN_KEY, '')).strip(),
                'commands': commands,
                'excluded': 0,
            })
        except RuleError as exc:
            errors.append(exc)

    if errors:
        _report_errors(errors)
        if STRICT:
            sys.exit("FATAL: fix the mapping and re-run. "
                     "Set STRICT = False to skip these rows instead.")

    # ---- resolve candidates
    for rule in rules:
        try:
            rule['candidates'] = rule_candidates(
                df_str, rule['keyword'], rule['iso'], rule['message'], rule['ref'])
        except RuleError as exc:
            if STRICT:
                sys.exit(f"FATAL: {exc}")
            print(f"SKIPPED: {exc}")
            rule['candidates'] = pd.Index([])

    # ---- PASS 1: exclusions, keyed (message_key, keyword)
    excluded = set()
    for rule in rules:
        if rule['candidates'].empty:
            continue
        for action, args in rule['commands']:
            if action == 'MATCH_ONLY':
                continue
            try:
                hit_idx = apply_exclusion(action, args, df, df_str,
                                          rule['candidates'], rule['keyword'],
                                          intel, rule['ref'])
            except RuleError as exc:
                if STRICT:
                    sys.exit(f"FATAL: {exc}")
                print(f"SKIPPED: {exc}")
                continue
            rule['excluded'] += len(hit_idx)
            for mid in ids.loc[hit_idx]:
                excluded.add((mid, rule['keyword']))

    print(f"\nPass 1 complete: {len(excluded):,} (message, keyword) exclusion(s).")

    # ---- PASS 2: matches
    records = []
    for rule in rules:
        if not any(a == 'MATCH_ONLY' for a, _ in rule['commands']):
            continue
        kw = rule['keyword']
        for mid in ids.loc[rule['candidates']]:
            if (mid, kw) in excluded:
                continue
            records.append({
                UNIQUE_ID_COLUMN: mid,
                'detected_keyword': kw,
                'matched_iso': rule['iso'],
                'RT_TYPE_INFO': rule['rt_type'],
            })

    if VERBOSE:
        active = [r for r in rules if len(r['candidates'])]
        print(f"\nRules with candidates: {len(active)} of {len(rules)}")
        for rule in active[:40]:
            print(f"  {rule['ref']:<18} {rule['keyword'][:28]:<28} "
                  f"candidates={len(rule['candidates']):<6} excluded={rule['excluded']:<6}")
        if len(active) > 40:
            print(f"  ... +{len(active) - 40} more")

    if not records:
        print('\nNo matches found after all rules applied.')
        return

    df_hits = pd.DataFrame(records).drop_duplicates(
        subset=[UNIQUE_ID_COLUMN, 'detected_keyword'])

    joined = lambda s: ', '.join(sorted({v for v in s.astype(str) if v}))
    agg = (
        df_hits.groupby(UNIQUE_ID_COLUMN, as_index=False)
        .agg(
            detected_keyword=('detected_keyword', joined),
            matched_iso=('matched_iso', joined),
            RT_TYPE_INFO=('RT_TYPE_INFO', joined),
            keyword_hit_count=('detected_keyword', 'size'),
        )
    )

    df_final = df.merge(agg, on=UNIQUE_ID_COLUMN, how='inner')
    before_internal = len(df_final)
    df_final = drop_internal_fi(df_final)

    df_final.to_csv(output_path, index=False)

    print('\n--- SUCCESS ---')
    print(f"Match records (message x keyword): {len(df_hits):,}")
    print(f"Distinct messages flagged:         {before_internal:,}")
    print(f"Removed as internal FI:            {before_internal - len(df_final):,}")
    print(f"Final report records:              {len(df_final):,}")
    print(f"Report saved to:                   {output_path}")


def drop_internal_fi(df_final: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in INTERNAL_FI_COLUMNS if c not in df_final.columns]
    if missing:
        print(f"WARNING: internal-FI filter skipped, missing column(s): {missing}")
        return df_final

    s = build_search_frame(df_final[list(INTERNAL_FI_COLUMNS)])
    o_key, o_cc, b_key, b_cc = (s[c].str.upper() for c in INTERNAL_FI_COLUMNS)

    orig = pd.Series(False, index=df_final.index)
    bene = pd.Series(False, index=df_final.index)
    for key, cc in INTERNAL_FI:
        orig |= o_key.eq(key.upper()) & o_cc.eq(cc.upper())
        bene |= b_key.eq(key.upper()) & b_cc.eq(cc.upper())

    drop = (orig & bene) if INTERNAL_FI_REQUIRE_BOTH_SIDES else (orig | bene)
    return df_final[~drop]


if __name__ == '__main__':
    run_ctf_pipeline(TRANSACTIONS_FILE, MAPPING_FILE, INTEL_FILE,
                     INTEL_SHEET_NAME, OUTPUT_FILE)
