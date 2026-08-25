"""
CTF Screening -- Master Rules Engine (corrected)
================================================

Keyword + geography screening over a transactions file, driven by an Excel
mapping maintained by the compliance team.

Architecture
------------
    load  ->  validate  ->  PASS 1 (exclusions)  ->  PASS 2 (matches)
          ->  apply exclusions  ->  aggregate  ->  internal-FI filter  ->  CSV

Two passes, not one: every EXCLUDE_* instruction across every mapping row is
evaluated BEFORE any MATCH_ONLY is resolved. The output is therefore
independent of the row order in the mapping workbook.

Design rules this file follows
------------------------------
  * Fail loud, never silent. An unparseable command, an unknown column group
    or an unknown ISO code aborts the run and names the offending mapping row.
    A screening control that silently disables itself is the worst outcome.
  * Raw data is never mutated. Searching happens on a parallel normalised
    string frame, so amounts and dates keep their dtypes in the output.
  * Keywords are escaped, never treated as regex.
"""

from __future__ import annotations

import re
import sys

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
}

RELATION_COLUMNS = ('ORIGINATOR_FI_ORG_KEY', 'BENEFICIARY_FI_ORG_KEY')

# Internal FIs to drop from the final report, compared FIELD BY FIELD.
# The original concatenated ORG_KEY + COUNTRY_CD and compared to 'BNPAFR',
# which also matches ORG_KEY='BNP' + COUNTRY_CD='AFR'.
INTERNAL_FI = [('BNPA', 'FR')]
INTERNAL_FI_COLUMNS = (
    'ORIGINATOR_FI_ORG_KEY', 'ORIGINATOR_FI_COUNTRY_CD',
    'BENEFICIARY_FI_ORG_KEY', 'BENEFICIARY_FI_COUNTRY_CD',
)
# False -> drop when EITHER side is internal (original behaviour).
# True  -> drop only genuine internal-to-internal transfers.
INTERNAL_FI_REQUIRE_BOTH_SIDES = False

# Match on word boundaries. This is the single biggest false-positive
# reducer: 'MALI' stops matching SOMALIA, MALIK and NORMALISED.
# Set False only to reproduce legacy substring behaviour.
WHOLE_WORD_MATCH = True

# Abort on an unrecognised command / column group / ISO instead of skipping.
STRICT = True

# Scope searched by EXCLUDE_IF when no column group is given.
# The original scanned EVERY column, including numeric identifiers.
EXCLUDE_IF_DEFAULT_SCOPE = DEFAULT_TEXT_COLUMNS

VERBOSE = True

ACTIONS = (
    'EXCLUDE_PM_ONLY',
    'EXCLUDE_PP_ONLY',
    'EXCLUDE_PP_PP_RELATION',
    'EXCLUDE_IF',
    'MATCH_ONLY',
)


class RuleError(Exception):
    """A mapping row could not be interpreted."""


# --------------------------------------------------------------------------
# NORMALISATION
# --------------------------------------------------------------------------

def build_search_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Parallel all-string view used for matching.

    Nulls become '' rather than the literal string 'nan', which the original
    produced via a blanket .astype(str) -- that made na=False meaningless and
    let a keyword such as 'na' match every empty cell.
    """
    out = pd.DataFrame(index=df.index)
    for col in df.columns:
        s = df[col]
        out[col] = s.astype(str).where(s.notna(), '').str.strip()
    return out


def keyword_pattern(kw: str) -> str:
    """Escaped, optionally word-bounded regex for a literal keyword.

    The original passed the raw keyword to str.contains(), where pandas
    treats it as a regex. Any keyword containing ( ) + * . ? | [ would
    either raise or match the wrong rows.
    """
    pat = re.escape(kw)
    if WHOLE_WORD_MATCH:
        # (?<!\w) / (?!\w) rather than \b, so keywords that begin or end with
        # punctuation still behave correctly.
        pat = rf'(?<!\w){pat}(?!\w)'
    return pat


def text_mask_for(df_str: pd.DataFrame, kw: str, cols) -> pd.Series:
    pat = keyword_pattern(kw)
    mask = pd.Series(False, index=df_str.index)
    for col in cols:
        if col in df_str.columns:
            mask |= df_str[col].str.contains(pat, case=False, na=False, regex=True)
    return mask


def geo_mask_for(df_str: pd.DataFrame, target_iso: str, rule_ref: str) -> pd.Series:
    """Geography mask. Supports ALL, a single ISO, or 'FR|BE|LU'."""
    target = (target_iso or '').strip().upper()
    if target in ('', 'NAN'):
        raise RuleError(f"{rule_ref}: 'Countries' is blank. Use ALL to mean every country.")
    if target in ('ALL', '*'):
        return pd.Series(True, index=df_str.index)

    isos = [t.strip() for t in re.split(r'[|,;]', target) if t.strip()]
    present = [c for c in GEO_COLUMNS if c in df_str.columns]
    if not present:
        raise RuleError(
            f"{rule_ref}: none of the geography columns {GEO_COLUMNS} exist in the "
            f"transactions file, so this rule could never match."
        )

    mask = pd.Series(False, index=df_str.index)
    for col in present:
        mask |= df_str[col].str.upper().isin(isos)
    return mask


# --------------------------------------------------------------------------
# COMMAND PARSING
# --------------------------------------------------------------------------

def parse_command(cmd: str, known_scopes, rule_ref: str):
    """Parse one Logic_Instruction command into (action, args).

    Preferred grammar uses an explicit separator, which is unambiguous:
        MATCH_ONLY
        EXCLUDE_PM_ONLY:BENEFICIARY_NAME
        EXCLUDE_IF:CHARITY:BENEFICIARY_NAME

    Legacy underscore grammar is still accepted:
        EXCLUDE_PM_ONLY_BENEFICIARY_NAME
        EXCLUDE_IF_CHARITY_BENEFICIARY_NAME

    The original used cmd.rsplit('_', 1), which splits at the LAST underscore.
    That turned 'MATCH_ONLY' into action='MATCH' -- so the match branch never
    fired and no hit was ever recorded -- and turned
    'EXCLUDE_PM_ONLY_BENEFICIARY_NAME' into action='EXCLUDE_PM_ONLY_BENEFICIARY',
    which matched no branch and silently did nothing.
    """
    cmd = (cmd or '').strip()
    if not cmd:
        raise RuleError(f"{rule_ref}: empty command in Logic_Instruction.")

    if ':' in cmd:
        parts = [p.strip() for p in cmd.split(':') if p.strip()]
        action, args = parts[0].upper(), parts[1:]
        if action not in ACTIONS:
            raise RuleError(f"{rule_ref}: unknown action {action!r} in command {cmd!r}.")
        return action, args

    up = cmd.upper()
    for action in sorted(ACTIONS, key=len, reverse=True):
        if up == action:
            return action, []
        if up.startswith(action + '_'):
            rest = cmd[len(action) + 1:]
            if action == 'EXCLUDE_IF':
                # 'CHARITY_BENEFICIARY_NAME' -> category 'CHARITY', scope 'BENEFICIARY_NAME'
                category, scope = _split_trailing_scope(rest, known_scopes)
                return action, [category] if scope is None else [category, scope]
            return action, [rest]

    raise RuleError(
        f"{rule_ref}: unrecognised command {cmd!r}. Known actions: {', '.join(ACTIONS)}."
    )


def _split_trailing_scope(rest: str, known_scopes):
    for scope in sorted(known_scopes, key=len, reverse=True):
        if rest.upper().endswith('_' + scope.upper()):
            return rest[: -(len(scope) + 1)], scope
    return rest, None


def resolve_scope(scope, df_str: pd.DataFrame, rule_ref: str):
    """Turn a column-group name or column name into a concrete column list."""
    if scope is None:
        return [c for c in EXCLUDE_IF_DEFAULT_SCOPE if c in df_str.columns]
    if scope in COLUMN_GROUPS:
        return [c for c in COLUMN_GROUPS[scope] if c in df_str.columns]
    if scope in df_str.columns:
        return [scope]
    raise RuleError(
        f"{rule_ref}: scope {scope!r} is neither a column group "
        f"({', '.join(COLUMN_GROUPS)}) nor a column in the transactions file."
    )


# --------------------------------------------------------------------------
# LOADERS
# --------------------------------------------------------------------------

def load_transactions(path: str):
    df = pd.read_csv(path, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]
    df = df.drop_duplicates().reset_index(drop=True)

    if UNIQUE_ID_COLUMN not in df.columns:
        sys.exit(f"FATAL: transactions file has no {UNIQUE_ID_COLUMN} column.")

    dupes = df[UNIQUE_ID_COLUMN].duplicated().sum()
    if dupes:
        # The final aggregation groups on this key, so duplicates would silently
        # collapse distinct transactions into one report line.
        print(f"WARNING: {dupes:,} duplicate {UNIQUE_ID_COLUMN} values -- "
              f"distinct transactions will be merged in the report.")

    df_str = build_search_frame(df)
    print(f"Transactions loaded: {len(df):,} rows, {len(df.columns)} columns.")
    return df, df_str


def load_mapping(path: str) -> pd.DataFrame:
    p1 = pd.read_excel(path, sheet_name=MAPPING_SHEETS[0])
    p2 = pd.read_excel(path, sheet_name=MAPPING_SHEETS[1])
    for df in (p1, p2):
        df.columns = [str(c).strip() for c in df.columns]
        for col in df.columns:
            s = df[col]
            df[col] = s.astype(str).where(s.notna(), '').str.strip()

    df_map = pd.merge(p2, p1, on=MAPPING_JOIN_KEY, how='inner')

    # An inner join silently discards rules whose RT Type is missing on one
    # side. Say so rather than under-screening without anyone noticing.
    lost = set(p2[MAPPING_JOIN_KEY]) ^ set(p1[MAPPING_JOIN_KEY])
    if lost:
        print(f"WARNING: {len(lost)} {MAPPING_JOIN_KEY} value(s) present in only one "
              f"mapping sheet and therefore dropped: {sorted(lost)[:10]}")

    if 'status' in {c.lower() for c in df_map.columns}:
        col = next(c for c in df_map.columns if c.lower() == 'status')
        before = len(df_map)
        df_map = df_map[df_map[col].str.upper() != 'INACTIVE'].reset_index(drop=True)
        print(f"Status filter: {before - len(df_map)} INACTIVE rule(s) skipped.")

    required = {'Keyword', 'Countries'}
    missing = required - set(df_map.columns)
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
        print(f"Intelligence loaded. Categories: {sorted(intel)}")
        return intel
    except Exception as exc:
        # The original downgraded this to a warning and continued with an empty
        # dict, which silently turned every EXCLUDE_IF rule into a no-op while
        # the report still looked complete.
        sys.exit(f"FATAL: could not load intelligence file '{path}': {exc}")


# --------------------------------------------------------------------------
# RULE EVALUATION
# --------------------------------------------------------------------------

def rule_candidates(df_str, kw, target_iso, msg_val, rule_ref):
    """Rows where the keyword appears AND the geography matches."""
    if msg_val and msg_val.lower() not in ('nan', '*'):
        cols = [c.strip() for c in msg_val.split(',') if c.strip()]
        unknown = [c for c in cols if c not in df_str.columns]
        if unknown and STRICT:
            raise RuleError(f"{rule_ref}: 'Message' names column(s) not in the "
                            f"transactions file: {unknown}")
        cols = [c for c in cols if c in df_str.columns]
        if not cols:
            raise RuleError(f"{rule_ref}: no scannable columns resolved from 'Message'.")
    else:
        cols = [c for c in DEFAULT_TEXT_COLUMNS if c in df_str.columns]

    mask = text_mask_for(df_str, kw, cols) & geo_mask_for(df_str, target_iso, rule_ref)
    return df_str.index[mask]


def apply_exclusion(action, args, df, df_str, candidates, kw, intel, rule_ref):
    """Return the subset of `candidates` this exclusion removes."""
    sub = df_str.loc[candidates]

    if action in ('EXCLUDE_PM_ONLY', 'EXCLUDE_PP_ONLY'):
        # NOTE: in the original these two branches contained byte-identical
        # code. They remain identical here so behaviour is unchanged -- if the
        # PM and PP variants are meant to differ, that logic still needs writing.
        if not args:
            raise RuleError(f"{rule_ref}: {action} requires a column group, "
                            f"e.g. {action}:BENEFICIARY_NAME")
        cols = resolve_scope(args[0], df_str, rule_ref)
        return sub.index[text_mask_for(sub, kw, cols)]

    if action == 'EXCLUDE_PP_PP_RELATION':
        a, b = RELATION_COLUMNS
        missing = [c for c in RELATION_COLUMNS if c not in df_str.columns]
        if missing:
            raise RuleError(f"{rule_ref}: EXCLUDE_PP_PP_RELATION needs {missing}.")
        both_present = sub[a].ne('') & sub[b].ne('')
        return sub.index[both_present & sub[a].eq(sub[b])]

    if action == 'EXCLUDE_IF':
        if not args:
            raise RuleError(f"{rule_ref}: EXCLUDE_IF requires a category, "
                            f"e.g. EXCLUDE_IF:CHARITY:BENEFICIARY_NAME")
        category = args[0].strip().upper()
        scope = args[1] if len(args) > 1 else None
        if category not in intel:
            raise RuleError(f"{rule_ref}: intelligence category {category!r} not found. "
                            f"Available: {sorted(intel)}")
        cols = resolve_scope(scope, df_str, rule_ref)
        mask = pd.Series(False, index=sub.index)
        for term in intel[category]:
            mask |= text_mask_for(sub, term, cols)
        return sub.index[mask]

    raise RuleError(f"{rule_ref}: {action} is not an exclusion action.")


# --------------------------------------------------------------------------
# PIPELINE
# --------------------------------------------------------------------------

def run_ctf_pipeline(trans_path, map_path, intel_path, intel_sheet, output_path):
    print('--- Starting Master Rules Engine ---')

    df, df_str = load_transactions(trans_path)
    df_map = load_mapping(map_path)
    intel = load_intel(intel_path, intel_sheet)

    known_scopes = list(COLUMN_GROUPS) + list(df_str.columns)
    ids = df_str[UNIQUE_ID_COLUMN]

    # ---- parse and cache every rule up front, so a bad mapping row fails
    # ---- before any scanning work happens
    rules, errors = [], []
    for i, row in df_map.iterrows():
        rule_ref = f"mapping row {i + 2}"
        try:
            kw = str(row['Keyword']).strip()
            if not kw or kw.lower() == 'nan':
                raise RuleError(f"{rule_ref}: blank Keyword.")

            instr = str(row.get('Logic_Instruction', '')).strip()
            if not instr or instr.lower() == 'nan':
                instr = 'MATCH_ONLY'

            commands = [parse_command(c, known_scopes, rule_ref)
                        for c in instr.split(',') if c.strip()]

            rules.append({
                'ref': rule_ref,
                'keyword': kw,
                'iso': str(row['Countries']).strip(),
                'message': str(row.get('Message', '')).strip(),
                'rt_type': str(row.get(MAPPING_JOIN_KEY, '')).strip(),
                'commands': commands,
            })
        except RuleError as exc:
            errors.append(str(exc))

    if errors:
        print(f"\n{len(errors)} unusable mapping row(s):")
        for e in errors[:20]:
            print(f"  - {e}")
        if STRICT:
            sys.exit("FATAL: fix the mapping and re-run. "
                     "Set STRICT = False to skip bad rows instead.")

    # ---- resolve candidates once per rule
    for rule in rules:
        try:
            rule['candidates'] = rule_candidates(
                df_str, rule['keyword'], rule['iso'], rule['message'], rule['ref'])
        except RuleError as exc:
            if STRICT:
                sys.exit(f"FATAL: {exc}")
            print(f"SKIPPED: {exc}")
            rule['candidates'] = pd.Index([])

    # ---- PASS 1: exclusions ------------------------------------------------
    # Keyed on (message_key, keyword) so an exclusion raised for one keyword
    # cannot suppress a different keyword's hit on the same message. Evaluated
    # in full before any match is resolved, so mapping row order is irrelevant.
    excluded: set[tuple] = set()
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
            rule['excluded'] = rule.get('excluded', 0) + len(hit_idx)
            for mid in ids.loc[hit_idx]:
                excluded.add((mid, rule['keyword']))

    print(f"Pass 1 complete: {len(excluded):,} (message, keyword) exclusion(s).")

    # ---- PASS 2: matches ---------------------------------------------------
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
        rule['kept'] = sum(1 for r in records if r['detected_keyword'] == kw)

    if VERBOSE:
        print('\nPer-rule summary (rules with candidates only):')
        for rule in rules:
            n = len(rule['candidates'])
            if n:
                print(f"  {rule['ref']:<18} {rule['keyword']:<28} "
                      f"candidates={n:<7} excluded={rule.get('excluded', 0):<7}")

    if not records:
        print('\nNo matches found after all rules applied.')
        return

    # Build a proper DataFrame. The original called pd.concat() on a list of
    # Series, which stacks them into ONE long Series rather than a frame --
    # the following drop_duplicates(subset=...) then raises TypeError.
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

    # Merging back onto df_trans restores the original column order and the
    # original dtypes automatically -- no reindex, so no phantom NaN columns.
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
