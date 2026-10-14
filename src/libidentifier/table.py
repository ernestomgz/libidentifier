"""Plain terminal summaries; presentation never evaluates version applicability."""
from __future__ import annotations

import re
import shutil
import sys
import unicodedata
from pathlib import PurePosixPath
from types import SimpleNamespace
from urllib.parse import unquote

from .vulnerabilities.correlate import _coordinate

_ESCAPES = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]')
_DISPLAY_NAMES = {'gson': 'Gson', 'okhttp': 'OkHttp', 'retrofit': 'Retrofit'}


def clean(value):
    text = _ESCAPES.sub('', str(value))
    return ''.join(' ' if c.isspace() else c for c in text
                   if c.isspace() or not unicodedata.category(c).startswith('C'))


def cells(text):
    return sum(0 if unicodedata.combining(c) else
               2 if unicodedata.east_asian_width(c) in {'W', 'F'} else 1 for c in text)


def wrap(value, width):
    """Wrap sanitized text by terminal cells, including long unbroken names."""
    width = max(1, width)
    lines, current = [], ''
    for match in re.finditer(r'(\s*)(\S+)', clean(value)):
        spacing, word = match.groups()
        if current and cells(current + spacing + word) <= width:
            current += spacing + word
            continue
        if current:
            lines.append(current)
            current = ''
        for c in word:
            size = cells(c)
            if current and cells(current) + size > width:
                lines.append(current)
                current = ''
            # Extremely narrow output cannot represent a two-cell glyph.
            current += '?' if size > width else c
    if current:
        lines.append(current)
    return lines or ['']


class _Terminal:
    def __init__(self, stream, width):
        self.stream = stream
        self.width = max(1, min(120, width))

    def line(self, text='', indent=0):
        indent = min(indent, max(0, self.width - 1))
        for line in wrap(text, self.width - indent):
            self.stream.write((' ' * indent + line).rstrip() + '\n')

    def section(self, title):
        self.line()
        self.line(title)
        self.stream.write('─' * self.width + '\n')

    def table(self, headings, rows):
        minimum = [8, 12, 12, 12][:len(headings)]
        if sum(minimum) + 2 * (len(headings) - 1) > self.width:
            for row in rows:
                self.line(row[0])
                for title, value in zip(headings[1:], row[1:]):
                    self.line(f'{title}: {value}', indent=2)
                self.line()
            return
        widths = [max(cells(clean(title)), *(cells(clean(r[i])) for r in rows), minimum[i])
                  for i, title in enumerate(headings)]
        while sum(widths) + 2 * (len(widths) - 1) > self.width:
            i = max(range(len(widths)), key=lambda i: widths[i] - minimum[i])
            widths[i] -= 1
        for row in [headings, *rows]:
            lines = [wrap(value, width) for value, width in zip(row, widths)]
            for n in range(max(map(len, lines))):
                values = [column[n] if n < len(column) else '' for column in lines]
                self.stream.write('  '.join(value + ' ' * (width - cells(value))
                    for value, width in zip(values, widths)).rstrip() + '\n')


def _range_text(r):
    """Only uniquely paired boundaries become intervals; never sort Maven versions.

    OSV events need not be sorted. Complex timelines/limits are rendered verbatim
    rather than paired, compared or collapsed with a new version algorithm.
    """
    if not isinstance(r, dict):
        return None
    events = r.get('events', [])
    if r.get('type') not in {'ECOSYSTEM', 'SEMVER'} or not isinstance(events, list) or not events:
        return None
    if any(not isinstance(e, dict) or len(e) != 1 or
           next(iter(e)) not in {'introduced', 'fixed', 'last_affected', 'limit'} or
           not isinstance(next(iter(e.values())), str) or not next(iter(e.values())) for e in events):
        return None
    introduced = [e['introduced'] for e in events if 'introduced' in e]
    closing = [e for e in events if 'fixed' in e or 'last_affected' in e]
    prefix = 'SemVer: ' if r['type'] == 'SEMVER' else ''
    if len(introduced) == 1 and len(closing) <= 1 and not any('limit' in e for e in events):
        start = introduced[0]
        if not closing:
            return prefix + ('all versions' if start == '0' else f'from {start} onward')
        kind, end = next(iter(closing[0].items()))
        if start == '0':
            return prefix + (f'before {end}' if kind == 'fixed' else f'up to {end} inclusive')
        return prefix + f'{start} inclusive to {end} ' + ('exclusive' if kind == 'fixed' else 'inclusive')
    if not introduced:
        return None
    # Preserve event types, order and limits, including qualifiers and '*'.
    return f"{r['type']} events: " + '; '.join(f'{k} {v}' for e in events for k, v in e.items())


def affected_text(records, coordinate):
    if not coordinate:
        return None
    descriptions = []
    incomplete = False
    for record in records:
        for entry in record.affected:
            if not isinstance(entry, dict) or not isinstance(entry.get('package'), dict):
                continue
            package = entry.get('package', {})
            if (package.get('ecosystem'), package.get('name')) != coordinate:
                continue
            ranges = entry.get('ranges') or []
            if not isinstance(ranges, list):
                ranges = []
                incomplete = True
            for r in ranges:
                text = _range_text(r)
                if text:
                    descriptions.append(text)
                else:
                    incomplete = True
            versions = entry.get('versions', [])
            if isinstance(versions, list) and versions and all(isinstance(v, str) and v for v in versions):
                descriptions.append('listed versions: ' + ', '.join(versions) if len(versions) <= 4 else
                                    f'{len(versions)} explicitly listed versions (see JSON)')
    if not descriptions:
        return None
    # Do not merge overlapping or disjoint ranges, or take min/max version strings.
    value = ' OR '.join(dict.fromkeys(descriptions))
    return value + (' (additional ranges in JSON)' if incomplete else '')


def _name(component):
    return _DISPLAY_NAMES.get(component.name, component.name)


def _summary(assessment, report):
    if assessment.status == 'affected':
        return f'{len(assessment.advisory_ids)} confirmed'
    if assessment.status == 'potential':
        count = str(len(assessment.advisory_ids)) + ('+ (capped)' if assessment.advisories_truncated else '')
        return count + ' potential'
    if assessment.status == 'not_affected':
        return 'No evaluated matches'
    if report.status == 'failed' or assessment.reason == 'Exact-version scanner evaluation failed':
        return 'Failed'
    return 'Not assessed'


def write_table(inventory=None, report=None, *, stream=None, width=None):
    stream = stream or sys.stdout
    terminal = _Terminal(stream, width if width is not None else shutil.get_terminal_size((100, 24)).columns)
    source = inventory or report
    filename = PurePosixPath(source.input.path.replace('\\', '/')).name
    terminal.line(f'LibIdentifier  |  {filename}')
    stream.write('═' * terminal.width + '\n')
    requested = report is not None and report.status != 'not_requested'
    assessments = {a.component_id: a for a in report.components} if requested else {}
    originals = {c.component_id: c for c in inventory.components} if inventory else {}
    if inventory:
        terminal.section('LIBRARIES')
        rows = []
        for c in inventory.components:
            version = c.version or 'Unknown'
            if not c.version and c.version_candidates:
                version += ' [' + ','.join(c.version_candidates) + (',…' if c.version_candidates_truncated else '') + ']'
            label = c.identity_confidence.capitalize()
            identity = f'{label:<6} ({c.score:.2f})' if c.score is not None else label
            row = [_name(c), identity, version]
            if requested:
                row.append(_summary(assessments[c.component_id], report) if c.component_id in assessments else 'Not assessed')
            rows.append(row)
        if rows:
            terminal.table(['Library', 'Identity', 'Version'] + (['Advisories'] if requested else []), rows)
        else:
            terminal.line('No profile-backed components identified.')
        terminal.line('Coverage: limited reference profiles.' if inventory.coverage.library_identification == 'limited' else
                      f'Coverage: {inventory.coverage.library_identification}; reference coverage is limited.')
        coverage = inventory.coverage
        if coverage.unknown_classes_truncated:
            terminal.line(f'Unknown classes: {coverage.unknown_classes_emitted} of {coverage.unknown_classes_total} emitted (truncated).')
        if inventory.frameworks_detected:
            terminal.section('FRAMEWORKS (presence indicators)')
            for f in inventory.frameworks_detected:
                terminal.line(f'{f.name} — {f.confidence.capitalize()}')
                for e in f.evidence_records:
                    terminal.line((e.location.member or e.location.container) +
                        (':' + e.location.class_descriptor if e.location.class_descriptor else ''), indent=2)
                terminal.line('; '.join(f.limitations), indent=2)
    if not requested:
        return
    terminal.section('VULNERABILITIES')
    records = {a.id: a for a in report.advisories}
    terminal.line(f'Advisory assessment: {report.status}')
    for a in report.components:
        c = originals.get(a.component_id)
        name = _name(c) if c else unquote((a.family_purl or a.component_id).rsplit('/', 1)[-1])
        summary = _summary(a, report)
        below_threshold = a.status == 'not_assessed' and a.reason.startswith('Identity score below')
        terminal.line(f'{name} — {summary}' + (' advisories' if a.status in {'affected', 'potential'} else '') +
                      (f' ({a.reason[0].lower() + a.reason[1:]})' if below_threshold else ''))
        for finding in report.findings:
            if finding.component_id != a.component_id:
                continue
            group = [records[aid] for aid in finding.related_advisory_ids or [finding.advisory_id] if aid in records]
            ids = {finding.advisory_id, *finding.related_advisory_ids}
            for record in group:
                ids.update(record.aliases)
            preferred = sorted(ids, key=lambda x: (0 if x.startswith('CVE-') else 1 if x.startswith('GHSA-') else 2, x))[0]
            status = {'affected': 'CONFIRMED', 'potential': 'POTENTIAL'}.get(finding.applicability, 'NOT ASSESSED')
            coordinate = _coordinate(c) if c else None
            if not coordinate and a.family_purl:
                # Reuse attribution parsing, including PURL qualifiers/fragments.
                coordinate = _coordinate(SimpleNamespace(purl=None, family_purl=a.family_purl, version=None))
            ranges = affected_text(group, coordinate)
            terminal.line(f'{preferred:<18}  {status:<9}' + (f'  Affected: {ranges}' if ranges else ''), indent=2)
            aliases = sorted(ids - {preferred})
            if aliases:
                terminal.line('Aliases: ' + ', '.join(aliases), indent=4)
        if a.status == 'potential':
            terminal.line(('Installed version unknown' if a.version_confidence == 'unknown' else
                           'Installed version evidence insufficient') + '; applicability not confirmed.', indent=2)
        elif a.status == 'affected':
            terminal.line(f'OSV confirmed version match: {a.evaluated_version}.', indent=2)
        elif not below_threshold:
            terminal.line(a.reason, indent=2)
        terminal.line()
    if not report.components:
        terminal.line('No identified components to assess; this is not an exhaustive clean scan.')
    for issue in report.errors:
        terminal.line(f'{issue.code}: {issue.message}')
    terminal.line('Advisory matches do not establish reachability or exploitability.')
