"""Isolated scan measurements; quality metrics require complete build ground truth.

python benchmarks/run.py --profiles profiles.sqlite --corpus corpus.json
Corpus paths are relative to the manifest. Each sample runs in a new process.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def peak_rss():
    if os.name != 'nt':
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
    import ctypes
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_ = [('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)] + [(name,ctypes.c_size_t) for name in (
            'PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage',
            'QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage')]
    counters=Counters();counters.cb=ctypes.sizeof(counters)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    psapi=ctypes.WinDLL('psapi',use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
    if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(),ctypes.byref(counters),counters.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    return counters.PeakWorkingSetSize


def worker(path,profiles):
    import lief
    from libidentifier import identify
    started=time.perf_counter();result=identify(path,profiles=profiles)
    return {'input':result.input.to_dict(),'tool_version':result.tool_version,'python':sys.version.split()[0],
        'lief':lief.__version__,'profile_database':result.profile_database.to_dict(),
        'seconds':time.perf_counter()-started,'peak_rss_bytes':peak_rss(),
        'classes':result.coverage.analyzed_count['classes'],'unknown':result.coverage.unknown_classes_total,
        'clusters':len(result.unattributed_clusters),'relationships':len(result.relationships),
        'analysis_runs':[r.to_dict() for r in result.analysis_runs],
        'errors':[e.to_dict() for e in result.errors],
        'components':[{'family_purl':c.family_purl,'version':c.version} for c in result.components]}


def quality(rows, samples):
    tp=fp=fn=exact=correct=known=0
    for row,sample in zip(rows,samples):
        if not sample.get('ground_truth_complete'):
            continue
        expected={c['family_purl']:c.get('version') for c in sample['components']}
        observed={c['family_purl']:c['version'] for c in row['components']}
        tp+=len(expected.keys()&observed.keys());fp+=len(observed.keys()-expected.keys());fn+=len(expected.keys()-observed.keys())
        known+=sum(v is not None for v in expected.values())
        for family,version in observed.items():
            if version is not None:
                exact+=1;correct+=family in expected and expected[family]==version
    return {'family_true_positive':tp,'family_false_positive':fp,'family_false_negative':fn,
        'exact_version_predictions':exact,'correct_exact_versions':correct,'ground_truth_versioned_components':known,
        'family_precision':tp/(tp+fp) if tp+fp else None,'family_recall':tp/(tp+fn) if tp+fn else None,
        'exact_version_precision':correct/exact if exact else None,'exact_version_coverage':correct/known if known else None}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--profiles',required=True)
    parser.add_argument('--corpus');parser.add_argument('--worker')
    args=parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker,args.profiles)));return
    corpus_path=Path(args.corpus).resolve();corpus=json.loads(corpus_path.read_text())
    if corpus.get('schema_version')!=1:raise ValueError('Unsupported corpus schema')
    rows=[]
    for sample in corpus['samples']:
        completed=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--profiles',str(Path(args.profiles).resolve()),
            '--worker',str((corpus_path.parent/sample['path']).resolve())],check=True,capture_output=True,text=True,encoding='utf-8',timeout=300)
        rows.append(json.loads(completed.stdout))
    print(json.dumps({'schema_version':1,'platform':sys.platform,'samples':rows,'quality':quality(rows,corpus['samples'])},indent=2))


if __name__=='__main__':main()
