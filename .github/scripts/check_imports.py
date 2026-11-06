"""Fail if any binary under <dir> imports a DLL that is neither bundled nor a Windows system DLL."""
import os, sys, pefile
root = sys.argv[1]
sysdir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
have = {f.lower() for _, _, fs in os.walk(root) for f in fs}
missing = {}
for d, _, fs in os.walk(root):
    for f in fs:
        if not f.lower().endswith(('.dll', '.exe')) or f.lower().startswith('vc_redist'):
            continue
        p = os.path.join(d, f)
        try:
            pe = pefile.PE(p, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                                                   pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT']])
        except Exception as e:
            print("skip", p, e); continue
        imps = [e.dll.decode().lower() for e in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])]
        delay = [e.dll.decode().lower() for e in getattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT', [])]
        for n, kind in [(i, 'import') for i in imps] + [(i, 'delay') for i in delay]:
            if n in have or n.startswith(('api-ms-', 'ext-ms-')):
                continue
            if os.path.exists(os.path.join(sysdir, n)):
                continue
            missing.setdefault(n, set()).add(f"{os.path.relpath(p, root)} ({kind})")
for n, who in sorted(missing.items()):
    print(n, '<-', ', '.join(sorted(who)))
print("done; missing:", len(missing))
sys.exit(1 if missing else 0)
