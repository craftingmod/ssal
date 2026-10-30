from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

root = Path('/src')
files = {
    'module.prop': root / 'module/module.prop',
    'skip_mount': root / 'module/skip_mount',
    'service.sh': root / 'module/service.sh',
    'bin/ssal': root / 'out/bin/ssal',
    'bin/ssald': root / 'out/bin/ssald',
}
destination = root / 'out/ssal-module-mock.zip'
temporary = destination.with_suffix('.tmp')
with ZipFile(temporary, 'w', compression=ZIP_DEFLATED) as archive:
    for name, source in files.items():
        info = ZipInfo(name, (2020, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = (0o100755 if name.startswith('bin/') or name.endswith('.sh') else 0o100644) << 16
        info.compress_type = ZIP_DEFLATED
        archive.writestr(info, source.read_bytes())
temporary.replace(destination)
print(destination)
