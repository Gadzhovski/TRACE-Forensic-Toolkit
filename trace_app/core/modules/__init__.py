"""External modules: third-party tools TRACE installs on request and runs
on evidence, never imports (no Qt).

The LEAPP parsers (iLEAPP for iOS, aLEAPP for Android) cannot be Python
dependencies -- iLEAPP needs pyliblzfse, which has wheels for Windows only,
and numpy/pandas; aLEAPP needs sqlcipher3 and a git-installed package -- so
TRACE drives their published, ready-built programs instead:

* `spec`     what each tool is: repository, release assets per platform,
             the program inside, the version TRACE was tested with
* `paths`    where tools are installed (`modules_dir`)
* `install`  find a release, download, check SHA256SUMS, unpack with
             nothing but Python and the OS, smoke-test, record
* `stage`    copy the files a tool looks for out of the evidence, with a
             hashed manifest that leads every result back to its file
* `run`      start the tool's command line in a clean environment
* `lava`     read what it wrote (LAVA: SQLite + JSON) into the case
"""
