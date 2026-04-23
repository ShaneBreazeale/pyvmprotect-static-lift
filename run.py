import sys, os
def _log(msg):
    try:
        sys.stderr.write(msg+'\n'); sys.stderr.flush()
    except Exception: pass
    try:
        _lp=os.path.join(os.path.dirname(os.path.abspath(__file__)),'pyvmp_run.log')
        open(_lp,'a').write(msg+'\n')
    except Exception: pass
_req="3.11"
_got=f"{sys.version_info.major}.{sys.version_info.minor}"
if _got!=_req:
    _log(f'[PyVMProtect] Python {_got} detected — this module requires Python 3.11. Get it at: https://www.python.org/downloads/')
    sys.exit(1)
try:
    import crackmev3
except Exception as _e:
    _log(f'[PyVMProtect] Failed to load crackmev3: {_e}')
    sys.exit(1)
try:
    crackmev3._ttokwy5gsm()
except Exception as _e:
    _log(f'[PyVMProtect] Runtime error in crackmev3: {_e}')
    sys.exit(1)
