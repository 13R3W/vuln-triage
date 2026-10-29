import tempfile
from datetime import datetime
from pathlib import Path

from triage import config, sample
from triage.collect import Sources
from triage.periods import JST
from triage.sources import poc as poc_src

CFG = config.load()


def jst(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=JST)


def make_sources(now: datetime, entries=None, fail=(), jvn_down=False, cfg=None):
    entries = entries if entries is not None else sample.universe()
    fetcher = sample.SampleFetcher(entries, now, fail=fail, jvn_down=jvn_down)
    tmp = Path(tempfile.mkdtemp(prefix="poc-test-"))
    sample.write_poc_tree(entries, tmp, now)
    src = Sources(cfg or CFG, fetcher, lambda: poc_src.scan(tmp), now=now)
    src.load()
    return src, fetcher
