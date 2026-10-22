import tempfile, os
from netshield.core import Store, Engine
def test_port_scan_rule():
    fd,path=tempfile.mkstemp();os.close(fd)
    try:
        store=Store(path); engine=Engine(store); engine.scan_ports=4
        events=[dict(timestamp=100+i,src_ip="192.0.2.1",dst_ip="198.51.100.2",dst_port=p,protocol="TCP",source_mode="test") for i,p in enumerate([21,22,23,24])]
        engine.process(events)
        assert any(a["type"]=="port_scan" for a in store.alerts())
    finally: os.unlink(path)
