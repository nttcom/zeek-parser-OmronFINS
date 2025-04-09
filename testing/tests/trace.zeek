# @TEST-DOC: Test Zeek parsing a trace file through the omron_fins analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/tcp-port-12345.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff omron_fins.log

# TODO: Adapt as suitable. The example only checks the output of the event
# handlers.

event omron_fins::message(c: connection, is_orig: bool, payload: string)
    {
    print fmt("Testing omron_fins: [%s] %s %s", (is_orig ? "request" : "reply"), c$id, payload);
    }
