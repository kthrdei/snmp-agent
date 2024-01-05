import asyncio
from src.snmp_agent.server import Server
from src.snmp_agent.snmp import Integer, Boolean, OctetString, Null, \
    ObjectIdentifier, IPAddress, Counter32, Gauge32, \
    TimeTicks, Counter64, NoSuchObject, NoSuchInstance, EndOfMibView, \
    SNMPRequest, SNMPResponse, VariableBinding ,File
from src.snmp_agent.utils import handle_request


async def handler(req: SNMPRequest) -> SNMPResponse:
    vbs = [
        VariableBinding(
            '1.3.6.1.2.1.1.1.0', OctetString('System')),
        VariableBinding(
            '1.3.6.1.2.1.1.3.0', TimeTicks(100)),
        VariableBinding(
            '1.3.6.1.2.1.2.2.1.1.1', Integer(1)),
        VariableBinding(
            '1.3.6.1.2.1.2.2.1.2.1', OctetString('fxp0')),
        VariableBinding(
            '1.3.6.1.2.1.2.2.1.5.1', Gauge32(0)),
        VariableBinding(
            '1.3.6.1.2.1.2.2.1.10.1', Counter32(1000)),
        VariableBinding(
            '1.3.6.1.2.1.2.2.1.16.1', Counter32(1000)),
        VariableBinding(
            '1.3.6.1.2.1.31.1.1.1.6.1', Counter64(1000)),
        VariableBinding(
            '1.3.6.1.2.1.31.1.1.1.10.1', Counter64(1000)),
        VariableBinding(
            '1.3.6.1.2.1.4.20.1.1.10.0.0.1', IPAddress('10.0.0.1')),
        VariableBinding(
            '1.3.6.1.4.1.50743.1.11',  File('sample_file_var.txt'))
    ]
    res_vbs = handle_request(req=req, vbs=vbs)
    res = req.create_response(res_vbs)
    return res

async def main():
    sv = Server(handler=handler, host='0.0.0.0', port=161)
    await sv.start()
    while True:
        await asyncio.sleep(3600)

loop = asyncio.get_event_loop()
loop.run_until_complete(main())