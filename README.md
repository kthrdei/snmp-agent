# snmp-agent
SNMP Server

```
import asyncio
import snmp_agent

async def handler(req: snmp_agent.SNMPRequest) -> snmp_agent.SNMPResponse:
    vbs = [
        snmp_agent.VariableBinding(
            '1.3.6.1.2.1.1.1.0', snmp_agent.OctetString('System')),
        snmp_agent.VariableBinding(
            '1.3.6.1.2.1.1.3.0', snmp_agent.TimeTicks(100)),
        snmp_agent.VariableBinding(
            '1.3.6.1.2.1.2.2.1.1.1', snmp_agent.Integer(1)),
        snmp_agent.VariableBinding(
            '1.3.6.1.2.1.2.2.1.2.1', snmp_agent.OctetString('fxp0')),
        snmp_agent.VariableBinding(
            '1.3.6.1.2.1.2.2.1.5.1', snmp_agent.Gauge32(0)),
        snmp_agent.VariableBinding(
            '1.3.6.1.2.1.2.2.1.10.1', snmp_agent.Counter32(1000)),
        snmp_agent.VariableBinding(
            '1.3.6.1.2.1.2.2.1.16.1', snmp_agent.Counter32(1000)),
        snmp_agent.VariableBinding(
            '1.3.6.1.2.1.31.1.1.1.6.1', snmp_agent.Counter64(1000)),
        snmp_agent.VariableBinding(
            '1.3.6.1.2.1.31.1.1.1.10.1', snmp_agent.Counter64(1000)),
        snmp_agent.VariableBinding(
            '1.3.6.1.2.1.4.20.1.1.10.0.0.1', snmp_agent.IPAddress('10.0.0.1')),
    ]
    res_vbs = snmp_agent.utils.handle_request(req=req, vbs=vbs)
    res = req.create_response(res_vbs)
    return res

async def main():
    sv = snmp_agent.Server(handler=handler, host='0.0.0.0', port=161)
    await sv.start()
    while True:
        await asyncio.sleep(3600)

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
```


# Requirements
- Python >= 3.8
- asn1


# Installation
```
pip install snmp-agent
```


# License
MIT
