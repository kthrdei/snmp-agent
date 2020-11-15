from typing import Callable, Awaitable
import asyncio
import logging

from . import snmp

logger = logging.getLogger(__name__)


class SNMPProtocol(asyncio.BaseProtocol):
    def __init__(self, handler: Callable[[snmp.SNMPRequest], Awaitable[snmp.SNMPResponse]]):
        self._handler = handler

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        loop = asyncio.get_event_loop()
        loop.create_task(self._handle(data=data, address=addr))

    async def _handle(self, data, address):
        # Decode request
        req = snmp.decode_request(data=data)
        logger.info(f"Received: {req.to_dict()}")

        # Callback
        res = await self._handler(req)

        # Encode response
        res_data = snmp.encode_response(response=res)

        self.transport.sendto(res_data, address)
        logger.info(f"Responded: {res.to_dict()}")


class Server(object):
    def __init__(self, handler: Callable[[snmp.SNMPRequest], Awaitable[snmp.SNMPResponse]], 
                 host: str = '127.0.0.1', port: int = 161):
        self._host = host
        self._port = port
        self._handler = handler
        self._server = None

    async def start(self):
        def create_snmp_server():
            return SNMPProtocol(handler=self._handler)

        loop = asyncio.get_event_loop()
        listen = loop.create_datagram_endpoint(
            create_snmp_server,
            local_addr=(self._host, self._port))
        transport, protocol = await listen
        self._server = transport

        logger.info(f"SNMP server is running on {self._host}:{self._port}")

    async def stop(self):
        self._server.close()
