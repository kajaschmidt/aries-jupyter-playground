import asyncio

class Connection:

    def __init__(self, connection_id, auto_accept=None):
        self.connection_id = connection_id
        self.is_active = asyncio.Future()
        self.is_trusted = asyncio.Future()
        self.auto_accept = auto_accept
        self.verified_attributes = []
        self.self_attested_attributes = []

