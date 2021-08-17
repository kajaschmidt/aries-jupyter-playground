import asyncio

class Message:

    def __init__(self, payload):
        self.connection_id = payload["connection_id"]
        self.message_id = payload["message_id"]
        self.content = payload["content"]
        self.state = payload["state"]
        self.sent_time = payload["sent_time"]