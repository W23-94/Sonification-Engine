import asyncio
import nats
from scapy.all import Ether
from scapy.compat import raw
from datetime import datetime

subject = "suspicious.traffic"

async def main():
    async def message_handler(msg):
        pkt_data = msg.data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            pkt = Ether(pkt_data)
            print(f"[{timestamp}] [RECEIVED] Suspicious packet: {pkt.summary()}")
        except Exception as e:
            print(f"[{timestamp}] [ERROR] Could not decode packet: {e}")

    nc = await nats.connect("nats://localhost:4222")
    js = nc.jetstream()

    await js.subscribe(subject, cb=message_handler, durable="suspicious_monitor")

    print("Consumer is listening for suspicious packets...")
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Consumer interrupted.")
