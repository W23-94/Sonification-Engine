import asyncio
import nats
from scapy.all import Ether
from scapy.compat import raw
from datetime import datetime
import os
import sys
import platform

subject = "suspicious.traffic"

async def main():
    
    msg_counter = 0
    
    
    def make_beep():
        if platform.system() == "Darwin": 
            os.system('afplay /System/Library/Sounds/Tink.aiff')
        elif platform.system() == "Linux":
            os.system('echo -e "\a"') 
        elif platform.system() == "Windows":
            import winsound
            winsound.Beep(1000, 200)  
        else:
            print('\a')  
    
    import asyncio
import nats
from scapy.all import Ether
from scapy.compat import raw
from datetime import datetime
import os
import sys
import platform
import threading
import time

subject = "suspicious.traffic"

async def main():
    
    msg_counter = 0
    total_messages = 0
    last_report_time = datetime.now()
    last_sound_time = datetime.now()
    
    
    MILESTONE = 1000  
    MIN_SOUND_INTERVAL = 0.3  
    
    
    def play_sound_nonblocking():
        def sound_thread_func():
            if platform.system() == "Darwin":  # macOS
                os.system('afplay /System/Library/Sounds/Tink.aiff &')
            elif platform.system() == "Windows":
                import winsound
                threading.Thread(target=lambda: winsound.Beep(1000, 100)).start()
            else:  
                print('\a', end='', flush=True)
        
        
        threading.Thread(target=sound_thread_func).start()
    
    
    async def report_activity():
        nonlocal last_report_time, msg_counter
        
        while True:
            await asyncio.sleep(60) 
            
            now = datetime.now()
            time_diff = (now - last_report_time).total_seconds() / 60.0  
            
            if time_diff > 0:
               
                msg_rate = int(msg_counter / time_diff)
                
                
                timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] [STATS] Rate: {msg_rate} msgs/min | Total: {total_messages} messages")
                
                
                msg_counter = 0
                last_report_time = now
    
    async def message_handler(msg):
        nonlocal msg_counter, total_messages, last_sound_time
        pkt_data = msg.data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            pkt = Ether(pkt_data)
            print(f"[{timestamp}] [RECEIVED] Suspicious packet: {pkt.summary()}")
            
            
            msg_counter += 1
            total_messages += 1
            
            
            if total_messages % MILESTONE == 0:
                play_sound_nonblocking()
                print(f"[{timestamp}] [MILESTONE] Processed {total_messages} total messages")
            else:
                
                current_time = datetime.now()
                time_since_last_sound = (current_time - last_sound_time).total_seconds()
                
                
                current_rate = msg_counter / max(0.1, (current_time - last_report_time).total_seconds())
                
                
                sound_interval = max(MIN_SOUND_INTERVAL, 5.0 / max(1, current_rate))
                
                if time_since_last_sound >= sound_interval:
                    play_sound_nonblocking()
                    last_sound_time = current_time
                
        except Exception as e:
            print(f"[{timestamp}] [ERROR] Could not decode packet: {e}")

    nc = await nats.connect("nats://localhost:4222")
    js = nc.jetstream()

    
    await js.subscribe(subject, cb=message_handler, durable="suspicious_monitor")

    print("Consumer is listening for suspicious packets...")
    print("Sound frequency adapts to message rate - faster traffic = more frequent sounds")
    print(f"A special sound alert also plays every {MILESTONE} messages")
    
    
    report_task = asyncio.create_task(report_activity())
    
    
    try:
        
        pending = asyncio.Future()
        await pending
    except asyncio.CancelledError:
        
        report_task.cancel()
        try:
            await report_task
        except asyncio.CancelledError:
            pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Consumer interrupted.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Consumer interrupted.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Consumer interrupted.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Consumer interrupted.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Consumer interrupted.")