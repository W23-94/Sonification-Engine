import asyncio
import nats
from scapy.all import Ether
from scapy.compat import raw
from datetime import datetime
import os
import platform
import threading
import time
import json
from pathlib import Path
import signal

subject = "malware.traffic"

async def main():
    # Message tracking
    msg_counter = 0
    total_messages = 0
    last_report_time = datetime.now()
    last_sound_time = datetime.now()

    # Performance measurement
    performance_data = {
        "start_time": datetime.now().isoformat(),
        "intervals": [],
        "total_messages": 0,
        "avg_throughput": 0
    }

    # Sound settings
    MILESTONE = 1000
    MIN_SOUND_INTERVAL = 0.3

    def play_sound_nonblocking():
        def sound_thread_func():
            if platform.system() == "Darwin":
                os.system('afplay /System/Library/Sounds/Tink.aiff &')
            elif platform.system() == "Windows":
                import winsound
                threading.Thread(target=lambda: winsound.Beep(1000, 100)).start()
            else:
                print('\a', end='', flush=True)
        threading.Thread(target=sound_thread_func).start()

    performance_dir = Path(os.path.dirname(os.path.abspath(__file__)))
    performance_file = performance_dir / f"throughput_performance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    def save_performance_data():
        try:
            with open(performance_file, 'w') as f:
                json.dump(performance_data, f, indent=2)
            print(f"[INFO] Performance data saved to {performance_file}")
        except Exception as e:
            print(f"[ERROR] Failed to save performance data: {e}")

    async def report_activity():
        nonlocal last_report_time, msg_counter, performance_data, total_messages

        while True:
            await asyncio.sleep(60)
            now = datetime.now()
            time_diff = (now - last_report_time).total_seconds()

            if time_diff > 0:
                msg_rate = msg_counter / time_diff
                interval_data = {
                    "timestamp": now.isoformat(),
                    "duration_seconds": time_diff,
                    "messages": msg_counter,
                    "throughput": msg_rate
                }
                performance_data["intervals"].append(interval_data)
                performance_data["total_messages"] = total_messages

                if performance_data["intervals"]:
                    total_throughput = sum(interval["throughput"] for interval in performance_data["intervals"])
                    performance_data["avg_throughput"] = total_throughput / len(performance_data["intervals"])

                save_performance_data()

                timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] [STATS] Rate: {msg_rate:.2f} msgs/sec | Total: {total_messages} messages | Avg Rate: {performance_data['avg_throughput']:.2f} msgs/sec")

                msg_counter = 0
                last_report_time = now

    async def analyze_throughput():
        nonlocal performance_data

        while True:
            await asyncio.sleep(300)
            if len(performance_data["intervals"]) > 0:
                throughputs = [interval["throughput"] for interval in performance_data["intervals"]]
                max_throughput = max(throughputs)
                min_throughput = min(throughputs)
                avg_throughput = sum(throughputs) / len(throughputs)
                variance = sum((t - avg_throughput) ** 2 for t in throughputs) / len(throughputs)
                std_dev = variance ** 0.5
                performance_data["analysis"] = {
                    "timestamp": datetime.now().isoformat(),
                    "max_throughput": max_throughput,
                    "min_throughput": min_throughput,
                    "avg_throughput": avg_throughput,
                    "std_deviation": std_dev,
                    "stability_score": 1 - (std_dev / max(1, avg_throughput))
                }
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] [ANALYSIS] Max Rate: {max_throughput:.2f} msgs/sec | Min Rate: {min_throughput:.2f} msgs/sec | Stability: {performance_data['analysis']['stability_score']:.2f}")
                save_performance_data()

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

    def generate_final_report():
        end_time = datetime.now()
        start_time = datetime.fromisoformat(performance_data["start_time"])
        total_duration = (end_time - start_time).total_seconds() / 60.0
        performance_data["end_time"] = end_time.isoformat()
        performance_data["total_duration_minutes"] = total_duration
        if total_duration > 0:
            performance_data["overall_throughput"] = total_messages / (total_duration * 60)
        save_performance_data()
        summary_file = performance_dir / f"performance_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(summary_file, 'w') as f:
                f.write(f"=== NATS Consumer Performance Report ===\n")
                f.write(f"Generated: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"Total Run Duration: {total_duration:.2f} minutes\n")
                f.write(f"Total Messages Processed: {total_messages}\n")
                f.write(f"Overall Throughput: {performance_data.get('overall_throughput', 0):.2f} msgs/sec\n\n")
                if "analysis" in performance_data:
                    f.write("=== Performance Analysis ===\n")
                    f.write(f"Maximum Throughput: {performance_data['analysis']['max_throughput']:.2f} msgs/sec\n")
                    f.write(f"Minimum Throughput: {performance_data['analysis']['min_throughput']:.2f} msgs/sec\n")
                    f.write(f"Average Throughput: {performance_data['analysis']['avg_throughput']:.2f} msgs/sec\n")
                    f.write(f"Throughput Stability: {performance_data['analysis']['stability_score']:.2f}\n")
            print(f"[INFO] Performance summary saved to {summary_file}")
        except Exception as e:
            print(f"[ERROR] Failed to save performance summary: {e}")

    nc = await nats.connect("nats://localhost:4222")
    js = nc.jetstream()
    await js.subscribe(subject, cb=message_handler, durable="suspicious_monitor")

    print("Consumer is listening for suspicious packets...")
    print("Sound frequency adapts to message rate - faster traffic = more frequent sounds")
    print(f"A special sound alert also plays every {MILESTONE} messages")
    print(f"Performance data will be saved to: {performance_file}")

    report_task = asyncio.create_task(report_activity())
    analysis_task = asyncio.create_task(analyze_throughput())

    try:
        pending = asyncio.Future()
        await pending
    except asyncio.CancelledError:
        generate_final_report()
        report_task.cancel()
        analysis_task.cancel()
        try:
            await asyncio.gather(report_task, analysis_task, return_exceptions=True)
        except asyncio.CancelledError:
            pass
        print("Shutting down. Final performance report generated.")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    main_task = loop.create_task(main())
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, main_task.cancel)
    try:
        loop.run_until_complete(main_task)
    except asyncio.CancelledError:
        print("Consumer interrupted by user.")
    finally:
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()
