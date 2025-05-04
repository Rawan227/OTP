from sender import Sender
from receiver import Receiver
import threading
import time
import sys

def run_receiver():
    try:
        receiver = Receiver()
        receiver.receive()
    except Exception as e:
        print(f"Receiver error: {str(e)}", file=sys.stderr)

def run_sender():
    try:
        # Wait for receiver to be ready
        time.sleep(2)
        sender = Sender()
        sender.connect_to_receiver()
        sender.send()
    except Exception as e:
        print(f"Sender error: {str(e)}", file=sys.stderr)

if __name__ == '__main__':
    print("Starting One-Time Pad communication...")
    
    # Start receiver in a separate thread
    receiver_thread = threading.Thread(target=run_receiver)
    receiver_thread.daemon = True
    receiver_thread.start()
    
    # Run sender in main thread after short delay
    time.sleep(1)
    run_sender()
    
    # Wait for receiver to finish
    receiver_thread.join()
    
    print("Communication complete.")