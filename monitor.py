import subprocess  
import sys  
import traceback  
import psutil  
import threading  
import time  
from scapy.all import sniff, IPv6 

def run_and_monitor_script(script_name):
    # Run the script as a subprocess
    process = subprocess.Popen([sys.executable, script_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Start a thread to monitor the script execution
    monitor_thread = threading.Thread(target=monitor_process, args=(process,))
    monitor_thread.start()

    try:
        # Read the script's output and error streams
        stdout, stderr = process.communicate()
        
        # If the script exited with an error, analyze and display the error details
        if process.returncode != 0:
            print(f"Script {script_name} exited with an error.")
            print("Error output:")
            print(stderr)
            analyze_error(stderr)
        else:
            print(f"Script {script_name} executed successfully.")
            print("Output:")
            print(stdout)
    except Exception as e:
        # Catch any exceptions that occur during script execution
        print(f"An error occurred while running {script_name}: {str(e)}")
        analyze_error(traceback.format_exc())

    # Wait for the monitor thread to finish
    monitor_thread.join()

def monitor_process(process):
    try:
        while True:
            # Check if the process has terminated
            if process.poll() is not None:
                break  # Exit the loop if the process has terminated
            else:
                # Check if the process has stalled
                if process_status_stalled(process):
                    print("The process has stalled.")
                    analyze_process_stall(process)
                time.sleep(5)  # Wait for 5 seconds before checking again
    except Exception as e:
        print(f"An error occurred while monitoring the process: {str(e)}")

def process_status_stalled(process):
    try:
        # Check the CPU usage to determine if the process is stalled
        cpu_usage = psutil.cpu_percent(interval=1)
        if cpu_usage < 1.0:  # If CPU usage is very low
            return True
    except Exception as e:
        print(f"An error occurred while checking process status: {str(e)}")
    return False

def analyze_error(error_output):
    # Analyze and display the error details
    try:
        exec_lines = error_output.splitlines()
        for line in exec_lines:
            if "Traceback" in line:
                print(line)
            elif "File" in line and ", line" in line:
                print(line)
            else:
                print(line)
    except Exception as e:
        print(f"An error occurred while analyzing the error: {str(e)}")

def analyze_process_stall(process):
    try:
        # Analyze the stalled process
        process_info = psutil.Process(process.pid)
        print("Process is stalled.")
        print("Memory Info:", process_info.memory_info())
        print("CPU Times:", process_info.cpu_times())
    except Exception as e:
        print(f"An error occurred while analyzing the process stall: {str(e)}")

def deep_analysis():
    # Analyze system resources
    process_info = psutil.Process()
    print("Memory Info:", process_info.memory_info())
    print("CPU Times:", process_info.cpu_times())

    # Start network analysis by capturing IPv6 packets
    print("Starting network analysis...")
    sniff(filter="ip6", prn=packet_callback, count=100)  # Capture the first 100 IPv6 packets

def packet_callback(packet):
    if IPv6 in packet:
        # Calculate the size of the IPv6 packet and print it
        ipv6_packet_size = len(packet)
        print(f"IPv6 Packet Size: {ipv6_packet_size} bytes")

if __name__ == "__main__":
    target_script = "pppwn.py"  
    run_and_monitor_script(target_script)
    deep_analysis()
