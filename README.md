import psutil
import os
import subprocess
import time
import datetime
import platform

def is_signed(file_path):
    # Use sigcheck from Sysinternals if available to check digital signature
    sigcheck_path = "sigcheck.exe"  # Place sigcheck.exe in the same folder or provide full path
    if not os.path.exists(sigcheck_path):
        return None  # Cannot determine
    try:
        result = subprocess.run([sigcheck_path, "-q", "-n", file_path], capture_output=True, text=True)
        # If output contains "Verified: Signed", it's signed
        if "Verified: Signed" in result.stdout:
            return True
        else:
            return False
    except Exception:
        return None

def is_suspicious_path(path):
    # Heuristic: suspicious if not in Program Files, Windows, or System32 folders
    suspicious = True
    path_lower = path.lower()
    if ("\\program files" in path_lower) or ("\\windows" in path_lower) or ("\\system32" in path_lower):
        suspicious = False
    return suspicious

def is_active(proc, cpu_usages):
    try:
        cpu_percent = cpu_usages.get(proc.pid, 0)
        net_io = proc.io_counters()
        return cpu_percent > 1 or (net_io.read_bytes + net_io.write_bytes) > 0
    except Exception:
        return False

def potential_damage(proc_name):
    # Simple heuristic: known dangerous names or high resource usage
    dangerous_names = ["cmd.exe", "powershell.exe", "wmic.exe", "rundll32.exe", "svchost.exe"]
    if proc_name.lower() in dangerous_names:
        return True, "Known system tools often abused by malware"
    return False, ""

def force_positive_negative(suspicious):
    return "Force Positive" if suspicious else "Force Negative"

def get_running_vms():
    """Get list of running VirtualBox VMs"""
    vboxmanage_paths = [
        "VBoxManage",
        "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe",
        "C:\\Program Files (x86)\\Oracle\\VirtualBox\\VBoxManage.exe"
    ]
    
    vboxmanage_path = None
    for path in vboxmanage_paths:
        if path == "VBoxManage":
            try:
                result = subprocess.run(["where", "VBoxManage"], capture_output=True, text=True)
                if result.returncode == 0:
                    vboxmanage_path = "VBoxManage"
                    break
            except:
                pass
        elif os.path.exists(path):
            vboxmanage_path = path
            break
    
    if not vboxmanage_path:
        return []
    
    try:
        cmd = f'cmd /c "{vboxmanage_path}" list runningvms'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        vms = []
        
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if '"' in line:
                    vm_name = line.split('"')[1]
                    vms.append(vm_name)
        return vms
    except:
        return []

def main():
    # Get current timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Get system information
    system_info = {
        "OS": platform.system() + " " + platform.release(),
        "Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor()
    }
    
    # Check for running VMs
    running_vms = get_running_vms()
    
    # Print header
    print("=" * 80)
    print(f"MALWARE INVESTIGATION REPORT - {timestamp}")
    print("=" * 80)
    print(f"System: {system_info['OS']} {system_info['Version']} {system_info['Machine']}")
    if running_vms:
        print(f"Running VMs: {', '.join(running_vms)}")
    print("=" * 80)
    
    report = []
    procs = list(psutil.process_iter(['pid', 'name', 'exe', 'status']))
    # Initialize CPU percent for all processes
    for proc in procs:
        try:
            proc.cpu_percent(interval=None)
        except Exception:
            pass
    time.sleep(0.1)  # Wait once for all
    cpu_usages = {}
    for proc in procs:
        try:
            cpu_usages[proc.pid] = proc.cpu_percent(interval=None)
        except Exception:
            cpu_usages[proc.pid] = 0
    
    # Count suspicious processes
    suspicious_count = 0
    active_count = 0
    potential_damage_count = 0
    
    for proc in procs:
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            exe = proc.info['exe'] or "N/A"
            status = proc.info['status']

            suspicious_path = is_suspicious_path(exe) if exe != "N/A" else True
            signed = is_signed(exe) if exe != "N/A" else None
            suspicious = suspicious_path or (signed is False)
            force_pos_neg = force_positive_negative(suspicious)
            active = is_active(proc, cpu_usages)
            damage, damage_reason = potential_damage(name)

            if suspicious:
                suspicious_count += 1
            if active:
                active_count += 1
            if damage:
                potential_damage_count += 1

            if not suspicious:
                reason = "Executable in standard path and signed" if signed else "Executable in standard path"
            else:
                reason = "Suspicious path or unsigned executable"

            report.append({
                "Malware name": name,
                "Malware location": exe,
                "Force positive or force negative": force_pos_neg,
                "Suspicious or not": "Suspicious" if suspicious else "Not suspicious",
                "If no, why and if suspicious why it's suspicious": reason,
                "If active or passive": "Active" if active else "Passive",
                "Potential damage: if is risk for the window": "Yes" if damage else "No",
                "If yes explain why": damage_reason if damage else ""
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Print summary
    print(f"Total processes: {len(report)}")
    print(f"Suspicious processes: {suspicious_count}")
    print(f"Active processes: {active_count}")
    print(f"Potentially harmful processes: {potential_damage_count}")
    print("=" * 80)
    
    # Sort report by suspiciousness and activity
    report.sort(key=lambda x: (x["Suspicious or not"] == "Suspicious", x["If active or passive"] == "Active"), reverse=True)
    
    # Print report
    for entry in report:
        print(f"Process: {entry['Malware name']} (Location: {entry['Malware location']})")
        print(f"Status: {entry['Force positive or force negative']} - {entry['Suspicious or not']}")
        print(f"Reason: {entry['If no, why and if suspicious why it\'s suspicious']}")
        print(f"Activity: {entry['If active or passive']}")
        print(f"Risk: {entry['Potential damage: if is risk for the window']}")
        if entry["If yes explain why"]:
            print(f"Risk reason: {entry['If yes explain why']}")
        print("-" * 80)
    
    # Save to file
    try:
        filename = f"malware_report_{timestamp.replace(':', '-').replace(' ', '_')}.txt"
        with open(filename, "w") as f:
            f.write(f"MALWARE INVESTIGATION REPORT - {timestamp}\n")
            f.write(f"System: {system_info['OS']} {system_info['Version']} {system_info['Machine']}\n")
            if running_vms:
                f.write(f"Running VMs: {', '.join(running_vms)}\n")
            f.write("=" * 80 + "\n")
            
            f.write(f"Total processes: {len(report)}\n")
            f.write(f"Suspicious processes: {suspicious_count}\n")
            f.write(f"Active processes: {active_count}\n")
            f.write(f"Potentially harmful processes: {potential_damage_count}\n")
            f.write("=" * 80 + "\n")
            
            for entry in report:
                f.write(f"Process: {entry['Malware name']} (Location: {entry['Malware location']})\n")
                f.write(f"Status: {entry['Force positive or force negative']} - {entry['Suspicious or not']}\n")
                f.write(f"Reason: {entry['If no, why and if suspicious why it\'s suspicious']}\n")
                f.write(f"Activity: {entry['If active or passive']}\n")
                f.write(f"Risk: {entry['Potential damage: if is risk for the window']}\n")
                if entry["If yes explain why"]:
                    f.write(f"Risk reason: {entry['If yes explain why']}\n")
                f.write("-" * 80 + "\n")
        
        print(f"\nReport saved to {filename}")
    except Exception as e:
        print(f"Error saving report: {str(e)}")

if __name__ == "__main__":
    main()
