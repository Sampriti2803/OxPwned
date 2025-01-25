import os
import email

def scan_attachments(msg, scan_tool="clamscan"):
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            print(f"Scanning attachment: {filename}")
            with open(filename, "wb") as f:
                f.write(part.get_payload(decode=True))
            os.system(f"{scan_tool} {filename}")
            os.remove(filename)

if __name__ == "__main__":
    # Sample usage
    # Assuming `raw_email` is parsed from email_parser.py
    scan_attachments(raw_email)