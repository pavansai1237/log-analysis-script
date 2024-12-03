import re
import csv
from collections import defaultdict, Counter

# Define a configurable threshold for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 10

# File paths
LOG_FILE = 'sample.log'
OUTPUT_FILE = 'log_analysis_results.csv'

# Function to parse log entries
def parse_log(file_path):
    ip_requests = Counter()
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?:GET|POST) (?P<endpoint>/\S*) HTTP/1.1" (?P<status>\d+) .*'
    )

    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.match(line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = match.group('status')

                ip_requests[ip] += 1
                endpoint_requests[endpoint] += 1

                if status == '401':  # Failed login attempts
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

# Function to detect suspicious activity
def detect_suspicious_activity(failed_logins, threshold):
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

# Function to save results to CSV
def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.most_common():
            writer.writerow([ip, count])
        writer.writerow([])  # Blank row

        # Most accessed endpoint
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])  # Blank row

        # Suspicious activity
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

# Main function
def main():
    print("Analyzing log file...")

    ip_requests, endpoint_requests, failed_logins = parse_log(LOG_FILE)

    # Identify the most accessed endpoint
    most_accessed_endpoint = endpoint_requests.most_common(1)[0]

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(failed_logins, FAILED_LOGIN_THRESHOLD)

    # Display results
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count:<15}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<25}")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count:<25}")

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, OUTPUT_FILE)
    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
