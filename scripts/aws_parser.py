import json
from datetime import datetime
import sys
import os

def parse_cloudtrail_logs(file_path):
    events = []
    with open(file_path, 'r') as file:
        for line in file:
            try:
                event = json.loads(line.strip())
                events.append(event)
            except json.JSONDecodeError:
                continue
    return events

def extract_key_events(events):
    key_events = []
    for event in events:
        event_time = datetime.strptime(event['eventTime'], "%Y-%m-%dT%H:%M:%SZ")
        event_name = event['eventName']
        event_source = event['eventSource']
        user_identity = event['userIdentity'].get('userName', event['userIdentity'].get('type', 'Unknown'))
        src_ip = event['sourceIPAddress']
        region = event['awsRegion']

        if event_name == 'ConsoleLogin':
            description = f"Console login by {user_identity}"
        elif event_name == 'StopInstances':
            instances = ', '.join([item['instanceId'] for item in event['requestParameters']['instancesSet']['items']])
            forced = event['requestParameters']['force']
            description = f"Stopped EC2 instances by {src_ip}" + f' (forced: {forced}, region: {region}) ' + f" : {instances}"
        elif event_name == 'StartInstances':
            instances_set = ', '.join([item['instanceId'] for item in event['requestParameters']['instancesSet']['items']])
            response_instances = ', '.join([item['instanceId'] + ' = code,previous_state: ' + str(item['previousState']['code']) + "," + item['previousState']['name'] + ' | code,current_state: ' + str(item['currentState']['code']) + "," + item['currentState']['name'] + '\n' \
                for item in event['responseElements']['instancesSet']['items']])
            description = f'Started EC2 instances by {src_ip} = instances_set: {instances_set} ---- response_instances: {response_instances}'
        elif event_name == 'ExecuteStatement':
            description = "Database query executed" + '\n'
            description = description + ' region: ' + region + ' sourceIP: ' + src_ip + '\n'
            description = description + '\t requestParameters: \n \t\t' + 'resourceArn: ' + event['requestParameters']['resourceArn'] + \
                ' | database: ' + event['requestParameters']['database'] + ' | sql: ' + event['requestParameters']['sql']
        elif event_name == 'AdminSetUserPassword':
            description = "User password reset"
        elif event_name == 'InitiateAuth':
            description = f"Authentication attempt by {src_ip}"
            if 'errorCode' in event:
                description = description + f"\n\tError due to: {event['errorCode']},{event['errorMessage']}"
        else:
            if 'errorCode' in event:
                error_code = event['errorCode']
                error_message = event.get('errorMessage', 'No specific error message provided')
                description = f"Error: {error_code} - {error_message}"
            description = f"{event_name} from {event_source}"

        key_events.append((event_time, description))

    return sorted(key_events)

def display_timeline(key_events):
    print("Timeline of Key Events:")
    print("=" * 50)
    for event_time, description in key_events:
        print(f"{event_time.strftime('%Y-%m-%d %H:%M:%S')} - {description}")

def write_out_timeline(key_events):
    output_dir = '../output/'
    output_file = 'out.txt'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    with open(output_dir + output_file, 'w+') as file:
        print("opened/created file")
        file.write("Timeline of Key Events:\n")
        file.write('=' * 50)
        for event_time, description in key_events:
            file.write(f"{event_time.strftime('%Y-%m-%d %H:%M:%S')} - {description}\n")

def main(file_path):
    events = parse_cloudtrail_logs(file_path)
    key_events = extract_key_events(events)
    display_timeline(key_events)
    write_out_timeline(key_events)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_cloudtrail_logs>")
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)