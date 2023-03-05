import argparse
import json
from datetime import datetime
from pathlib import Path

import pyfiglet
import pyfiglet.fonts
from bs4 import BeautifulSoup

import shared
import sys

MESSAGE_TYPES = {
    'zalo_messages': {'cliMsgId', 'dName', 'fromUid', 'message',
                 'msgId', 'resend', 'sendDttm', 'toUid', 'z_parsedTokens'}, 
    'messages': {'creator', 'conversationId', 'content', 'composetime', 'originalarrivaltime',
                'clientArrivalTime', 'isFromMe', 'createdTime', 'clientmessageid', 'contenttype', 'messagetype',
                'version', 'messageKind', 'properties', 'attachments'},           
    'messageMap': {'creator', 'conversationId', 'content', 'id', 'originalArrivalTime',
                'clientArrivalTime', 'isSentByCurrentUser', 'clientMessageId', 'contentType', 'messageType',
                'version', 'properties'},
    'contact': {'displayName', 'avatar', 'phoneNumber', 'userId','username','zaloName'},
    'buddy': {'displayName', 'mri'},
    'conversation': {'version', 'members', 'clientUpdateTime', 'id', 'threadProperties', 'type'}
}

def map_updated_zalo_keys(value):
    # Seems like Microsoft discovered duck typing
    # set the new keys to the old values too
    value['z_parsedTokens'] = str(value['z_parsedTokens'][0])
    return value

def strip_html_tags(value):
    try:
        # Get the text of any embedded html, such as divs, a href links
        soup = BeautifulSoup(value, features="html.parser")
        text = soup.get_text()
        return text
    except:
        return value


def convert_time_stamps(content_utf8_encoded):
    # timestamp appear in epoch format with milliseconds alias currentmillis
    # Convert data to neat timestamp
    converted_time_datetime = datetime.utcfromtimestamp(int(content_utf8_encoded) / 1000)
    converted_time_string = converted_time_datetime.strftime('%Y-%m-%dT%H:%M:%S.%f')

    return str(converted_time_string)


def extract_fields(record, keys):
    keys_by_message_type = MESSAGE_TYPES[keys]
    extracted_record = {key: record[key] for key in record.keys() & keys_by_message_type}
    return extracted_record


def decode_and_loads(properties):
    if (type(properties) is bytes):
        soup = BeautifulSoup(properties, features="html.parser")
        properties = properties.decode(soup.original_encoding)
    return json.loads(properties)

def parse_contacts(contacts):
    cleaned = []
    for contact in contacts:
        try:
            value = contact['value']
            x = extract_fields(value, 'contact')
            x['origin_file'] = contact['origin_file']
            x['record_type'] = 'contact'
            cleaned.append(x)
        except UnicodeDecodeError or KeyError:
            print("Could not decode contact.")

    # Deduplicate based on userId - should be unique anyway
    cleaned = deduplicate(cleaned, 'userId')

    return cleaned

def parse_zalo_message(zalo_messages):
    cleaned = []
    for zalo_message in zalo_messages:
        try:
            value = zalo_message['value']
            x = extract_fields(value, 'zalo_messages')
            x['origin_file'] = zalo_message['origin_file']
            x['record_type'] = 'message'
            if 'z_parsedTokens' in x:
                x = map_updated_zalo_keys(x)
            cleaned.append(x)
        except (UnicodeDecodeError, KeyError, NameError) as e:
            print("Could not decode the following item in the zalo_messages (output is not deduplicated).")
            print("\t ", value)
    cleaned = deduplicate(cleaned, 'msgId')
    return cleaned


def parse_records(records):
    parsed_records = []

    # Parse the records based on the store they are in.

    # parse contacts
    contacts = [d for d in records if d['store'] == 'friend']
    parsed_records += parse_contacts(contacts)

    # parse text messages, posts, call logs, file transfers
    zalo_messages = [d for d in records if d['store'] == 'message']
    parsed_records += parse_zalo_message(zalo_messages)

    return parsed_records


def deduplicate(records, key):
    distinct_records = [i for n, i in enumerate(records) if
                        i.get(key) not in [y.get(key) for y in
                                           records[n + 1:]]]
    return distinct_records


def process_db(filepath, output_path):
    # Do some basic error handling
    if not filepath.endswith('leveldb'):
        raise Exception('Expected a leveldb folder. Path: {}'.format(filepath))

    p = Path(filepath)
    if not p.exists():
        raise Exception('Given file path does not exists. Path: {}'.format(filepath))

    if not p.is_dir():
        raise Exception('Given file path is not a folder. Path: {}'.format(filepath))

    # convert the database to a python list with nested dictionaries

    extracted_values = shared.parse_db(filepath)

    # parse records
    parsed_records = parse_records(extracted_values)

    # write the output to a json file
    shared.write_results_to_json(parsed_records, output_path)


def run(args):
    process_db(args.filepath, args.outputpath)


def parse_cmdline():
    description = 'Forensics.im Xtract Tool'
    parser = argparse.ArgumentParser(description=description)
    required_group = parser.add_argument_group('required arguments')
    required_group.add_argument('-f', '--filepath', required=True, help='File path to the IndexedDB.')
    required_group.add_argument('-o', '--outputpath', required=True, help='File path to the processed output.')
    args = parser.parse_args()
    return args


def cli():
    header = pyfiglet.figlet_format("Forensics.im Xtract Tool")
    print(header)
    args = parse_cmdline()
    run(args)
    sys.exit(0)


if __name__ == '__main__':
    cli()
