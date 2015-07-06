__author__ = 'wartortell'

import json
from pymisp import PyMISP
import logging
import argparse
import xmltodict
import unicodedata

from autofocus import AFQuery


def find_event(args):
    event_json = None

    if args.format == 'online':
        args.logger.debug("Downloading MISP event from %s" % args.server)

        event = args.misp.get_event(args.event)

        if event.status_code == 403:
            print "Your API key does not have th"
            exit(-1)

        event_json = event.json()["Event"]

    elif args.format == 'json':
        args.logger.debug("Loading JSON MISP database from %s" % args.input_file)
        with open(args.input_file, "r") as f:
            try:
                misp_data = json.load(f)
                event_json = misp_data["Event"]
            except Exception as e:
                args.logger.error("Failed to load JSON file at: %s" % args.input_file)
                exit(-1)

    elif args.format == 'xml':
        args.logger.debug("Loading XML MISP database from %s" % args.input_file)
        with open(args.xml_file, "r") as f:
            try:
                misp_data = xmltodict.parse(f.read())["response"]
                for event in misp_data["Event"]:
                    if event["id"] == args.event:
                        event_json = event
                        break
            except Exception as e:
                args.logger.error("Failed to load XML file at: %s" % args.input_file)
                exit(-1)

    elif args.format == 'csv':
        args.logger.error("CSV file importing not implemented yet!")
        exit(-1)

    return event_json


def convert_misp_event(args, event):
    # Create a new AFQuery for this event
    query = AFQuery("any")

    query.name = event["info"]
    query.description = "Autofocus query generated from MISP event %s from %s" % (args.event, args.server)

    # Dictionary of unsupported information
    unsupported = {}

    # Create a per-entry AutoFocus search
    if event["Attribute"]:
        for at in event["Attribute"]:
            if not (type(at) == dict):
                continue

            if not (at["category"] in unsupported):
                unsupported[at["category"]] = set()

            if at["category"] == "Network activity":
                if at["type"] == "domain":
                    query.add_condition("sample.tasks.dns", "contains", at["value"])
                elif at["type"] == "user-agent":
                    query.add_condition("alias.user_agent", "contains", at["value"])
                elif at["type"] == "hostname":
                    query.add_condition("alias.domain", "contains", at["value"])
                elif at["type"] == "ip-dst":
                    query.add_condition("alias.ip_address", "is", at["value"])
                elif at["type"] == "url":
                    query.add_condition("alias.url", "contains", at["value"])
                else:
                    unsupported[at["category"]].add(at["type"])

            elif at["category"] == "Artifacts dropped":
                if at["type"] == "filename":
                    query.add_condition("alias.filename", "contains", at["value"])
                elif at["type"] == "mutex":
                    query.add_condition("sample.tasks.mutex", "contains", at["value"])
                elif at["type"] == "md5":
                    query.add_condition("sample.md5", "is", at["value"])
                elif at["type"] == "sha1":
                    query.add_condition("sample.sha1", "is", at["value"])
                elif at["type"] == "sha256":
                    query.add_condition("sample.sha256", "is", at["value"])
                elif at["type"] in ["regkey", "regkey|value"]:
                    query.add_condition("sample.tasks.registry", "contains", at["value"])

                else:
                    unsupported[at["category"]].add(at["type"])

            elif at["category"] == "Payload type":
                if at["type"] == "text":
                    pass
                else:
                    unsupported[at["category"]].add(at["type"])

            elif at["category"] == "Payload delivery":
                if at["type"] == "url":
                    query.add_condition("alias.url", "contains", at["value"])
                elif at["type"] == "md5":
                    query.add_condition("alias.hash", "contains", at["value"])
                else:
                    unsupported[at["category"]].add(at["type"])

            elif at["category"] == "Attribution":
                if at["type"] == "":
                    pass
                else:
                    unsupported[at["category"]].add(at["type"])

            elif at["category"] == "Targeting data":
                if at["type"] == "":
                    pass
                else:
                    unsupported[at["category"]].add(at["type"])
            elif at["category"] == "Other":
                if at["type"] == "":
                    pass
                else:
                    unsupported[at["category"]].add(at["type"])
            elif at["category"] == "Persistence mechanism":
                if at["type"] == "":
                    pass
                else:
                    unsupported[at["category"]].add(at["type"])
            elif at["category"] == "External analysis":
                if at["type"] == "":
                    pass
                else:
                    unsupported[at["category"]].add(at["type"])
            elif at["category"] == "Payload installation":
                if at["type"] == "":
                    pass
                else:
                    unsupported[at["category"]].add(at["type"])
            elif at["category"] == "Antivirus detection":
                if at["type"] == "":
                    pass
                else:
                    unsupported[at["category"]].add(at["type"])

            elif at["category"] == "Internal reference":
                if at["type"] == "":
                    pass
                else:
                    unsupported[at["category"]].add(at["type"])

            else:
                unsupported[at["category"]].add(at["type"])

    print "Unsupported MISP Types:"
    for key in unsupported.keys():
        if len(unsupported[key]) > 0:
            print("%s: %s" % (key, ", ".join(list(unsupported[key]))))
    print("")

    return query


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--format',
                        action='store',
                        required='true',
                        choices=['online', 'csv', 'json', 'xml'],
                        default='online',
                        help='The format of the MISP database (online | csv | json | xml)')

    parser.add_argument('-i', '--input_file',
                        action='store',
                        help='Path to a MISP database (xml, csv, or json)')

    parser.add_argument('-e', '--event',
                        action='store',
                        help='The event ID of the event to create a query from')

    parser.add_argument('-s', '--server',
                        action='store',
                        help='The MISP server address')

    parser.add_argument('-a', '--auth',
                        action='store',
                        help='Your authentication key to access the MISP server API')

    parser.add_argument('--ssl',
                        action='store_true',
                        help='Use SSL for communication with MISP API')

    parser.add_argument('-o', '--output',
                        action='store',
                        help='The file you would like to save your searches into')

    return parser


def output_autofocus_query(args, query):

    name = unicodedata.normalize('NFKD', query.name).encode('ascii', 'ignore')
    query_str = "%s\n%s\n%s\n\n" % (name, query.description, str(query))

    if args.output:
        with open(args.output, "w") as f:
            f.write(query_str)
    else:
        print(query_str)


def print_usage(message, parser):
    print(message)
    parser.print_help()
    exit(-1)


def main():
    parser = parse_arguments()
    args = parser.parse_args()
    args.logger = logging.getLogger("MISP")

    # Set up the PyMISP object
    if args.format == "online":

        if (not args.server) or (not args.auth):
            print_usage("To download from a MISP server, you must provide a server and API key", parser)

        if not (args.server.startswith("http://") or args.server.startswith("https://")):
            args.server = "https://%s" % args.server

        # Create the MISP api class
        args.misp = PyMISP(args.server, args.auth, ssl=args.ssl)

    elif (args.format in ["csv", "xml", "json"]) and (not args.input_file):
        print_usage("You must provide a path to a file to import the %s MISP database from" % args.format.upper(), parser)

    else:
        args.misp = None

    event_json = find_event(args)

    query = convert_misp_event(args, event_json)

    output_autofocus_query(args, query)


if __name__ == "__main__":
    main()
