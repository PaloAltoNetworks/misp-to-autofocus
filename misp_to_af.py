__author__ = 'wartortell'

import json
from pymisp import PyMISP
import logging
import argparse
import xmltodict
import unicodedata

from autofocus import AFCondition, AFQuery


def find_event(args):
    event_json = None

    if args.download:
        args.logger.debug("Downloading MISP event from %s" % args.server)
        #db = download_database(args)

        event = args.misp.get_event(args.event)

        if event.status_code == 403:
            print "MISP server not configured for API use."
            exit(-1)

        event_json = event.json()["Event"]

    elif args.json_file:
        args.logger.debug("Loading JSON MISP database from %s" % args.json_file)
        with open(args.json_file, "r") as f:
            try:
                misp_data = json.load(f)
                for event in misp_data["Event"]:
                    if event["id"] == args.event:
                        event_json = event
                        break
            except Exception as e:
                args.logger.error("Failed to load JSON file at: %s" % args.json_file)
                exit(-1)

    elif args.xml_file:
        args.logger.debug("Loading XML MISP database from %s" % args.xml_file)
        with open(args.xml_file, "r") as f:
            try:
                misp_data = xmltodict.parse(f.read())["response"]
                for event in misp_data["Event"]:
                    if event["id"] == args.event:
                        event_json = event
                        break
            except Exception as e:
                args.logger.error("Failed to load XML file at: %s" % args.xml_file)
                exit(-1)

    elif args.csv_file:
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

    parser.add_argument('-d', '--download',
                        action='store_true',
                        help='Get the event from an online MISP server')

    parser.add_argument('-x', '--xml_file',
                        action='store',
                        help='Path to a MISP XML database')

    parser.add_argument('-c', '--csv_file',
                        action='store',
                        help='Path to a MISP CSV database')

    parser.add_argument('-j', '--json_file',
                        action='store',
                        help='Path to a MISP JSON database')

    parser.add_argument('-e', '--event',
                        action='store',
                        help='The event ID of the event to create a query from',
                        required='true')

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


def main():
    parser = parse_arguments()
    args = parser.parse_args()
    args.logger = logging.getLogger("MISP")

    # Set up the PyMISP object
    if args.download:
        if (not args.server) or (not args.auth):
            print "To download from a MISP server, you must provide a server and API key"
            parser.print_help()
            exit(-1)
        args.misp = PyMISP(args.server, args.auth, ssl=args.ssl)

    else:
        args.misp = None

    event_json = find_event(args)

    query = convert_misp_event(args, event_json)

    output_autofocus_query(args, query)


if __name__ == "__main__":
    main()
