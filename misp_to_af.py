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

    if args.format == 'online':
        args.logger.info("Downloading MISP event from %s" % args.server)

        event = args.misp.get_event(args.event)

        if event.status_code == 403:
            print "Your API key does not have permission to access the MISP API."
            exit(-1)

        event_json = event.json()["Event"]

    elif args.format == 'json':
        args.logger.info("Loading JSON MISP event from %s" % args.input_file)
        with open(args.input_file, "r") as f:
            try:
                event_json = json.load(f)["Event"]
            except Exception as e:
                args.logger.error("Failed to load JSON file at: %s" % args.input_file)
                exit(-1)

    elif args.format == 'xml':
        args.logger.info("Loading XML MISP event from %s" % args.input_file)
        with open(args.input_file, "r") as f:
            try:
                # Must convert OrderedDict to dict
                event_xml = dict(xmltodict.parse(f.read())["response"]["Event"])
                temp = []
                for key in event_xml["Attribute"]:
                    temp.append(dict(key))
                event_xml["Attribute"] = temp

                event_json = event_xml
            except Exception as e:
                print e.message
                args.logger.error("Failed to load XML file at: %s" % args.input_file)
                exit(-1)

    elif args.format == 'csv':
        args.logger.error("CSV file importing not implemented yet!")
        exit(-1)

    return event_json


def create_conditions(args, event):
    conditions = {"ip": [],
                  "domain": [],
                  "hostname": [],
                  "url": [],
                  "user-agent": [],
                  "mutex": [],
                  "md5": [],
                  "sha1": [],
                  "sha256": [],
                  "file_path": [],
                  "process": [],
                  "registry": []}

    # Create a new AFQuery for this event
    query = AFQuery("any")

    query.name = event["info"]
    if args.format == "online":
        query.description = "Autofocus query generated from MISP event %s from %s" % (args.event, args.server)
    else:
        query.description = "Autofocus query generated from MISP event %s from %s" % (event["id"], event["org"])

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
                    conditions["domain"].append(AFCondition("sample.tasks.dns", "contains", at["value"]))
                elif at["type"] == "user-agent":
                    conditions["user-agent"].append(AFCondition("alias.user_agent", "contains", at["value"]))
                elif at["type"] == "hostname":
                    conditions["domain"].append(AFCondition("alias.domain", "contains", at["value"]))
                elif at["type"] == "ip-dst":
                    if not args.no_ip:
                        conditions["ip"].append(AFCondition("alias.ip_address", "is", at["value"]))
                elif at["type"] == "url":
                    conditions["url"].append(AFCondition("alias.url", "contains", at["value"]))
                else:
                    unsupported[at["category"]].add(at["type"])

            elif at["category"] == "Artifacts dropped":
                if at["type"] == "filename":
                    conditions["file_path"].append(AFCondition("alias.filename", "contains", at["value"]))
                elif at["type"] == "mutex":
                    conditions["mutex"].append(AFCondition("sample.tasks.mutex", "contains", at["value"]))

                elif at["type"] in ["regkey", "regkey|value"]:
                    conditions["registry"].append(AFCondition("sample.tasks.registry", "contains", at["value"]))

                # For hashes we just make a list
                elif at["type"] == "md5":
                    conditions["md5"].append(at["value"])
                elif at["type"] == "sha1":
                    conditions["sha1"].append(at["value"])
                elif at["type"] == "sha256":
                    conditions["sha256"].append(at["value"])

                else:
                    unsupported[at["category"]].add(at["type"])

            elif at["category"] == "Payload type":
                if at["type"] == "text":
                    pass
                else:
                    unsupported[at["category"]].add(at["type"])

            elif at["category"] == "Payload delivery":
                if at["type"] == "url":
                    conditions["url"].append(AFCondition("alias.url", "contains", at["value"]))
                elif at["type"] == "md5":
                    conditions["md5"].append(at["value"])
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

    args.logger.info("")
    args.logger.info("  Condition Type Counts:")
    for key in sorted(conditions.keys()):
        args.logger.info("    %s - %d" % (key, len(conditions[key])))

    # Handle tokenized conditions that will be searched against a list
    if len(conditions["md5"]) > 0:
        conditions["md5"] = [AFCondition("sample.md5", "is in the list", conditions["md5"])]
    if len(conditions["sha1"]) > 0:
        conditions["sha1"] = [AFCondition("sample.sha1", "is in the list", conditions["sha1"])]
    if len(conditions["sha256"]) > 0:
        conditions["sha256"] = [AFCondition("sample.sha256", "is in the list", conditions["sha256"])]

    args.logger.info("")
    args.logger.info("  Unsupported MISP Types:")
    for key in unsupported.keys():
        if len(unsupported[key]) > 0:
            args.logger.info("    %s:%s%s" % (key, " "*(24 - len(key)), ", ".join(list(unsupported[key]))))

    return conditions


def create_query(args, event):
    # Create a new AFQuery for this event
    query = AFQuery("any")

    query.name = event["info"]
    if args.format == "online":
        query.description = "Autofocus query generated from MISP event %s from %s" % (args.event, args.server)
    else:
        query.description = "Autofocus query generated from MISP event %s from %s" % (event["id"], event["org"])

    return query


def create_queries(args, event, conditions):
    queries = []

    current_query = create_query(args, event)

    for key in conditions.keys():
        if args.split:
            if len(current_query.children) > 0:
                queries.append(current_query)
            current_query = create_query(args, event)

        for condition in conditions[key]:
            current_query.add_condition(condition)

            if args.max_query:
                if len(current_query.children) >= int(args.max_query):
                    queries.append(current_query)
                    current_query = create_query(args, event)

    if len(current_query.children) > 0:
        queries.append(current_query)

    return queries


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

    parser.add_argument('-m', '--max_query',
                        action='store',
                        help='The maximum number of items you would like in a query')

    parser.add_argument('-sp', '--split',
                        action='store_true',
                        help='Split the queries into their sub types (e.g. ip, domain, file, etc.)')

    parser.add_argument('-ni', '--no_ip',
                        action='store_true',
                        help='Use this argument if you don\'t want IP addresses included')

    return parser


def output_autofocus_query(args, query):

    name = unicodedata.normalize('NFKD', query.name).encode('ascii', 'ignore')
    query_str = "%s\n%s\n%s\n\n" % (name, query.description, str(query))

    if args.output:
        with open(args.output, "w") as f:
            f.write(query_str)
    else:
        print(query_str)


def print_usage(message, args, parser):
    args.logger.debug(message)
    parser.print_help()
    exit(-1)


def main():
    parser = parse_arguments()
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    args.logger = logging.getLogger("MISP")

    # Set up the PyMISP object
    if args.format == "online":

        if (not args.server) or (not args.auth):
            print_usage("To download from a MISP server, you must provide a server and API key", args, parser)

        if not (args.server.startswith("http://") or args.server.startswith("https://")):
            args.server = "https://%s" % args.server

        # Create the MISP api class
        args.misp = PyMISP(args.server, args.auth, ssl=args.ssl)

    elif (args.format in ["csv", "xml", "json"]) and (not args.input_file):
        print_usage("You must provide a path to a file to import the %s MISP database from" % args.format.upper(), args, parser)

    else:
        args.misp = None

    event_json = find_event(args)

    conditions = create_conditions(args, event_json)

    queries = create_queries(args, event_json, conditions)

    for query in queries:
        output_autofocus_query(args, query)


if __name__ == "__main__":
    main()
