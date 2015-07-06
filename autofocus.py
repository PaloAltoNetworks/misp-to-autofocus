__author__ = 'wartortell'

import json

class AFCondition:
    def __init__(self, field, operator, value):
        self.field = field
        self.operator = operator
        self.value = value

    def __str__(self):
        return json.dumps({"field": self.field, "operator": self.operator, "value": self.value})

class AFQuery:
    def __init__(self, operator):
        self.operator = operator
        self.children = []

        self.name = "Mr. Evil McMeanyPants"
        self.description = "Does lots of bad stuff"

    def add_condition(self, field, operator, value):
        cond = AFCondition(field, operator, value)
        self.children.append(cond)

    def add_query(self, query):
        self.children.append(query)

    def __str__(self):
        child_str = ",".join(map(str, self.children))
        return "{\"operator\": \"%s\",\"children\": [%s]}" % (self.operator, child_str)


