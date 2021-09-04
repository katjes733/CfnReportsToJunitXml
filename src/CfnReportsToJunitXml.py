# MIT License

# Copyright (c) 2021 Martin Macecek

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse, json, sys, re, pathlib
sys.path.insert(0, "external")
from junit_xml import TestSuite, TestCase
from os import walk

def xml_filename_regex(arg_value, pat=re.compile(r"(?i)^[\w-]*\.xml$")):
    if not pat.match(arg_value):
        raise argparse.ArgumentTypeError
    return arg_value

parser = argparse.ArgumentParser()
parser.add_argument('report', help='The file name of the scan report')
parser.add_argument('reportType', choices=['CFN-NAG', 'CFN-GUARD', 'CFN-LINT'], help='The report type to use as conversion basis')
parser.add_argument('output', type=xml_filename_regex, help='The output xml file name of the generated JSON configuration')
parser.add_argument('--rules', help='The file name of the rules file')
parser.add_argument('--pathToTemplates', help='The path to the CloudFormation templates')
args = parser.parse_args()

if (args.reportType == 'CFN-NAG' or args.reportType == 'CFN-LINT') and args.rules is None:
    raise ValueError(f"For reportType {args.reportType}, parameter rules must be provided")
if (args.reportType == 'CFN-LINT') and args.rules is None:
    raise ValueError(f"For reportType {args.reportType}, parameter pathToTemplates must be provided")

def write_junit_xml_report(rules, report):
    test_cases = []
    for file_findings in report:
        for rule in rules:
            test_case=TestCase(f"{rule['id']} - {file_findings['filename']}")
            violations = [v for v in file_findings["file_results"]['violations'] if v['id'] == rule['id']] 
            if violations:
                output=",\n".join(list(map(lambda x, y: f"Line {x} ({y})", violations[0]['line_numbers'], violations[0]['logical_resource_ids'])))
                test_case.add_failure_info(output=f"{output}", message=violations[0]['message'])
            test_cases.append(test_case)

    test_suite = TestSuite(f"{args.reportType} test suite", test_cases)
    junitReportFile = open(args.output, 'w')
    junitReportFile.write(TestSuite.to_xml_string([test_suite], prettyprint=True))
    junitReportFile.close()

def generate_junit_report_from_cfn_nag():    
    rulesFile = open(args.rules, 'r')
    rules = json.load(rulesFile)
    rulesFile.close()

    reportFile = open(args.report, 'r')
    report = json.load(reportFile)
    reportFile.close()

    write_junit_xml_report(rules, report)

def generate_junit_report_from_cfn_lint():
    pattern =  re.compile(r"^(?P<id>[EW]{1}\d+)\: (?P<message>.*)$")
    rules = []
    with open(args.rules, 'r') as stream:
        for line in stream:  
            match = pattern.match(line)     
            if match:
                rules.append({"id": match.group('id'), "type": "FAIL" if match.group('id').startswith('E') else "WARN", "message": match.group('id')})

    reportFile = open(args.report, 'r')
    lintReport = json.load(reportFile)
    reportFile.close()

    templates = next(walk(args.pathToTemplates), (None, None, []))[2]
    report = []
    for template in templates:
        report.append({"filename": f"{args.pathToTemplates}/{template}", "file_results": {"failure_count": 0, "violations": []}})

    for finding in lintReport:
        type = "FAIL" if finding['Level'] == 'Error' else "WARN"
        filename = pathlib.PureWindowsPath(finding['Filename']).as_posix()
        id = finding['Rule']['Id']
        logical_resource_id = finding['Location']['Path'][1]
        line_number = finding['Location']['Start']['LineNumber']
        file = [f for f in report if f['filename'] == filename ]
        if file:
            print(f"Filename {filename} already exists; adding violation")
            violations = file[0]['file_results']['violations'] 
            violation = [v for v in violations if v['id'] == id]
            if violation:
                print(f"Violation {violation[0]['id']} already exists; adding details to violation")
                violation[0]['logical_resource_ids'].append(logical_resource_id)
                violation[0]['line_numbers'].append(line_number)
            else:
                print(f"Violation for Rule {id} does not yet exist; adding new violation")
                file[0]['file_results']['failure_count'] += 1
                violations.append({"id": id, "type": type, "message": finding['Rule']['ShortDescription'],"logical_resource_ids": [logical_resource_id], "line_numbers": [line_number]})
        else:
            print(f"Filename {filename} does not yet exist; adding violation as first to new record")            
            report.append({
                "filename": filename,
                "file_results": {"failure_count": 1, "violations": [{"id": id, "type": type, "message": finding['Rule']['ShortDescription'],"logical_resource_ids": [logical_resource_id], "line_numbers": [line_number]}]}})

    write_junit_xml_report(rules, report)

# this function is experimental for now as it has not been verified with cfn_guard
def generate_junit_report_from_cfn_guard():
    test_cases = []
    count_id = 0
    reportFile = open(args.report, 'r')
    report = json.load(reportFile)
    reportFile.close()
    for file_findings in report:
        finding = file_findings["message"]
        # extract resource id from finding line
        resource_regex = re.search("^\[([^]]*)]", finding)
        if resource_regex:
            resource_id = resource_regex.group(1)
            test_case = TestCase(f"{count_id} - {finding}", classname=resource_id)
            test_case.add_failure_info(output="%s#R:%s" % (file_findings["file"], resource_id))
            test_cases.append(test_case)
            count_id += 1

    test_suite = TestSuite(f"{args.reportType} test suite", test_cases)
    junitReportFile = open(args.output, 'w')
    junitReportFile.write(TestSuite.to_xml_string([test_suite], prettyprint=True))
    junitReportFile.close()

def process_report():
    if args.reportType == 'CFN-NAG':            
        return generate_junit_report_from_cfn_nag()
    if args.reportType == 'CFN-LINT':            
        return generate_junit_report_from_cfn_lint()
    # CFN-GUARD is not yet supported
    # elif args.reportType == 'CFN-GUARD':            
    #     return generate_junit_report_from_cfn_guard()
    else:
        print(f"Not yet supported report type: {args.reportType}")

try:
    print("Starting function") 
    process_report()
    print("Finished function")
except Exception as error:
    print("Error {}".format(error))
    raise