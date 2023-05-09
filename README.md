# Overview
Code based on archived project from https://repo1.dso.mil/ironbank-tools/grype-parser.  This code has been updated to work on the Grype JSON schemas as of May 2023.

Grype Parser is a tool designed to parse the output of [Anchore's Grype](https://github.com/anchore/grype) utility and provide an analysis of whether this application can proceed with hardening.

# Installation and Configuration

## Grype

Specific documentation regarding Grype may be found here: https://github.com/anchore/grype

On a Mac, the easiest option is to install using Brew:
```
brew install grype
```

Or you may install using one of the below:
```
# install the latest version to /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# install a specific version into a specific dir
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b <SOME_BIN_PATH> <RELEASE_VERSION>
```

Additionally, you must configure Grype to output analysis as JSON. You can do this either through a configuration file (see [example configuration file](.grype.yaml)) or via the output flag `-o json`).

## Grype-Parser

Grype-parser requires Python3.

Install the required Python modules:
```
pip install -r requirements.txt
```

# Usage

You must first analyze an application using Grype and save the analysis as a JSON file that can then be parsed by grype-parser.

## Grype

Example:
```shell
> grype registry1.dsop.io/ironbank/redhat/ubi/ubi8:latest -o json > ubi8.json

✔ Vulnerability DB     [updated]
✔ Loaded image         
✔ Parsed image         
✔ Cataloged image      [196 packages]
✔ Scanned image        [159 vulnerabilities]
```

You should see the vulnerability database being updated, if not, make sure to run the following, then rerun analysis:
```shell
> grype db update

No vulnerability database update available
```

Your analysis has been saved as `ubi8.json` and can now be used to generate a report.

## Grype-Parser

Example:
```shell
> python grype-parser.py --filename=ubi8.json --excel-report=ubi8.xlsx 

Finding totals:
Severity    Count    Threshold    Status
Critical        0           10    Passed
High            2           20    Passed
Medium        108          200    Passed
Low            49         None    Passed
Negligible      0         None    Passed
Info            0         None    Passed
Total         159          300    Passed

 year  critical  high  medium  low  negligible  info  status
 2021         0     0       1    0           0     0  Passed
 2020         0     1      55    9           0     0  Failed
 2019         0     1      46   25           0     0  Failed
 2018         0     0       5   13           0     0  Failed
 2017         0     0       2    2           0     0  Failed
 2016         0     0       0    0           0     0  Passed
 2015         0     0       0    0           0     0  Passed
 2014         0     0       0    0           0     0  Passed
 2013         0     0       0    0           0     0  Passed
 2012         0     0       0    0           0     0  Passed
 2011         0     0       0    0           0     0  Passed
 2010         0     0       0    0           0     0  Passed
 2009         0     0       0    0           0     0  Passed
 2008         0     0       0    0           0     0  Passed
 2007         0     0       0    0           0     0  Passed
 2006         0     0       0    0           0     0  Passed
 2005         0     0       0    0           0     0  Passed
 2004         0     0       0    0           0     0  Passed
 2003         0     0       0    0           0     0  Passed
 2002         0     0       0    0           0     0  Passed

This application exceeds 4 thresholds.

*** DISCLAIMER ***
This preliminary analysis does NOT guarantee that this application will be approved. It should only used as guidance for determining whether an application
should be considered acceptable to START the hardening/approval processes. If you are a vendor looking to submit your application, you will be responsible
for rectifying any Failed thresholds prior to onboarding.

Additionally, not all findings may be applicable based on whether or not this application must be rebased and/or updated. Yum update or equivalent commands
may rectify a number of these findings but ultimately the application MUST be rebased onto an approved base image within Ironbank such as Red Hat UBI8.
```

# Report Details

As you can see in the example output above, there are two sets of criteria grype-parser is using to generate pass/fail data:
- Severity Totals
- Severity by Age Totals

## Severity Totals

This is a simplistic count of the total number of findings per severity. Additionally, it sums up all severities (minus info and negligible) to provide a total count as well.

Inside grype-parser.py you'll find a global variable specifying these thresholds:

```python
thresholds = {
    'critical':     10,
    'high':         20,
    'medium':       200,
    'low':          -1,
    'negligible':   -1,
    'info':         -1,
    'total':        300
}
```

This can be modified to specify the thresholds for each severity. All severities are optional. Additionally, specifying `-1` indicates unlimited findings (e.g., findings you probably don't care about).

While these thresholds can be modified, they should only be modified and commited to this repository for all to use. Modifying these thresholds in a one-off manner simply to make an application pass initial review and proceed with hardening is not authorized.

## Severity by Age Totals

Grype-parser estimates the age of a particular finding based on it's CVE ID. While this isn't always accurate, it is *very* likely that the year used in the CVE ID is the year the vulnerability was reported.

Since the year can be reasonably estimated and we know the criticality, we simply present this information to the end user. Additionally, thresholds can be applied in order to ensure that there are no findings of a particular severity over a certain age (e.g., no criticals over 2 years old).

Threshold information can be found and specified directly in the grype-parser.py file as a global variable.

```python
# Set the age of CVE thresholds
# The first key (a digit) represents the age of the finding in years. Each year is optional.
# The second set of keys (nested dict) represents the severity thresholds. Each severity is optional. Specify -1 for allow all.
# Example:
#   Current year is 2021.
#   ageThresholds = {
#       0: {                # Would represent year 2021 (current year - 0)
#           'critical': 0,
#           'high':     10,
#           'medium':   20,
#           'low':      -1  # Unlimited low findings
#       },
#       1: {                # Would represent year 2020 (current year - 1)
#           'critical': 3,
#           'high':     5,
#           'medium':   10
#           # low is missing here because it's optional
#       }
#       # Additional years could be specified, but if they're not, they're assumed to be 0 for all severity levels (except negligible and info).
#   }
ageThresholds = {
    0: {
        'critical': 5,
        'high':     10,
        'medium':   20
    },
    1: {
        'critical': 3,
        'high':     5,
        'medium':   10
    },
    2: {
        'critical': 1,
        'high':     3,
        'medium':   5
    },
    3: {
        'critical': 0,
        'high':     2,
        'medium':   3,
    },
    4: {
        'critical': 0,
        'high':     0,
        'medium':   0
    },
    5: {
        'critical': 0,
        'high':     0,
        'medium':   0
    }
}
```

## Excel

Additionally, the same information presented on the console is presented in an Excel document for easier reading and further refined analysis.

### Severity Totals

![](severity%20totals.png)

### Severity by Age Totals

![](severity%20by%20age.png)

# Problems

There are problems with this type of report generation that should be discussed and will likely require further analysis to ultimately determine if an application should proceed with hardening.

Specifically, some of the known problems are:
- It's hard to assess if the OS packages actually apply because of two reasons:
  - We will be rebasing the image onto UBI8 or some other approved base image. In this case, determine, as much as possible, if this application requires OS packages to function or if the application is primarily Java other language. If it's determined the application is primarily written in a language that does not require OS packages, then you may be able to subtract the majority of OS packages.
  - Many applications simply don't do `yum update` or equivalent but could theoretically do so. The easiest option here is force the container to perform an update and rerun the analysis.
- This is the first draft and many of the thresholds have NOT been validated against anything. There will need to be discussions and likely additional testing to ensure the thresholds are applicable to a wide variety of application.s
- This tool does not parse ALL Grype output, specifically many of the other supported language types like Python, Ruby, etc. These can easily be added but as part of the initial draft of this application, were not included.
