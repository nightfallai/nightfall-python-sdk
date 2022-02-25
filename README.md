# Nightfall Python SDK

**Embed Nightfall scanning and detection functionality into Python applications**

[![PyPI version](https://badge.fury.io/py/nightfall.svg)](https://badge.fury.io/py/nightfall)

##  Features

This SDK provides Python functions for interacting with the Nightfall API. It allows you to add functionality to your
applications to scan plain text and files in order to detect different categories of information. You can leverage any
of the detectors in Nightfall's pre-built library, or you may programmatically define your own custom detectors.

Additionally, this library provides convenience features such as encapsulating the steps to chunk and upload files.

To obtain an API Key, login to the [Nightfall dashboard](https://app.nightfall.ai/) and click the section
titled "Manage API Keys".

See our [developer documentation](https://docs.nightfall.ai/docs/entities-and-terms-to-know) for more details about
integrating with the Nightfall API.

## Dependencies

The Nightfall Python SDK requires Python 3.7 or later.

For a full list of external dependencies please consult `setup.py`.


## Installation

```
pip install nightfall
```

## Usage


### Scanning Plain Text

Nightfall provides pre-built detector types, covering data types ranging from PII to PHI to credentials. The following
snippet shows an example of how to scan using pre-built detectors.

####  Sample Code

```python
>>> from nightfall import Confidence, DetectionRule, Detector, Nightfall

>>> # By default, the client reads the API key from the environment variable NIGHTFALL_API_KEY
>>> nightfall = Nightfall()

>>> # A rule contains a set of detectors to scan with
>>> cc = Detector(min_confidence=Confidence.LIKELY, nightfall_detector="CREDIT_CARD_NUMBER")
>>> ssn = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="US_SOCIAL_SECURITY_NUMBER")
>>> detection_rule = DetectionRule([cc, ssn])

>>> findings, _ = nightfall.scan_text( ["hello world", "my SSN is 678-99-8212", "4242-4242-4242-4242"], detection_rules=[detection_rule])

>>> print(findings)
[[], [Finding(finding='678-99-8212', redacted_finding=...)]]

```



### Scanning Files

Scanning common file types like PDF's or office documents typically requires cumbersome text
extraction methods like OCR.

Rather than implementing this functionality yourself, the Nightfall API allows you to upload the
original files, and then we'll handle the heavy lifting.

The file upload process is implemented as a series of requests to upload the file in chunks. The library
provides a single method that wraps the steps required to upload your file. Please refer to the
[API Reference](https://docs.nightfall.ai/reference) for more details.

The file is uploaded synchronously, but as files can be arbitrarily large, the scan itself is conducted asynchronously.
The results from the scan are delivered by webhook; for more information about setting up a webhook server, refer to
[the docs](https://docs.nightfall.ai/docs/creating-a-webhook-server).

#### Sample Code

```python
>>> from nightfall import Confidence, DetectionRule, Detector, Nightfall
>>> import os

>>> # By default, the client reads the API key from the environment variable NIGHTFALL_API_KEY
>>> nightfall = Nightfall()

>>> # A rule contains a set of detectors to scan with
>>> cc = Detector(min_confidence=Confidence.LIKELY, nightfall_detector="CREDIT_CARD_NUMBER")
>>> ssn = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="US_SOCIAL_SECURITY_NUMBER")
>>> detection_rule = DetectionRule([cc, ssn])


>>> # Upload the file and start the scan.
>>> # These are conducted asynchronously, so provide a webhook route to an HTTPS server to send results to.
>>> id, message = nightfall.scan_file( "./README.md", os.environ["WEBHOOK_ENDPOINT"], detection_rules=[detection_rule])
>>> print("started scan", id, message)
started scan...scan initiated

```

## Contributing

Contributions are welcome! Open a pull request to fix a bug, or open an issue to discuss a new feature
or change. Please adhere to the linting criteria expected by flake8, and be sure to add unit tests for
any new functionality you add.

Refer to `CONTRIBUTING.md` for the full details.

## License

This code is licensed under the terms of the MIT License. See [here](https://opensource.org/licenses/MIT)
for more information.

Please create an issue with a description of your problem, or open a pull request with the fix.

## Development

### Installing Development Dependencies

If you want to hack on this project, you should set up your local development
environment with the following commands:

1. Fork and clone this repo and open a terminal with the root of this repository in your working directory.
1. Create and activate a virtualenv `python3 -m venv venv && source venv/bin/activate`
1. Install development dependencies with `pip install -r dev-requirements.txt`
1. Install an editable version of this package `pip install -e .`

### Run Unit Tests

Unit and Integration tests can be found in the `tests/` directory. You can run them with `pytest`. Be sure to have `NIGHTFALL_API_KEY` set as an environment variable before running the tests.

### View Code Coverage

You can view the code coverage report by running `coverage html` and `python3 -m http.server --directory htmlcov` after running the unit tests.

### Creating a Release

Releases are automatically published to PyPI using GitHub Actions. Creating a release in GitHub will trigger a new build that will publish the latest version of this library to [PyPI](https://pypi.org/project/nightfall/).

The steps to do this are:

1. Add what changed to the CHANGELOG file
2. Update the version in `setup.py`
3. Commit changes and push to the main branch.
4. Create a new release in the GitHub UI.
5. Observe the release action succeed and see the latest version of this library on PyPI.

