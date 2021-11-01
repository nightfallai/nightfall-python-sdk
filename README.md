# Nightfall Python SDK

This is a python SDK for working with the Nightfall API.

[![PyPI version](https://badge.fury.io/py/nightfall.svg)](https://badge.fury.io/py/nightfall)


## Installation 

This module requires Python 3.7 or higher.

```
pip install nightfall
```

## Quickstart 

Make a new [API Token](https://app.nightfall.ai/api/) in Nightfall and store the value as an environment variable.

```python
import os

from nightfall import Confidence, DetectionRule, Detector, Nightfall

nightfall = Nightfall(os.getenv('NIGHTFALL_API_KEY'))

findings, _ = nightfall.scan_text(
        ["4916-6734-7572-5015 is my credit card number"],
        [DetectionRule(
            [Detector(min_confidence=Confidence.LIKELY,
                     nightfall_detector="CREDIT_CARD_NUMBER")])])
print(findings)
```

For more information on the details of this library, please refer to 
the [API Documentation](https://docs.nightfall.ai/).
## Contributing

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
## License 

MIT


