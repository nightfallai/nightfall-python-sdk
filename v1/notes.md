# Nightfall Python SDK

## Setup
```
pip3 install -r dev-requirements.txt
python3 setup.py install
python3 setup.py bdist_wheel
pip3 install --force-reinstall dist/nightfall-*.whl
```

note: wheel installation is until package is published

## Coverage
```
# terminal report
NIGHTFALL_API_KEY="<your nightfall api key>" pytest --cov=nightfall

# html report
NIGHTFALL_API_KEY="<your nightfall api key>" pytest --cov-report html --cov=nightfall tests
```

## Usage

### Initialization

```
nightfall = Nightfall("<your nightfall api key>")
```

### Text Scanning

```
nightfall.scanText({
    "text": ["",],
    "detectionRules": [
        {}, 
    ]
})

nightfall.scanText({
    "text": ["",],
    "detectionRuleUuids": ["",]
})
```