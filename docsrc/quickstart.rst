Quickstart
==========

Installation
------------

.. note::
    Nightfall requires Python 3.6 or higher. 

You can install the latest version of Nightfall with:

::

    pip install nightfall

Basic Usage
-----------

Make a new `API Token <https://app.nightfall.ai/api/>`_ and `Detection Set <https://app.nightfall.ai/detection-engine/detection-rules>`_ in the Nightfall UI and export these as environment variables.

Import Nightfall and start using methods:

::

    from nightfall import Nightfall

    nightfall = Nightfall(
        os.getenv('NIGHTFALL_TOKEN'),
        os.getenv('NIGHTFALL_CONDITION_SET')
        )

    response = nightfall.scan(['test string'])

    print(response)    
